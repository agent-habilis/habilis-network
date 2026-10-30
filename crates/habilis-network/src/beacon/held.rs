use std::net::{Ipv4Addr, SocketAddr};

use iroh::address_lookup::memory;
use iroh::{Endpoint, EndpointAddr};

use crate::lookup::{ProbeAnswer, TransportHandles, build_endpoint, probe_answer};
use crate::protocol::meshes::LookupOpts;
use crate::util::clock::Instant;

use super::rung_ladder::{admit_rung, forget_rungs, settle_on_rung};
use super::{
    Rendezvous, RendezvousLane, RendezvousParams, RivalProbe, RungRead, RungWatch, claim,
    releasable, rung_is_busy, spawn_rival_probe,
};

use n0_future::task;
use std::time;
/// What the busy rungs of a private ladder answer to an identity probe, by port, before a joiner's
/// first dial. The book must name the rung that serves our beacon before the joiner subscribes:
/// a first dial with no address that answers is one the gossip layer keeps for seconds before a
/// re-graft can replace it. One throwaway endpoint per rung, as the walk's probes: a prober that
/// reached the id at one rung may reuse that path for the next port and read a foreign rung as
/// ours. All rungs at once, `budget` each, so eight silent rungs cost one budget. A rung whose
/// prober did not bind is left unread, and read later by the walk. Each endpoint closes off this
/// task: closing one that dialed a silent rung takes seconds.
pub(crate) async fn read_busy_rungs(
    params: &RendezvousParams,
    budget: time::Duration,
) -> Vec<(u16, ProbeAnswer)> {
    let probes: Vec<_> = params
        .bind_ports
        .iter()
        .copied()
        .filter(|&port| rung_is_busy(port))
        .map(|port| {
            let id = params.id;
            task::spawn(async move {
                let prober = match build_endpoint(
                    &LookupOpts::loopback(),
                    None,
                    None,
                    Vec::new(),
                    TransportHandles::default(),
                )
                .await
                {
                    Ok(prober) => prober,
                    Err(error) => {
                        tracing::debug!(target: "habilis_network::beacon", port, %error, "no endpoint to read the busy rung with; the walk reads it");
                        return None;
                    }
                };
                let address = EndpointAddr::new(id)
                    .with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
                let answer = probe_answer(&prober, address, budget).await;
                tracing::debug!(target: "habilis_network::beacon", port, ?answer, "busy rung read at setup");
                drop(task::spawn(async move { prober.close().await }));
                Some((port, answer))
            })
        })
        .collect();
    let mut read = Vec::with_capacity(probes.len());
    for probe in probes {
        if let Ok(Some(reading)) = probe.await {
            read.push(reading);
        }
    }
    read
}

/// Read the busy rungs of a private ladder without claiming one: admit the rung that serves our
/// beacon, forget a foreign one, ask about the unknown ones. For a member that may not co-host
/// yet: its book left the busy rungs out at setup (`register_rendezvous`), and until one is read
/// as ours it has no address of the rendezvous that answers. The walk of the co-host arm reads the
/// same way, but a joiner's first walk waits for the reclaim ticker, and its first link with it.
pub(crate) async fn read_ladder(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    rungs: &mut RungWatch,
) {
    let node = peer.id();
    let now = Instant::now();
    for &port in &params.bind_ports {
        if !rung_is_busy(port) {
            continue;
        }
        match rungs.reading(port, now) {
            RungRead::Ours => {
                rungs.clear_foreign(port);
                settle_on_rung(params, peer, peer_book, port).await;
                return;
            }
            RungRead::Foreign | RungRead::SilentLongEnough => {
                rungs.mark_foreign(port);
                forget_rungs(params, peer, peer_book, |rung| rung == port).await;
            }
            RungRead::Silent => {
                if !rungs.refused(port) {
                    admit_rung(params, peer, peer_book, port).await;
                }
            }
            RungRead::Unknown => rungs.ask(params, node, port, true),
        }
    }
}

/// What [`build_rendezvous_endpoint`] ended with.
pub(crate) enum Walk {
    /// A rung was free (or, public, the endpoint was built): the beacon can stand up on it.
    Bound(Endpoint, RendezvousLane),
    /// A rung was taken and its listener answered as the beacon of our own mesh: a holder exists,
    /// and it is not this member. The port is the rung of the holder.
    Rival(u16),
    /// No rung was taken, and no holder was read.
    Nothing,
    /// Every rung is held by another process, each read as foreign or silent for the whole
    /// window.
    NoRung,
}

/// What a call of [`ensure_holder`] left behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Held {
    /// This call stood up the rendezvous: a `None`/dead to live transition.
    Claimed,
    /// The ladder walk read a live holder of our mesh that is not this member. Only a private
    /// ladder reads one inline; a public member learns it from its probe verdict.
    Rival,
    /// Nothing changed: the beacon is held already, or a probe is out.
    Idle,
    /// Every rung of the ladder is held by another process: no member can serve the rendezvous
    /// until one lets go.
    NoRung,
}

/// Idempotent: a no-op while we co-host and the task is alive;
/// otherwise (never started, or the task died) try to (re)stand-up the
/// rendezvous. All outcomes are quiet — the next heal/reclaim tick retries.
///
/// **Nothing slow happens on the caller's task.** A public member that must
/// probe before claiming starts the probe (`spawn_rival_probe`) and returns
/// immediately; the verdict lands on the event loop's own arm, which calls
/// [`claim_after_probe`]. The private ladder walk is instant too: a rung that
/// is bound by somebody else is read from `rungs`, and what is not known is
/// asked by probe tasks whose reports land on the loop's own arm, which walks
/// again. The bind is milliseconds, and `subscribe_and_join` runs inside the
/// spawned co-host task.
///
/// Returns what the call left behind: [`Held::Claimed`] is a **new**
/// rendezvous (a `None`/dead → live transition), the edge the event loop's
/// rival re-check scheduling keys on. Starting a probe is not that edge.
pub(crate) async fn walk_ladder(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    current: &mut Option<Rendezvous>,
    probe_first: bool,
    probe: &mut Option<RivalProbe>,
    rungs: &mut RungWatch,
) -> Held {
    if !releasable(current) {
        return Held::Idle;
    }
    // Public probe-before-claim. Skipped for the eager origin
    // (`probe_first == false`): it has no peers to collide with and must be
    // the beacon from t=0. One probe at a time — a second would answer the
    // same question at the same cost.
    if params.bind_ports.is_empty() && probe_first {
        if probe.is_none() {
            *probe = spawn_rival_probe(params, peer.id()).await;
        }
        return Held::Idle;
    }
    claim::claim_holder(params, peer, peer_book, current, rungs).await
}
