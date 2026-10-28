//! The **beacon role**: the runtime that co-hosts the rendezvous
//! endpoint — the creator-independent bootstrap anchor.
//!
//! Concept split (see the Concept Glossary in AGENTS.md): *rendezvous*
//! is the seed-derived **identity** (`protocol::crypto`); *beacon*
//! is the **role** a live member plays by binding and serving that
//! identity. This module owns the role; it never derives the identity.
//!
//! A co-hosting member binds a second iroh endpoint to the shared
//! `rendezvous_secret` and glues it into the local mesh via this
//! process's own peer endpoint, so a cold joiner that dials the
//! seed-derived `rendezvous_id` is shuffled into the full mesh.
//!
//! - **Public:** ephemeral port, discoverable by node id via N0 pkarr.
//!   Every member co-hosts permanently; pkarr is last-writer-wins, so
//!   the record always resolves to a recently-live member. Two
//!   `EagerProbed` members can still claim inside each other's probe
//!   window and bind duplicate same-id copies (each capturing its own
//!   bootstrap dial); the event loop's periodic rival re-check shed
//!   (`daemon::event_loop::shed_rival_beacon_if_due`) re-arbitrates, so
//!   the single-co-host invariant holds *eventually*, not at claim time.
//! - **Private:** a deterministic loopback port *ladder* (no
//!   pkarr/DNS). One member per mesh is the beacon, the holder of the
//!   lowest live rung. A member binds the first free rung; on
//!   `AddrInUse` it reads the rung from the answer of a probe task —
//!   *ours* ⇒ the beacon already exists, stay a peer; *foreign* (an
//!   unrelated mesh that derived the same port) ⇒ skip to the next
//!   rung; *no answer* ⇒ wait, and bind the rung only once it has been
//!   silent for the whole reclaim window. A listener that refuses,
//!   closes or fails before a certificate (a busy or starting beacon of
//!   the same mesh) is read as no answer: only a key that the verifier
//!   rejects, or an identity that iroh reads as another, is *foreign*.
//!   So independent private meshes
//!   on one host never hijack each other. A second same-identity
//!   co-host can still stand up when a host is too loaded to answer: a
//!   holder above the first rung yields it on a positive answer of a
//!   lower rung, at the next heal tick, and a holder whose own rung
//!   stops answering sheds it. On the beacon's death its rung frees and
//!   the next heal/reclaim tick re-elects.
//!
//! The rendezvous endpoint never authors app messages; its node id is
//! filtered out of peer-side neighbor handling.

use std::net::{Ipv4Addr, SocketAddr};

use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::sync::mpsc;

use crate::lookup::{
    ProbeAnswer, TransportHandles, add_peer_addr, build_endpoint, build_mesh, probe_answer,
    replace_peer_addr,
};
use crate::protocol::mesh::{LookupOpts, RelayChoice};
use crate::util::clock::Instant;
use crate::util::tuning::RENDEZVOUS_PROBE;

use crate::util::tuning;
use iroh::address_lookup::memory;

mod contest;
mod dependents;
mod held;
mod rendezvous;
mod rendezvous_params;
mod rival_probe;
mod rung_ladder;
mod rung_watch;
pub(crate) use contest::{Contest, claim_after_probe, releasable};
pub(crate) use dependents::Dependents;
pub(crate) use held::{Held, Walk, read_busy_rungs, read_ladder, walk_ladder};
pub(crate) use rendezvous::{Rendezvous, RendezvousLane};
pub(crate) use rendezvous_params::RendezvousParams;
pub(crate) use rival_probe::{RivalProbe, probe_verdict, spawn_rival_probe};
pub(crate) use rung_ladder::{
    admit_rung, busy_rungs, forget_rungs, holder_entry, refresh_holder_rung, rendezvous_addr,
    rendezvous_addr_without, rung_of, settle_on_rung,
};
pub(crate) use rung_watch::{RungRead, RungReport, RungWatch};

/// Probe a `AddrInUse` private rung: is the listener *our* mesh's
/// rendezvous, or an unrelated mesh that happened to derive the same
/// port? A loopback `connect` to `rendezvous_id` succeeds only if the
/// listener presents that exact node id (iroh validates it during the
/// TLS handshake) — a foreign rendezvous (different key) is rejected,
/// a dead socket times out. Resolves in milliseconds against a live
/// loopback listener; the timeout only guards a pathological socket.
///
/// `prober` must be a **throwaway** endpoint, never this member's peer
/// endpoint, and that is a correctness requirement rather than hygiene.
/// The dial goes out on `GOSSIP_ALPN`, which is exactly what the beacon's
/// gossip accepts and adopts as a peer connection. Dialed from our own
/// endpoint it arrives as a second connection *from us*, and
/// `PeerState::accept_conn` promotes the newcomer to our **active**
/// connection, superseding the real one. Closing the probe then reads to
/// the beacon as our active connection dropping: it marks us
/// disconnected and emits `NeighborDown`. The probe would tear down the
/// very link whose existence it is asking about — and on a ticker, kill
/// it again every time it was re-established. From a throwaway identity
/// the beacon sees a stranger arrive and leave, which costs it nothing.
/// [`spawn_rival_probe`] takes the same precaution for the public path.
///
/// **One attempt, and four answers.** A rung whose listener failed the identity is foreign for
/// certain: the verifier rejected its key, or iroh reads the identity as another. A rung that
/// refused or said nothing is not: a busy or starting beacon of our own mesh refuses, a host too
/// loaded to answer reads as silence, and a bind cannot be taken back. So the walk binds on
/// [`ProbeAnswer::Foreign`] at once, and on silence or a refusal only after the rung has stayed
/// silent for [`RECLAIM_WINDOW`] across walks (see `build_rendezvous_endpoint`). A walk costs
/// one attempt on a silent rung, not three.
async fn rung_answer(prober: &Endpoint, rendezvous_id: EndpointId, port: u16) -> ProbeAnswer {
    let addr = EndpointAddr::new(rendezvous_id)
        .with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    let answer = probe_answer(prober, addr, RENDEZVOUS_PROBE).await;
    tracing::trace!(target: "habilis_network::beacon", port, ?answer, "private rung identity-probe");
    answer
}

/// Tests only: the members whose rung probe says nothing whatever is there. It stands for a host
/// too loaded to answer, and it is per member: a process-wide dial would make every in-process
/// member misread at once, which is not what a loaded host does.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
static BLIND_RUNG_PROBES: std::sync::Mutex<std::collections::BTreeSet<EndpointId>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// Make the rung probe of `member` read silence (`blind`), or let it read the truth again.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub(crate) fn set_blind_rung_probes(member: EndpointId, blind: bool) {
    let mut members = BLIND_RUNG_PROBES.lock().expect("no poison");
    if blind {
        members.insert(member);
    } else {
        members.remove(&member);
    }
}

/// Whether a test made the rung probe of `member` read silence. It is always false outside the
/// `iroh-test-utils` build.
pub(crate) fn rung_probes_are_blind(member: EndpointId) -> bool {
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    {
        BLIND_RUNG_PROBES
            .lock()
            .expect("no poison")
            .contains(&member)
    }
    #[cfg(not(all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
    {
        let _ = member;
        false
    }
}

/// Whether somebody holds `port`: a socket of ours cannot be bound there. Instant, and no side
/// effect, so a walk can tell which rungs of a ladder are busy without binding one.
pub(crate) fn rung_is_busy(port: u16) -> bool {
    std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_err()
}

/// The beacon mirrors the peer's *address-lookups* (so a joiner
/// resolves `rendezvous_id` via whichever it enabled) but homes on a
/// **single** relay rung — `params.bootstrap_relay`, the first
/// reachable rung of the ladder. Unlike a peer (which spreads
/// across the whole multi-relay set for resilience), the beacon must be
/// at the one deterministic rung the joiner pre-registers
/// (`daemon::setup::register_rendezvous`), or the relay-direct dial
/// finds nothing. A `None` rung ⇒ relay off for the beacon (joiners use
/// mDNS/DHT).
pub(crate) fn beacon_lookups(params: &RendezvousParams) -> LookupOpts {
    LookupOpts::new(
        params
            .bootstrap_relay
            .clone()
            .map_or(RelayChoice::Disabled, |rung| {
                RelayChoice::Custom(vec![rung])
            }),
    )
    .with_mdns(params.lookups.mdns)
    .with_dht(params.lookups.dht)
}

/// Build the rendezvous endpoint (see module docs for the one-beacon /
/// claim-if-free / identity-probe rationale). Public: one
/// ephemeral-port endpoint. Private: bind the first **free** ladder
/// rung; on `AddrInUse`, probe — *ours* ⇒ `None` (stay a peer),
/// *foreign* ⇒ next rung. `None` also covers public build failure /
/// every rung foreign-squatted (≈0); the next tick retries.
async fn build_rendezvous_endpoint(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    rungs: &mut RungWatch,
) -> Walk {
    let node = peer.id();
    let lookups = beacon_lookups(params);
    if params.answers_jsep() {
        // The public probe-before-claim that used to run here — the analog
        // of the private rung identity-probe below — now runs off the loop
        // (`spawn_rival_probe`), and `ensure` only reaches this point once
        // its verdict says the rendezvous is free. Everything left is a
        // bind.
        //
        // A public rendezvous carries the `WebRTC` transport and answers
        // JSEP: a browser-shaped peer has no IP to punch with, so on a mesh
        // whose relay is lookup only the data channel is the only path its
        // rendezvous link can ever be admitted on.
        let webrtc = crate::lookup::new_webrtc_handle(params.secret.public());
        // Made before the endpoint: the endpoint reports its connections to it
        // from the first handshake on.
        let admission = crate::transport::SignalAdmission::new(crate::transport::MAX_DIRECT_PEERS);
        let endpoint = build_endpoint(
            &lookups,
            Some(params.secret.clone()),
            None,
            Vec::new(),
            TransportHandles {
                webrtc: Some(webrtc.clone()),
                admission: Some(admission.clone()),
                ..TransportHandles::default()
            },
        )
        .await
        .ok();
        if endpoint.is_some() {
            tracing::info!(target: "habilis_network::beacon", node = %node.fmt_short(), "beacon assumed: bound public rendezvous endpoint (ephemeral port)");
        } else {
            tracing::debug!(target: "habilis_network::beacon", "public beacon endpoint build failed; next tick retries");
        }
        return endpoint.map_or(Walk::Nothing, |endpoint| {
            Walk::Bound(endpoint, Some((webrtc, admission)))
        });
    }
    // The private ladder. The walk is instant: it binds a free rung when every lower rung is
    // foreign (by answer, or by silence for the whole window), reads what the probe tasks
    // reported about the busy ones, and asks for what it does not know.
    let now = Instant::now();
    for (index, &port) in params.bind_ports.iter().enumerate() {
        // The bind is what says that a rung is free, rung by rung: it is instant, and the answer
        // of a socket check could differ from it. A rung that does not bind is read.
        match build_endpoint(
            &lookups,
            Some(params.secret.clone()),
            Some(port),
            Vec::new(),
            TransportHandles::default(),
        )
        .await
        {
            Ok(endpoint) => {
                tracing::info!(target: "habilis_network::beacon", node = %node.fmt_short(), port, "beacon assumed: bound rendezvous ladder rung");
                rungs.forget();
                rungs.clear_foreign(port);
                // No `WebRTC` on the ladder: a loopback mesh has no browsers.
                return Walk::Bound(endpoint, None);
            }
            Err(error) => {
                tracing::trace!(target: "habilis_network::beacon", node = %node.fmt_short(), port, %error, "rung does not bind: read it");
            }
        }
        match rungs.reading(port, now) {
            RungRead::Ours => {
                tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), port, "rung already serves our beacon; staying peer");
                return Walk::Rival(port);
            }
            RungRead::Foreign | RungRead::SilentLongEnough => {
                tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), port, "rung held by a foreign mesh, or silent for the whole window; trying next rung");
                rungs.mark_foreign(port);
                forget_rungs(params, peer, peer_book, |rung| rung == port).await;
            }
            RungRead::Silent => {
                if rungs.refused(port) {
                    forget_rungs(params, peer, peer_book, |rung| rung == port).await;
                } else {
                    admit_rung(params, peer, peer_book, port).await;
                }
                tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), port, "rung says nothing; staying peer for now");
                return Walk::Nothing;
            }
            RungRead::Unknown => {
                // This rung is asked, and so is every later rung that looks busy: eight silent
                // rungs are resolved in one window, not eight. The socket check only picks the
                // rungs to ask early; the walk itself binds or reads one rung at a time.
                rungs.ask(params, node, port, true);
                for &later_port in params.bind_ports.iter().skip(index + 1) {
                    if rung_is_busy(later_port)
                        && rungs.reading(later_port, now) == RungRead::Unknown
                    {
                        rungs.ask(params, node, later_port, true);
                    }
                }
                return Walk::Nothing;
            }
        }
    }
    tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), "no rendezvous ladder rung taken; staying peer");
    if params.bind_ports.is_empty() {
        Walk::Nothing
    } else {
        Walk::NoRung
    }
}

/// [`walk_ladder`] for a test that has no loop: it waits for the probe tasks that the walk
/// asked for, and walks again, until the walk has nothing left to wait for.
#[cfg(test)]
pub(crate) async fn ensure_holder(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    current: &mut Option<Rendezvous>,
    probe_first: bool,
    probe: &mut Option<RivalProbe>,
) -> Held {
    use crate::util::tuning::RECLAIM_WINDOW;
    let (reports, mut arrivals) = mpsc::unbounded_channel();
    let mut rungs = RungWatch::new(reports);
    loop {
        let held = walk_ladder(
            params,
            peer,
            peer_book,
            current,
            probe_first,
            probe,
            &mut rungs,
        )
        .await;
        if held != Held::Idle || !rungs.waiting() {
            // After the test body, so that the walk keeps its own timing.
            habilis_network_test_tracing::at_end(async move { rungs.finish().await });
            return held;
        }
        if let Ok(Some(report)) = n0_future::time::timeout(
            RECLAIM_WINDOW + std::time::Duration::from_secs(4),
            arrivals.recv(),
        )
        .await
        {
            rungs.note(report, Instant::now());
        } else {
            habilis_network_test_tracing::at_end(async move { rungs.finish().await });
            return held;
        }
    }
}

/// [`ensure_holder`], as the bool of "did this call stand up a new rendezvous".
#[cfg(test)]
pub(crate) async fn ensure(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    current: &mut Option<Rendezvous>,
    probe_first: bool,
    probe: &mut Option<RivalProbe>,
) -> bool {
    ensure_holder(params, peer, peer_book, current, probe_first, probe).await == Held::Claimed
}

/// Bind the rendezvous endpoint and stand the beacon up on it. The rival
/// question is already settled by the time this runs — either it never
/// applied (private ladder, eager origin) or [`claim_after_probe`] answered
/// it.
#[cfg(test)]
async fn claim(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    current: &mut Option<Rendezvous>,
) -> bool {
    claim_holder(params, peer, peer_book, current, &mut RungWatch::detached()).await
        == Held::Claimed
}

/// [`claim`], with what the walk read when it did not bind.
pub(crate) async fn claim_holder(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &memory::MemoryLookup,
    current: &mut Option<Rendezvous>,
    rungs: &mut RungWatch,
) -> Held {
    let (endpoint, lane) = match build_rendezvous_endpoint(params, peer, peer_book, rungs).await {
        Walk::Bound(endpoint, lane) => (endpoint, lane),
        // Private: a rung is taken by the beacon of our own mesh. Joiners reach it by an
        // identity-checked dial; whether this member must go to it is the caller's to say.
        Walk::Rival(port) => {
            rungs.clear_foreign(port);
            settle_on_rung(params, peer, peer_book, port).await;
            return Held::Rival;
        }
        Walk::NoRung => return Held::NoRung,
        // Public: the endpoint build failed. Private: a rung is read, or waits for its probe.
        // Nothing to do; the next tick retries.
        Walk::Nothing => return Held::Idle,
    };

    // The rendezvous pseudo-node's active view is overlay plumbing, not the
    // member peer cap, so it stays at the shipped default rather than
    // tracking `--max-peers`.
    // The rendezvous pseudo-node accepts no unicast — it is not a peer.
    // A *public* rendezvous answers JSEP (`build_rendezvous_endpoint` put
    // the transport on the endpoint): a browser-shaped peer has no other
    // way onto a mesh whose relay is lookup only.
    let (gossip, router, book) = build_mesh(
        endpoint.clone(),
        tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
        None,
        lane.clone().map(|(handle, admission)| {
            (
                handle,
                admission,
                crate::transport::IceProfile { host_only: false },
            )
        }),
        // The rendezvous serves no caller protocol either — it is a meeting
        // point, not somewhere an application is reachable.
        Vec::new(),
        params.relay_transport.relay_allowed(),
        // The rendezvous keeps the hold: a joiner grafts it only once their
        // session is attached, so a held dial here is not a second one.
        false,
    );

    // Register the peer's address so the rendezvous can dial it
    // in private mode (no lookup); a harmless direct hint in public.
    add_peer_addr(&book, peer.addr());
    // And the other way: our peer is the one that dials the rendezvous, and a
    // public mesh without a relay rung gives it no lookup to find the id by. The entry keeps the
    // relay rung or the ladder that the mesh registered, see `holder_entry`.
    match rung_of(&endpoint, &params.bind_ports) {
        // A ladder: this node dials its own beacon by the id, and the endpoint tries every address
        // that it knows for the id. A rung that it did not bind can be held by an endpoint of
        // another identity, which fails the dial as a whole. The ladder was registered whole at
        // start, when no rung was busy yet.
        Some(index) => settle_on_rung(params, peer, peer_book, params.bind_ports[index]).await,
        None => replace_peer_addr(
            peer_book,
            holder_entry(endpoint.addr(), params, &rungs.withheld_rungs()),
        ),
    }
    let topic_id = params.topic_id;

    // Relay-monitor inputs. The monitor runs as its **own** task (below),
    // off both the event loop and this gossip task, so relay probes never
    // stall rendezvous bridging. Spawned whenever relay is enabled
    // (public + a non-empty ladder) — *not* gated on currently holding a
    // rung, so a relay-less beacon keeps probing to rediscover one.
    let ladder = crate::lookup::relay_ladder(&params.lookups.relay_lookup).collect::<Vec<_>>();
    let monitors_relay = !params.lookups.is_loopback() && !ladder.is_empty();
    let monitor_endpoint = endpoint.clone();
    let monitor_homed = params.bootstrap_relay.is_some();
    let monitor_rung_tx = params.rung_tx.clone();
    let rendezvous_endpoint = endpoint.clone();
    // A bounded channel and `try_send`: a sign that is lost to a burst is one of many.
    let (arrivals_tx, arrivals) = mpsc::channel(32);

    let task = n0_future::task::spawn(async move {
        use futures_util::StreamExt as _;

        // Keep the gossip frontend + the Router's accept loop alive
        // for the task's lifetime so the rendezvous stays reachable by
        // cold joiners.
        let _endpoint = endpoint;
        let _router = router;

        // *Inside the task*, not in `ensure`, so `daemon::run` never blocks
        // here — blocking it stalls in-process two-session setups whose
        // runtime must also drive the peer. No bootstrap: our own peer dials
        // us, and dialing it back races that dial (see
        // `a_rendezvous_does_not_dial_its_own_peer`).
        let Ok(topic) = gossip.subscribe(topic_id, Vec::new()).await else {
            return;
        };
        // Retain the gossip frontend for the task's lifetime.
        let _gossip = gossip;
        let (_sender, mut receiver) = topic.split();
        // App payloads are discarded — this node only relays the gossip
        // overlay. Who links to it is reported to the holder, which reads it as a sign of
        // another group. Ends when the topic terminally closes.
        while let Some(event) = receiver.next().await {
            if let Ok(iroh_gossip::api::Event::NeighborUp(id)) = event {
                let _ = arrivals_tx.try_send(id);
            }
        }
    });

    // Relay liveness/discovery, off this gossip task: never stops
    // probing, backs off while relay-less. `None` when relay is disabled
    // (private / empty ladder).
    let monitor = monitors_relay.then(|| {
        crate::lookup::spawn_relay_monitor(monitor_endpoint, ladder, monitor_rung_tx, monitor_homed)
    });

    tracing::info!(target: "habilis_network::beacon", node = %peer.id().fmt_short(), "beacon role active: serving the rendezvous");
    *current = Some(Rendezvous {
        task,
        monitor,
        endpoint: rendezvous_endpoint,
        lane,
        arrivals,
        released: false,
    });
    Held::Claimed
}

#[cfg(test)]
mod tests {
    use super::dependents::foreign_sessions;
    use super::rival_probe::verdict_of;
    use super::{
        Contest, Endpoint, LookupOpts, Rendezvous, RendezvousParams, RivalProbe, claim, ensure,
        holder_entry, probe_verdict, releasable, rendezvous_addr, spawn_rival_probe,
    };
    use habilis_network_test_tracing::test;
    use iroh::SecretKey;
    use iroh_gossip::proto::TopicId;
    use tokio::sync::{oneshot, watch};

    use crate::daemon::setup;
    use crate::util::{clock, tuning};
    use iroh::address_lookup::memory;
    use tokio::sync::mpsc;
    /// Two ports of a ladder: the first is taken by `held` (a socket that says nothing, or another
    /// mesh's beacon), the second is free.
    fn ladder_of_two() -> (std::net::UdpSocket, Vec<u16>) {
        let first = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a loopback socket for the first rung");
        let second = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let ports = vec![first.local_addr().expect("its address").port(), second];
        (first, ports)
    }

    /// A rung that says nothing is not a rung that is not ours: a host too loaded to answer reads
    /// the same, and a bind cannot be taken back. One walk binds nothing on a silence, and costs
    /// one attempt, not three: the owner of a silent rung held the caller's task for 3.5 s.
    #[test]
    async fn one_walk_that_meets_a_silent_rung_binds_nothing_and_costs_one_attempt() {
        let (silent, ports) = ladder_of_two();
        let mut params = public_params();
        params.bind_ports = ports;
        let peer = loopback_endpoint().await;
        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut probe = None;

        let started = std::time::Instant::now();
        let claimed = ensure(&params, &peer, &book, &mut beacon, false, &mut probe).await;
        let took = started.elapsed();

        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        peer.close().await;
        drop(silent);
        assert!(
            !claimed,
            "the walk read a rung that said nothing as foreign and bound the next one"
        );
        assert!(
            took < std::time::Duration::from_millis(1500),
            "the walk of a silent rung took {took:?}: one attempt is 1 s"
        );
    }

    /// A rung that answers as another mesh's beacon is foreign for certain, and the walk binds the
    /// next rung at once: it does not wait to be told twice.
    #[test]
    async fn a_walk_that_meets_another_meshs_beacon_binds_the_next_rung_at_once() {
        let (squat, ports) = ladder_of_two();
        let first = ports[0];
        drop(squat);
        let other_secret = SecretKey::generate();
        let mut other = public_params();
        other.id = other_secret.public();
        other.secret = other_secret;
        other.bind_ports = vec![first];
        let other_peer = loopback_endpoint().await;
        let other_book = crate::lookup::address_book(&other_peer);
        let mut other_beacon = None;
        let mut other_probe = None;
        assert!(
            ensure(
                &other,
                &other_peer,
                &other_book,
                &mut other_beacon,
                false,
                &mut other_probe,
            )
            .await,
            "the other mesh claims the first rung"
        );

        let mut params = public_params();
        params.bind_ports = ports;
        let peer = loopback_endpoint().await;
        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut probe = None;
        let started = std::time::Instant::now();
        let claimed = ensure(&params, &peer, &book, &mut beacon, false, &mut probe).await;
        let took = started.elapsed();

        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        if let Some(held) = other_beacon.take() {
            held.shed_and_wait().await;
        }
        peer.close().await;
        other_peer.close().await;
        assert!(
            claimed,
            "a foreign beacon is read as foreign: the next rung is bound"
        );
        assert!(
            took < std::time::Duration::from_millis(1500),
            "the walk took {took:?} to bind the rung after a foreign one"
        );
    }

    /// Three of the four answers of a probe are told apart by what a listener does: a listener of
    /// the identity that was asked for opens the connection, a listener of another identity fails
    /// the handshake, and a port that nobody answers on says nothing. The fourth, a refusal, has
    /// its own tests in `lookup`. The mapping is read from the error types of iroh, so this test
    /// is what proves it on a real handshake.
    #[test]
    async fn a_probe_tells_ours_from_foreign_from_no_answer() {
        use super::{EndpointAddr, EndpointId, Ipv4Addr, SocketAddr};
        use crate::lookup::{ProbeAnswer, probe_answer};

        // One prober per probe: iroh dials an identity and keeps every path it learned for it, so
        // a second dial of the same id from one endpoint can complete on the path of the first.
        async fn asked(addr: EndpointAddr, timeout: std::time::Duration) -> ProbeAnswer {
            let prober = loopback_endpoint().await;
            let answer = probe_answer(&prober, addr, timeout).await;
            prober.close().await;
            answer
        }

        let port = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let mut params = public_params();
        params.bind_ports = vec![port];
        let holder = loopback_endpoint().await;
        let holder_book = crate::lookup::address_book(&holder);
        let mut beacon = None;
        let mut holder_probe = None;
        assert!(
            ensure(
                &params,
                &holder,
                &holder_book,
                &mut beacon,
                false,
                &mut holder_probe,
            )
            .await,
            "the beacon claims the rung"
        );
        let silent =
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a silent loopback socket");
        let at = |id: EndpointId, rung: u16| {
            EndpointAddr::new(id).with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, rung)))
        };
        let timeout = std::time::Duration::from_secs(2);

        let ours = asked(at(params.id, port), timeout).await;
        let foreign = asked(at(SecretKey::generate().public(), port), timeout).await;
        let none = asked(
            at(params.id, silent.local_addr().expect("its address").port()),
            std::time::Duration::from_secs(1),
        )
        .await;

        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        holder.close().await;
        assert_eq!(ours, ProbeAnswer::Ours);
        assert_eq!(
            foreign,
            ProbeAnswer::Foreign,
            "a handshake that failed is an answer"
        );
        assert_eq!(
            none,
            ProbeAnswer::NoAnswer,
            "a socket that says nothing is no answer"
        );
    }

    /// A rung that stays silent is bound at the walk after it has been silent for the whole
    /// reclaim window, and not before: the host that answers late is given the window, a rung
    /// that nobody serves is not kept for ever.
    #[test]
    async fn a_rung_that_stays_silent_for_the_whole_window_is_bound_at_a_later_walk() {
        use super::{Held, RungWatch, walk_ladder};
        use crate::util::tuning::RECLAIM_WINDOW;

        let (silent, ports) = ladder_of_two();
        let first = ports[0];
        let mut params = public_params();
        params.bind_ports = ports;
        let peer = loopback_endpoint().await;
        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut probe = None;
        let (reports, mut arrivals) = mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);

        // The first walk asks, and binds nothing.
        let asked = walk_ladder(
            &params,
            &peer,
            &book,
            &mut beacon,
            false,
            &mut probe,
            &mut rungs,
        )
        .await;
        let report = tokio::time::timeout(std::time::Duration::from_secs(5), arrivals.recv())
            .await
            .expect("a probe task reports")
            .expect("the channel is open");
        rungs.note(report, clock::Instant::now());
        // The rung says nothing: still no bind.
        let waited = walk_ladder(
            &params,
            &peer,
            &book,
            &mut beacon,
            false,
            &mut probe,
            &mut rungs,
        )
        .await;
        let kept_free = beacon.is_none();
        // The rung has been silent for the window already.
        rungs.age_silence(first, RECLAIM_WINDOW + std::time::Duration::from_secs(1));
        let later = walk_ladder(
            &params,
            &peer,
            &book,
            &mut beacon,
            false,
            &mut probe,
            &mut rungs,
        )
        .await;

        let bound = beacon.is_some();
        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        rungs.finish().await;
        peer.close().await;
        drop(silent);
        assert_eq!(
            asked,
            Held::Idle,
            "one walk binds nothing on a rung it has not read"
        );
        assert_eq!(waited, Held::Idle, "a silence binds nothing at once");
        assert!(kept_free);
        assert_eq!(
            later,
            Held::Claimed,
            "a rung silent for the whole window is bound"
        );
        assert!(bound);
    }

    /// Two silent rungs, and a free one after them: both are asked at once, both are passed when
    /// they have been silent for the window, and the free one is bound. A walk that asked one
    /// rung at a time would take two windows, and eight silent rungs eight.
    #[test]
    async fn two_silent_rungs_are_asked_at_once_and_passed_and_the_free_one_after_them_is_bound() {
        use super::{Held, RungWatch, walk_ladder};
        use crate::util::tuning::RECLAIM_WINDOW;

        let (first_socket, mut ports) = ladder_of_two();
        let (second_socket, second_ports) = ladder_of_two();
        let free = ports.pop().expect("the free port of the first ladder");
        ports.push(second_ports[0]);
        ports.push(free);
        let (first, second) = (ports[0], ports[1]);
        let mut params = public_params();
        params.bind_ports = ports;
        let peer = loopback_endpoint().await;
        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut probe = None;
        let (reports, mut arrivals) = mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);

        let asked = walk_ladder(
            &params,
            &peer,
            &book,
            &mut beacon,
            false,
            &mut probe,
            &mut rungs,
        )
        .await;
        // Both rungs are out at once: both report inside one second, not two.
        let started = std::time::Instant::now();
        for _ in 0..2 {
            let report = tokio::time::timeout(std::time::Duration::from_secs(5), arrivals.recv())
                .await
                .expect("a probe task reports")
                .expect("the channel is open");
            rungs.note(report, clock::Instant::now());
        }
        let both_asked_at_once = started.elapsed() < std::time::Duration::from_millis(1800);
        let window = RECLAIM_WINDOW + std::time::Duration::from_secs(1);
        rungs.age_silence(first, window);
        rungs.age_silence(second, window);
        let later = walk_ladder(
            &params,
            &peer,
            &book,
            &mut beacon,
            false,
            &mut probe,
            &mut rungs,
        )
        .await;

        let bound = beacon.is_some();
        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        rungs.finish().await;
        peer.close().await;
        drop((first_socket, second_socket));
        assert_eq!(asked, Held::Idle);
        assert!(
            both_asked_at_once,
            "the two rungs were asked one after the other"
        );
        assert_eq!(
            later,
            Held::Claimed,
            "both silent rungs are passed and the free one is bound"
        );
        assert!(bound);
    }

    /// One report of silence is one sample. A rung is passed as silent when two reports a window
    /// apart said nothing, not when one report is read late: the reading stays fresh for a heal
    /// tick, and a walk that reads it a window after its only report must still wait for the
    /// second one.
    #[test]
    fn one_silent_report_is_not_a_window_of_silence_however_late_it_is_read() {
        use super::{RungRead, RungReport, RungWatch};
        use crate::lookup::ProbeAnswer;
        use crate::util::tuning::RECLAIM_WINDOW;

        let (reports, _arrivals) = mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);
        let then = clock::Instant::now();
        rungs.note(
            RungReport {
                port: 4242,
                answer: ProbeAnswer::NoAnswer,
                generation: 0,
            },
            then,
        );

        let late = then + RECLAIM_WINDOW + std::time::Duration::from_secs(1);
        assert_eq!(
            rungs.reading(4242, late),
            RungRead::Silent,
            "one report of silence passed the rung after the window: a sample is not a window"
        );
    }

    /// A probe task that was given up can still report. Its report answers an ask that is over, and
    /// it must not end the wait for the probe that replaced it: the loop would walk on an answer
    /// that is older than the ask it waits for.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    #[test]
    async fn the_late_report_of_a_probe_that_was_given_up_does_not_stop_its_replacement() {
        use super::{RungRead, RungWatch};

        let params = public_params();
        let node = SecretKey::generate().public();
        crate::beacon::set_blind_rung_probes(node, true);
        let (reports, mut arrivals) = mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);
        let port = 4242;

        rungs.ask(&params, node, port, true);
        let old = arrivals.recv().await.expect("the first probe reports");
        rungs.expire_probes_in_flight();
        rungs.ask(&params, node, port, true);
        let new = arrivals.recv().await.expect("the second probe reports");

        let now = clock::Instant::now();
        rungs.note(old, now);
        let waiting = rungs.waiting();
        let read = rungs.reading(port, now);
        rungs.note(new, now);
        let waiting_after = rungs.waiting();
        let read_after = rungs.reading(port, now);
        crate::beacon::set_blind_rung_probes(node, false);

        assert!(
            waiting,
            "the late report of the first probe ended the wait for the second"
        );
        assert_eq!(
            read,
            RungRead::Unknown,
            "an answer older than the ask in flight was stored as fresh"
        );
        assert!(
            !waiting_after,
            "the report of the second probe ends its wait"
        );
        assert_eq!(read_after, RungRead::Silent);
    }

    /// A rung whose listener answered and gave no identity stays out of the book until it answers
    /// as ours. A rung that said nothing is not kept out: a host too loaded to answer holds our
    /// beacon on it all the same.
    #[test]
    fn a_refused_rung_is_withheld_until_it_answers_as_ours() {
        use super::{ProbeAnswer, RungReport, RungWatch};

        let (reports, _arrivals) = mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);
        let port = 4242;
        let mut generation = 0;
        let mut note = |watch: &mut RungWatch, answer| {
            generation += 1;
            watch.note(
                RungReport {
                    port,
                    answer,
                    generation,
                },
                clock::Instant::now(),
            );
            watch.withheld_rungs()
        };

        assert_eq!(note(&mut rungs, ProbeAnswer::Refused), vec![port]);
        assert_eq!(note(&mut rungs, ProbeAnswer::NoAnswer), Vec::<u16>::new());
        assert_eq!(note(&mut rungs, ProbeAnswer::Refused), vec![port]);
        assert_eq!(note(&mut rungs, ProbeAnswer::Ours), Vec::<u16>::new());
    }

    /// A report that comes after the report of a newer probe of the same rung says nothing new, and
    /// it must not make the reading fresh again.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    #[test]
    async fn an_old_report_does_not_make_a_newer_reading_fresh_again() {
        use super::RungWatch;

        let params = public_params();
        let node = SecretKey::generate().public();
        crate::beacon::set_blind_rung_probes(node, true);
        let (reports, mut arrivals) = mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);
        let port = 4242;

        rungs.ask(&params, node, port, true);
        let old = arrivals.recv().await.expect("the first probe reports");
        rungs.expire_probes_in_flight();
        rungs.ask(&params, node, port, true);
        let new = arrivals.recv().await.expect("the second probe reports");

        let first = clock::Instant::now();
        rungs.note(new, first);
        rungs.note(old, first + std::time::Duration::from_secs(5));
        let stored = rungs
            .readings
            .get(&port)
            .expect("the reading of the second probe")
            .read_at;
        crate::beacon::set_blind_rung_probes(node, false);

        assert_eq!(
            stored, first,
            "the report of the first probe moved the time of a newer reading"
        );
    }

    /// A bind clears the readings: the ladder is ours now. The late report of a probe that was
    /// given up must not bring an answer back from before the bind, after the probe that replaced
    /// it has reported and the bind has cleared its reading.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    #[test]
    async fn a_late_report_of_a_probe_that_was_given_up_does_not_come_back_after_a_bind() {
        use super::{RungRead, RungWatch};

        let params = public_params();
        let node = SecretKey::generate().public();
        crate::beacon::set_blind_rung_probes(node, true);
        let (reports, mut arrivals) = mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);
        let port = 4242;

        rungs.ask(&params, node, port, true);
        let old = arrivals.recv().await.expect("the first probe reports");
        rungs.expire_probes_in_flight();
        rungs.ask(&params, node, port, true);
        let new = arrivals.recv().await.expect("the second probe reports");

        let now = clock::Instant::now();
        rungs.note(new, now);
        rungs.forget();
        rungs.note(old, now);
        let read = rungs.reading(port, now);
        crate::beacon::set_blind_rung_probes(node, false);

        assert_eq!(
            read,
            RungRead::Unknown,
            "an answer from before the bind was stored after it"
        );
    }

    /// Two reports that said nothing, a window apart, pass the rung: the second one is the proof.
    #[test]
    fn two_silent_reports_a_window_apart_pass_the_rung() {
        use super::{RungRead, RungReport, RungWatch};
        use crate::lookup::ProbeAnswer;
        use crate::util::tuning::RECLAIM_WINDOW;

        let (reports, _arrivals) = mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);
        let then = clock::Instant::now();
        let report = RungReport {
            port: 4242,
            answer: ProbeAnswer::NoAnswer,
            generation: 0,
        };
        rungs.note(report, then);

        let again = then + RECLAIM_WINDOW + std::time::Duration::from_secs(1);
        rungs.note(report, again);

        assert_eq!(rungs.reading(4242, again), RungRead::SilentLongEnough);
    }

    /// A reading in the map is used, not asked for again: a rung that answered as ours is a
    /// holder, whatever its next probe would say, and a rung that answered as foreign is passed
    /// at once. This is the fact that the lower-rung check of a holder leaves for the walk after
    /// its shed.
    #[test]
    async fn a_fresh_reading_in_the_map_is_read_without_asking_again() {
        use super::{Held, RungReport, RungWatch, walk_ladder};
        use crate::lookup::ProbeAnswer;

        let (silent, ports) = ladder_of_two();
        let first = ports[0];
        let mut params = public_params();
        params.bind_ports = ports;
        let peer = loopback_endpoint().await;
        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut probe = None;
        let mut rungs = RungWatch::detached();
        let now = clock::Instant::now();

        rungs.note(
            RungReport {
                port: first,
                answer: ProbeAnswer::Ours,
                generation: 0,
            },
            now,
        );
        let on_ours = walk_ladder(
            &params,
            &peer,
            &book,
            &mut beacon,
            false,
            &mut probe,
            &mut rungs,
        )
        .await;
        rungs.note(
            RungReport {
                port: first,
                answer: ProbeAnswer::Foreign,
                generation: 0,
            },
            now,
        );
        let on_foreign = walk_ladder(
            &params,
            &peer,
            &book,
            &mut beacon,
            false,
            &mut probe,
            &mut rungs,
        )
        .await;

        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        peer.close().await;
        drop(silent);
        assert_eq!(
            on_ours,
            Held::Rival,
            "a rung that answered as ours is a holder"
        );
        assert_eq!(
            on_foreign,
            Held::Claimed,
            "a foreign rung is passed at once"
        );
    }

    /// Every rung of the ladder is held by another process: the walk says so, and does not stay
    /// "idle" as it does while a probe is out. A member that cannot serve the rendezvous and
    /// cannot reach one is in a state that the loop must be able to report.
    #[test]
    async fn a_walk_that_reads_every_rung_as_taken_says_so() {
        use super::{Held, RungReport, RungWatch, walk_ladder};
        use crate::lookup::ProbeAnswer;

        let (first_socket, first_ports) = ladder_of_two();
        let (second_socket, second_ports) = ladder_of_two();
        let (first, second) = (first_ports[0], second_ports[0]);
        let mut params = public_params();
        params.bind_ports = vec![first, second];
        let peer = loopback_endpoint().await;
        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut probe = None;
        let mut rungs = RungWatch::detached();
        let now = clock::Instant::now();
        for port in [first, second] {
            rungs.note(
                RungReport {
                    port,
                    answer: ProbeAnswer::Foreign,
                    generation: 0,
                },
                now,
            );
        }

        let walked = walk_ladder(
            &params,
            &peer,
            &book,
            &mut beacon,
            false,
            &mut probe,
            &mut rungs,
        )
        .await;

        let bound = beacon.is_some();
        peer.close().await;
        drop((first_socket, second_socket));
        assert_eq!(
            walked,
            Held::NoRung,
            "a ladder that is taken whole is not a walk that waits for a probe"
        );
        assert!(!bound);
    }

    /// The walk of a claim tick does not wait for a rung that does not answer. The caller is the
    /// event loop, and a silent rung held it for a second at every tick (three and a half
    /// before the walk made one attempt): the members that hold no beacon, all of them, paid it.
    #[test]
    async fn the_walk_of_a_claim_tick_returns_at_once_on_a_rung_that_says_nothing() {
        use super::{Held, RungWatch, walk_ladder};

        let (silent, ports) = ladder_of_two();
        let mut params = public_params();
        params.bind_ports = ports;
        let peer = loopback_endpoint().await;
        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut probe = None;

        let mut rungs = RungWatch::detached();
        let started = std::time::Instant::now();
        let held = walk_ladder(
            &params,
            &peer,
            &book,
            &mut beacon,
            false,
            &mut probe,
            &mut rungs,
        )
        .await;
        let took = started.elapsed();

        if let Some(bound) = beacon.take() {
            bound.shed_and_wait().await;
        }
        rungs.finish().await;
        peer.close().await;
        drop(silent);
        assert_eq!(held, Held::Idle, "a silent rung binds nothing in one walk");
        assert!(
            took < std::time::Duration::from_millis(100),
            "the walk of a claim tick waited {took:?} for a rung that says nothing"
        );
    }

    /// A free rung is claimed, and a taken rung of our own mesh is read as a holder that is not us.
    /// The second answer used to be `false`, the same as "nothing happened".
    #[test]
    async fn a_walk_that_reads_a_holder_of_our_mesh_says_so() {
        use super::{Held, ensure_holder};

        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let mut params = public_params();
        params.bind_ports = vec![port];

        let first = loopback_endpoint().await;
        let first_book = crate::lookup::address_book(&first);
        let mut first_beacon = None;
        let mut first_probe = None;
        let claimed = ensure_holder(
            &params,
            &first,
            &first_book,
            &mut first_beacon,
            false,
            &mut first_probe,
        )
        .await;

        let second = loopback_endpoint().await;
        let second_book = crate::lookup::address_book(&second);
        let mut second_beacon = None;
        let mut second_probe = None;
        let read = ensure_holder(
            &params,
            &second,
            &second_book,
            &mut second_beacon,
            false,
            &mut second_probe,
        )
        .await;
        let held_again = ensure_holder(
            &params,
            &first,
            &first_book,
            &mut first_beacon,
            false,
            &mut first_probe,
        )
        .await;

        if let Some(held) = first_beacon.take() {
            held.shed_and_wait().await;
        }
        first.close().await;
        second.close().await;
        assert_eq!(claimed, Held::Claimed, "a free rung is claimed");
        assert_eq!(read, Held::Rival, "a taken rung of our mesh is a holder");
        assert!(second_beacon.is_none(), "and it is not claimed");
        assert_eq!(held_again, Held::Idle, "a held beacon changes nothing");
    }

    #[test]
    fn the_holder_with_the_lower_member_id_keeps_the_beacon() {
        let first = SecretKey::generate().public();
        let second = SecretKey::generate().public();
        let (low, high) = if first < second {
            (first, second)
        } else {
            (second, first)
        };

        let contest = |own, rival| Contest { own, rival }.own_yields();
        assert!(contest(high, low), "the higher id yields to the lower");
        assert!(!contest(low, high), "the lower id keeps the beacon");
        assert!(!contest(low, low), "an id never yields to itself");
    }

    /// Observed on both holders of a split topic: the one session counted as a
    /// dependent was the holder's own peer endpoint, so each deferred its shed
    /// for the full wait and the split stayed.
    #[test]
    fn a_session_of_our_own_endpoints_is_no_dependent() {
        let peer = SecretKey::generate().public();
        let beacon = SecretKey::generate().public();
        let tab = SecretKey::generate().public();
        let own = [peer, beacon];

        assert_eq!(foreign_sessions(&[peer, beacon], &own).len(), 0);
        assert_eq!(foreign_sessions(&[peer, tab], &own), [tab]);
    }

    /// A real endpoint that touches nothing: `LookupOpts::loopback` binds
    /// 127.0.0.1 with relay, mDNS, DHT and the portmapper all off, so these
    /// tests make zero external network calls.
    async fn loopback_endpoint() -> Endpoint {
        crate::lookup::build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            crate::lookup::TransportHandles::default(),
        )
        .await
        .expect("loopback endpoint")
    }

    /// A probe wrapped around a channel we drive by hand. The endpoint is
    /// real but inert, because `RivalProbe` retains one so a departure can
    /// close it, and these tests are about the slot, not the dial.
    async fn probe_for(rx: oneshot::Receiver<bool>) -> (RivalProbe, Endpoint) {
        let endpoint = loopback_endpoint().await;
        let probe = RivalProbe {
            rx,
            task: n0_future::task::spawn(std::future::pending()),
            endpoint: Some(endpoint.clone()),
            cancel: None,
        };
        (probe, endpoint)
    }

    /// A beacon holding `endpoint`, whose co-host task is already finished —
    /// the "dead beacon" `releasable` is meant to clear.
    async fn dead_beacon(endpoint: Endpoint) -> Rendezvous {
        let task = n0_future::task::spawn(async {});
        // Let it finish, so `task.is_finished()` is true below.
        for _ in 0..100 {
            if task.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(task.is_finished(), "the co-host task should have ended");
        Rendezvous {
            task,
            monitor: None,
            endpoint,
            lane: None,
            arrivals: mpsc::channel(1).1,
            released: false,
        }
    }

    /// Params for the public probe-before-claim path: no `bind_ports` (so
    /// `ensure` takes the public branch) and all-off lookups (so nothing
    /// leaves the machine).
    fn public_params() -> RendezvousParams {
        let secret = SecretKey::generate();
        let id = secret.public();
        RendezvousParams {
            topic_id: TopicId::from_bytes([7u8; 32]),
            secret,
            bind_ports: Vec::new(),
            id,
            lookups: LookupOpts::loopback(),
            relay_transport: crate::transport::PayloadPath::DirectOnly,
            bootstrap_relay: None,
            rung_tx: watch::channel(None).0,
        }
    }

    /// Give a spawned close a chance to run, without pinning a duration the
    /// scheduler has to honour.
    async fn settle(endpoint: &Endpoint) {
        for _ in 0..200 {
            if endpoint.is_closed() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// A probe that is dropped, not asked to close, is what a crash leaves: the loop is aborted and
    /// its slot drops the probe. The prober endpoint must still close.
    #[test]
    async fn a_dropped_rival_probe_closes_its_endpoint() {
        let silent = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a silent loopback socket");
        let mut params = public_params();
        params.bind_ports = vec![silent.local_addr().expect("its address").port()];
        let probe = spawn_rival_probe(&params, SecretKey::generate().public())
            .await
            .expect("a probe with a rung to dial");
        let prober = probe.endpoint.clone().expect("the probe dials");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        drop(probe);

        // A close in the middle of a handshake drains for about 3 s, as in the test above.
        for _ in 0..600 {
            if prober.is_closed() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            prober.is_closed(),
            "a dropped probe left its endpoint open; its last handle logs the ungraceful-abort error"
        );
    }

    /// The same for a beacon that is dropped: the aborted loop drops it with no `shed`.
    #[test]
    async fn a_dropped_beacon_closes_its_endpoint() {
        let endpoint = loopback_endpoint().await;
        let beacon = dead_beacon(endpoint.clone()).await;

        drop(beacon);

        settle(&endpoint).await;
        assert!(
            endpoint.is_closed(),
            "a dropped beacon left its endpoint open; its last handle logs the ungraceful-abort error"
        );
    }

    /// Regression for `Endpoint dropped without calling Endpoint::close` on
    /// every Ctrl-C that landed mid-probe. A probe still in its handshake has
    /// sent a close frame nobody will acknowledge, so iroh's close waits out
    /// the QUIC drain (about 3s) before it finishes. A budget shorter than that
    /// abandoned the endpoint half-closed, and its drop logged the error.
    #[test]
    async fn abort_and_close_waits_out_a_probe_mid_handshake() {
        // Bound and never read: the handshake's packets vanish without an
        // answer, as they do into a relay rung nobody serves.
        let silent = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a silent loopback socket");
        let mut params = public_params();
        params.bind_ports = vec![silent.local_addr().expect("its address").port()];
        let probe = spawn_rival_probe(&params, SecretKey::generate().public())
            .await
            .expect("a probe with a rung to dial");
        let prober = probe.endpoint.clone().expect("the probe dials");
        // Let the handshake start, so there is a connection to drain.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        probe.abort_and_close().await;

        assert!(
            prober.is_closed(),
            "abort_and_close returned with the probe endpoint still open; its drop logs the ungraceful-abort error"
        );
    }

    /// The other half of the same error: the probe's dial ran out on its own
    /// and its task was already closing the endpoint when the departure came.
    /// Aborting the task there cut that close short, and a second `close()`
    /// returns at once while one is in flight, so nothing finished it.
    #[test]
    async fn abort_and_close_lets_a_probe_finish_closing_its_own_endpoint() {
        let silent = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a silent loopback socket");
        let target = super::EndpointAddr::new(SecretKey::generate().public())
            .with_ip_addr(silent.local_addr().expect("its address"));
        let prober = loopback_endpoint().await;
        let dialer = prober.clone();
        let task = n0_future::task::spawn(async move {
            // The dial gives up almost at once, leaving a handshake to drain,
            // and the task moves on to its own close, as the real one does.
            crate::lookup::probe_connect(&dialer, target, std::time::Duration::from_millis(200))
                .await;
            dialer.close().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let probe = RivalProbe {
            rx: oneshot::channel().1,
            task,
            endpoint: Some(prober.clone()),
            cancel: None,
        };

        probe.abort_and_close().await;

        assert!(
            prober.is_closed(),
            "abort_and_close cut the probe's own close short; its drop logs the ungraceful-abort error"
        );
    }

    /// Regression for `Endpoint dropped without calling Endpoint::close` on a
    /// departure while the relay monitor re-walks the ladder: the walk probes
    /// each rung on an endpoint of its own, and aborting the monitor mid-walk
    /// dropped that endpoint open. Relay-less, the monitor walks at once.
    #[cfg(feature = "host")]
    #[test]
    fn shed_and_wait_mid_rewalk_closes_the_monitor_probe_endpoint() {
        let (_silent, rung) = crate::testing::silent_relay_rung();

        let errors = crate::testing::errors_through_runtime_drop(async {
            let endpoint = loopback_endpoint().await;
            let monitor = crate::lookup::spawn_relay_monitor(
                endpoint.clone(),
                vec![rung],
                watch::channel(None).0,
                false,
            );
            // Let the walk bind its probe and start waiting for the relay.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let rendezvous = Rendezvous {
                task: n0_future::task::spawn(std::future::pending()),
                monitor: Some(monitor),
                endpoint,
                lane: None,
                arrivals: mpsc::channel(1).1,
                released: false,
            };

            rendezvous.shed_and_wait().await;
        });

        assert!(
            !errors.contains("Endpoint dropped without calling"),
            "the relay monitor's probe endpoint reached its drop open:\n{errors}"
        );
    }

    /// A holder dials its own beacon, and the endpoint tries every address that it knows for the id:
    /// a rung that it did not bind can be held by an endpoint of another identity, which fails the
    /// dial as a whole. The mesh registers the whole ladder at start, when no rung is busy yet, so
    /// the claim leaves the endpoint knowing the rung that the beacon bound and no other.
    #[test]
    async fn a_claim_leaves_the_endpoint_knowing_only_the_rung_it_bound() {
        let sockets: Vec<_> = (0..3)
            .map(|_| {
                std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                    .expect("a free loopback port")
            })
            .collect();
        let rungs: Vec<u16> = sockets
            .iter()
            .map(|socket| socket.local_addr().expect("its address").port())
            .collect();
        drop(sockets);
        let mut params = public_params();
        params.bind_ports = rungs.clone();
        let peer = loopback_endpoint().await;
        let book = crate::lookup::address_book(&peer);
        setup::register_rendezvous(&book, &params, &[]);
        peer.add_endpoint_addr(rendezvous_addr(&params).expect("the ladder"))
            .await
            .expect("the endpoint takes the ladder");
        let mut beacon = None;

        let claimed = claim(&params, &peer, &book, &mut beacon).await;

        let on = beacon
            .as_ref()
            .and_then(|held| held.rung_in(&rungs))
            .map(|index| rungs[index]);
        let known: Vec<u16> = peer
            .remote_info(params.id)
            .await
            .map(|info| {
                info.addrs()
                    .filter_map(|info| {
                        if let iroh::TransportAddr::Ip(socket) = info.addr() {
                            Some(socket.port())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let booked: Vec<u16> = book
            .get_endpoint_info(params.id)
            .expect("an entry")
            .into_endpoint_addr()
            .ip_addrs()
            .map(std::net::SocketAddr::port)
            .collect();
        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        peer.close().await;
        assert!(claimed, "a free rung is claimed");
        let on = on.expect("the beacon is bound on a rung");
        assert_eq!(
            known,
            vec![on],
            "the endpoint knows rungs that the beacon did not bind"
        );
        assert_eq!(
            booked,
            vec![on],
            "the book names rungs that the beacon did not bind"
        );
    }

    /// A member that knows a holder does not walk the ladder, and its book names the rung of the
    /// holder that it read last. When the holder moves to another rung, the member reads the
    /// ladder again without claiming, and the book names the new rung.
    #[test]
    async fn a_member_that_knows_a_holder_finds_the_rung_it_moved_to() {
        let sockets: Vec<_> = (0..2)
            .map(|_| {
                std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                    .expect("a free loopback port")
            })
            .collect();
        let rungs: Vec<u16> = sockets
            .iter()
            .map(|socket| socket.local_addr().expect("its address").port())
            .collect();
        drop(sockets);
        let mut params = public_params();
        params.bind_ports = rungs.clone();
        let holder_peer = loopback_endpoint().await;
        let holder_book = crate::lookup::address_book(&holder_peer);
        let mut beacon = None;
        assert!(claim(&params, &holder_peer, &holder_book, &mut beacon).await);
        let on = beacon
            .as_ref()
            .and_then(|held| held.rung_in(&rungs))
            .expect("the beacon is bound on a rung");
        let stale = rungs[1 - on];

        let member = loopback_endpoint().await;
        let book = crate::lookup::address_book(&member);
        crate::lookup::replace_peer_addr(
            &book,
            super::rung_ladder::rendezvous_holder_addr(&params, stale),
        );
        let (reports, mut arrivals) = mpsc::unbounded_channel();
        let mut rungs_watch = super::RungWatch::new(reports);
        for _ in 0..3 {
            super::refresh_holder_rung(&params, &member, &book, &mut rungs_watch).await;
            let ours = book
                .get_endpoint_info(params.id)
                .is_some_and(|info| info.into_endpoint_addr().ip_addrs().count() == 1)
                && book.get_endpoint_info(params.id).is_some_and(|info| {
                    info.into_endpoint_addr()
                        .ip_addrs()
                        .all(|socket| socket.port() == rungs[on])
                });
            if ours {
                break;
            }
            if let Ok(Some(report)) =
                n0_future::time::timeout(std::time::Duration::from_secs(5), arrivals.recv()).await
            {
                rungs_watch.note(report, super::Instant::now());
            }
        }

        let kept: Vec<u16> = book
            .get_endpoint_info(params.id)
            .expect("an entry")
            .into_endpoint_addr()
            .ip_addrs()
            .map(std::net::SocketAddr::port)
            .collect();
        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        member.close().await;
        holder_peer.close().await;
        assert_eq!(kept, vec![rungs[on]], "the book still names the old rung");
    }

    /// A rung that a foreign listener held and that this member then binds is its own rung: it
    /// is not foreign any more, or `register_rendezvous` would leave it out of the book after each
    /// heal.
    #[tokio::test]
    async fn a_rung_that_this_member_binds_is_no_longer_foreign() {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("a free loopback port");
        let rung = socket.local_addr().expect("its address").port();
        drop(socket);
        let mut params = public_params();
        params.bind_ports = vec![rung];
        let peer = loopback_endpoint().await;
        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut rungs = super::RungWatch::detached();
        rungs.mark_foreign(rung);

        let outcome = super::claim_holder(&params, &peer, &book, &mut beacon, &mut rungs).await;

        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        peer.close().await;
        assert_eq!(outcome, super::Held::Claimed, "the free rung is claimed");
        assert_eq!(
            rungs.withheld_rungs(),
            Vec::<u16>::new(),
            "the rung of our own beacon is still read as foreign"
        );
    }

    /// The entry after a claim holds the relay rung of the rendezvous and the direct addresses of
    /// the new holder, and none of a former holder's. A lane peer, whose IP transports are cleared,
    /// dials the bare id and can use only the relay rung.
    #[test]
    fn a_claim_keeps_the_relay_rung_of_the_rendezvous() {
        let mut params = public_params();
        params.bootstrap_relay = Some("https://relay.example/".parse().expect("relay url"));
        let at = |port: u16| {
            iroh::EndpointAddr::new(params.id).with_ip_addr(std::net::SocketAddr::from((
                std::net::Ipv4Addr::LOCALHOST,
                port,
            )))
        };
        let book = memory::MemoryLookup::new();
        crate::lookup::add_peer_addr(&book, at(4000));

        crate::lookup::replace_peer_addr(&book, holder_entry(at(5000), &params, &[]));

        let entry = book
            .get_endpoint_info(params.id)
            .expect("an entry")
            .into_endpoint_addr();
        assert!(
            entry
                .addrs
                .iter()
                .any(|addr| matches!(addr, iroh::TransportAddr::Relay(_))),
            "the relay rung that the mesh registered is gone"
        );
        let ports: Vec<u16> = entry.ip_addrs().map(std::net::SocketAddr::port).collect();
        assert_eq!(ports, vec![5000], "the address of a former holder stays");
    }

    #[test]
    fn a_public_rendezvous_is_named_at_its_relay_rung() {
        let mut params = public_params();
        params.bootstrap_relay = Some("https://relay.example/".parse().expect("relay url"));

        let addr = rendezvous_addr(&params).expect("a public rendezvous has a rung to name");

        assert_eq!(addr.id, params.id);
        assert!(
            addr.addrs
                .iter()
                .any(|addr| matches!(addr, iroh::TransportAddr::Relay(_))),
            "the probe must dial the rung the beacon homes on, not a bare id"
        );
    }

    #[test]
    fn a_private_rendezvous_is_named_at_every_ladder_rung() {
        let mut params = public_params();
        params.bind_ports = vec![4001, 4002, 4003];

        let addr = rendezvous_addr(&params).expect("a ladder is always nameable");

        let rungs = addr
            .addrs
            .iter()
            .filter(|addr| matches!(addr, iroh::TransportAddr::Ip(_)))
            .count();
        assert_eq!(
            rungs, 3,
            "iroh's node-id dial reaches whichever rung the beacon bound, so name them all"
        );
    }

    #[test]
    fn nothing_to_name_is_none_not_a_bare_id() {
        // Relay disabled and no ladder: mDNS/DHT are the only resolution
        // channel, and handing back a bare id would look like an address the
        // caller could dial when it is not one.
        let params = public_params();
        assert!(params.bootstrap_relay.is_none() && params.bind_ports.is_empty());

        assert!(rendezvous_addr(&params).is_none());
    }

    #[test]
    fn an_answered_probe_is_taken_at_its_word() {
        assert!(verdict_of(Ok(true)), "a rival answered");
        assert!(!verdict_of(Ok(false)), "nobody answered; the id is free");
        // `RecvError` cannot be constructed here, so the unanswered case is
        // covered end-to-end by `a_probe_whose_task_dies_frees_the_slot_too`.
    }

    #[test]
    async fn a_verdict_is_delivered_once_and_frees_the_slot() {
        let (tx, rx) = oneshot::channel();
        let (probe, endpoint) = probe_for(rx).await;
        let mut slot = Some(probe);
        tx.send(false).expect("verdict accepted");

        assert!(!probe_verdict(&mut slot).await, "the rendezvous is free");
        // Cleared, or the loop's arm would re-fire on the closed channel
        // forever and no later tick could ever start a fresh probe.
        assert!(slot.is_none(), "the slot is free for the next probe");
        endpoint.close().await;
    }

    #[test]
    async fn an_unanswerable_probe_reads_held_not_free() {
        // Relay disabled, no ladder, and no mDNS/DHT on the mesh: the probe
        // has no dialable address (`nothing_to_name_is_none_not_a_bare_id`
        // pins that half) and no lookup that could resolve the bare id. A
        // dial would only ever time out, and a timeout must not read as
        // "free" — claiming blind is the duplicate-beacon collision the
        // probe exists to prevent, and `gossip::recv::arms_reclaim`'s
        // widened gate leans on exactly this.
        let params = public_params();
        let mut slot = spawn_rival_probe(&params, SecretKey::generate().public()).await;
        assert!(
            slot.is_some(),
            "the probe reports a verdict, it does not vanish"
        );
        assert!(
            probe_verdict(&mut slot).await,
            "an unanswerable probe reads as held, never as free"
        );
    }

    #[test]
    async fn a_probe_whose_task_dies_frees_the_slot_too() {
        let (tx, rx) = oneshot::channel::<bool>();
        let (probe, endpoint) = probe_for(rx).await;
        let mut slot = Some(probe);
        drop(tx);

        assert!(
            probe_verdict(&mut slot).await,
            "could not tell; stay a peer"
        );
        assert!(slot.is_none(), "a dead probe must not wedge the slot");
        endpoint.close().await;
    }

    #[test]
    async fn no_probe_means_the_arm_never_fires() {
        let mut slot: Option<RivalProbe> = None;
        let pending = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            probe_verdict(&mut slot),
        )
        .await;
        assert!(pending.is_err(), "an empty slot pends instead of firing");
    }

    #[test]
    async fn shedding_a_beacon_closes_its_endpoint() {
        let endpoint = loopback_endpoint().await;
        let beacon = dead_beacon(endpoint.clone()).await;

        beacon.shed();

        settle(&endpoint).await;
        assert!(endpoint.is_closed(), "`shed` must close, not just abort");
    }

    #[test]
    async fn shed_then_resolves_when_the_endpoint_is_closed() {
        let endpoint = loopback_endpoint().await;
        let beacon = dead_beacon(endpoint.clone()).await;

        let closed = beacon.shed_then();
        assert!(!endpoint.is_closed(), "the close runs off the caller");
        closed.await.expect("the close task reports");

        assert!(
            endpoint.is_closed(),
            "the receiver resolves after the close, not before"
        );
    }

    #[test]
    async fn shed_and_wait_closes_before_it_returns() {
        let endpoint = loopback_endpoint().await;
        let beacon = dead_beacon(endpoint.clone()).await;

        beacon.shed_and_wait().await;

        // No settling: the whole point of the awaited form is that the close
        // has happened by the time the departure path moves on.
        assert!(
            endpoint.is_closed(),
            "the awaited shed must finish the close"
        );
    }

    #[test]
    async fn clearing_a_dead_beacon_closes_its_endpoint() {
        // Regression: this slot used to be cleared with `*current = None`.
        // The co-host task ending says nothing about the endpoint, so the
        // plain drop abandoned a live socket — iroh's `Endpoint dropped
        // without calling Endpoint::close`, and peers linked to a corpse
        // until the QUIC idle timeout.
        let endpoint = loopback_endpoint().await;
        let mut slot = Some(dead_beacon(endpoint.clone()).await);

        assert!(releasable(&mut slot), "a dead beacon frees the slot");
        assert!(slot.is_none(), "and is cleared out of it");

        settle(&endpoint).await;
        assert!(
            endpoint.is_closed(),
            "the dead beacon's endpoint must be closed, not dropped"
        );
    }

    #[test]
    async fn a_live_beacon_keeps_the_slot_and_its_endpoint() {
        let endpoint = loopback_endpoint().await;
        let mut slot = Some(Rendezvous {
            task: n0_future::task::spawn(std::future::pending()),
            monitor: None,
            endpoint: endpoint.clone(),
            lane: None,
            arrivals: mpsc::channel(1).1,
            released: false,
        });

        assert!(!releasable(&mut slot), "a live beacon is not releasable");
        assert!(slot.is_some(), "and is left alone");
        assert!(!endpoint.is_closed(), "its endpoint stays open");
        endpoint.close().await;
    }

    /// The peer dials its co-hosted rendezvous (its bootstrap, or a re-graft),
    /// so the rendezvous must not dial back. Two dials open two connections;
    /// iroh-gossip keeps the newer one and stops reading the older, and a
    /// `Join` or `Neighbor` already sent on the older one is lost. Only one
    /// side then lists the other as a neighbor, and the rendezvous forwards
    /// nothing to its own peer. Here the peer never dials, so any link can
    /// only be the rendezvous dialing it.
    #[test]
    async fn a_rendezvous_does_not_dial_its_own_peer() {
        use futures_util::StreamExt as _;
        use iroh_gossip::api::Event;

        let port = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free loopback port")
            .port();
        let mut params = public_params();
        params.bind_ports = vec![port];

        let peer = loopback_endpoint().await;
        let (gossip, router, _book) = crate::lookup::build_mesh(
            peer.clone(),
            tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
            None,
            None,
            Vec::new(),
            false,
            false,
        );
        let (_sender, mut receiver) = gossip
            .subscribe(params.topic_id, Vec::new())
            .await
            .expect("subscribe without a bootstrap")
            .split();

        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut probe = None;
        assert!(
            ensure(&params, &peer, &book, &mut beacon, false, &mut probe).await,
            "a free ladder rung is claimed"
        );

        let first_neighbor = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match receiver.next().await {
                    Some(Ok(Event::NeighborUp(id))) => return id,
                    Some(_) => {}
                    None => std::future::pending::<()>().await,
                }
            }
        })
        .await;

        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        let _ = router.shutdown().await;
        assert!(
            first_neighbor.is_err(),
            "the rendezvous dialed its own peer (neighbor {}); with the peer dialing it too, the pair opens two connections and one side's Join is lost",
            first_neighbor.map_or_else(|_| String::new(), |id| id.fmt_short().to_string())
        );
    }

    /// On a public mesh with no relay rung nothing names the rendezvous for a
    /// lookup to find, yet the holder's own peer is the one that must dial it
    /// (the rendezvous never dials its peer). With every lookup off, only the
    /// address the claim hands the peer lets the holder's re-graft reach it.
    #[test]
    async fn a_holder_reaches_its_own_public_rendezvous_without_lookups() {
        use futures_util::StreamExt as _;
        use iroh_gossip::api::Event;

        let params = public_params();
        let peer = loopback_endpoint().await;
        let (gossip, router, _book) = crate::lookup::build_mesh(
            peer.clone(),
            tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
            None,
            None,
            Vec::new(),
            false,
            false,
        );
        let (sender, mut receiver) = gossip
            .subscribe(params.topic_id, Vec::new())
            .await
            .expect("subscribe without a bootstrap")
            .split();

        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut probe = None;
        assert!(
            ensure(&params, &peer, &book, &mut beacon, false, &mut probe).await,
            "a public rendezvous is claimed when no probe is asked for"
        );
        sender
            .join_peers(vec![params.id])
            .await
            .expect("ask the gossip to join the rendezvous");
        let linked = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match receiver.next().await {
                    Some(Ok(Event::NeighborUp(id))) if id == params.id => return,
                    Some(_) => {}
                    None => std::future::pending::<()>().await,
                }
            }
        })
        .await
        .is_ok();

        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        let _ = router.shutdown().await;
        assert!(
            linked,
            "the holder never reached its own rendezvous: nothing registered its address, and with every lookup off nothing can resolve it"
        );
    }

    /// The holder learns who links to its beacon. The re-check of a holder that knows no member
    /// is an hour or two out, and a member that arrives is the sign that it must look sooner.
    #[test]
    async fn a_member_that_links_to_the_beacon_is_reported_to_its_holder() {
        use futures_util::StreamExt as _;
        use iroh_gossip::api::Event;

        let params = public_params();
        let peer = loopback_endpoint().await;
        let (gossip, router, _book) = crate::lookup::build_mesh(
            peer.clone(),
            tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
            None,
            None,
            Vec::new(),
            false,
            false,
        );
        let (sender, mut receiver) = gossip
            .subscribe(params.topic_id, Vec::new())
            .await
            .expect("subscribe without a bootstrap")
            .split();

        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut probe = None;
        assert!(
            ensure(&params, &peer, &book, &mut beacon, false, &mut probe).await,
            "a public rendezvous is claimed when no probe is asked for"
        );
        sender
            .join_peers(vec![params.id])
            .await
            .expect("ask the gossip to join the rendezvous");
        let linked = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match receiver.next().await {
                    Some(Ok(Event::NeighborUp(id))) if id == params.id => return,
                    Some(_) => {}
                    None => std::future::pending::<()>().await,
                }
            }
        })
        .await
        .is_ok();
        let mut arrivals = Vec::new();
        if let Some(held) = beacon.as_mut() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while arrivals.is_empty() {
                    arrivals.extend(held.take_arrivals());
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await;
        }

        if let Some(held) = beacon.take() {
            held.shed_and_wait().await;
        }
        let _ = router.shutdown().await;
        assert!(linked, "the member never linked to the beacon");
        assert!(
            arrivals.contains(&peer.id()),
            "the beacon did not report the member that linked to it"
        );
    }

    #[test]
    async fn ensure_starts_the_probe_instead_of_waiting_for_it() {
        // The invariant the departure bug came down to: `ensure` runs on the
        // sole event loop, so it must not block on the probe. It used to,
        // for the full `HEAL_PROBE` — long enough that `Node::leave`'s
        // 3s budget expired and the graceful `Left` was never sent.
        let params = public_params();
        let peer = loopback_endpoint().await;
        let book = crate::lookup::address_book(&peer);
        let mut beacon = None;
        let mut probe = None;

        let started = std::time::Instant::now();
        let claimed = ensure(&params, &peer, &book, &mut beacon, true, &mut probe).await;
        let elapsed = started.elapsed();

        // The structural assertion, not the clock, is what pins this: a call
        // that *waited* would have consumed the verdict and left the slot
        // empty. The timing bound below is only a coarse backstop — on
        // loopback the dial fails fast, so a blocking `ensure` would still
        // return quickly here.
        assert!(
            probe.is_some(),
            "ensure must leave the probe running, not await it"
        );
        assert!(
            !claimed,
            "and claim nothing on the strength of a probe it never read"
        );
        assert!(beacon.is_none(), "and stand no beacon up");
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "ensure must return without waiting out the probe, took {elapsed:?}"
        );

        // A second call must not stack a second probe answering the same
        // question at the same cost.
        let before = std::time::Instant::now();
        assert!(!ensure(&params, &peer, &book, &mut beacon, true, &mut probe).await);
        assert!(
            before.elapsed() < std::time::Duration::from_secs(1),
            "and neither must the next tick"
        );

        if let Some(probe) = probe.take() {
            probe.abort_and_close().await;
        }
        peer.close().await;
    }
}
