use iroh::Endpoint;
use iroh::address_lookup::memory;
use tokio::sync::mpsc;

use crate::lookup::{add_peer_addr, build_mesh, replace_peer_addr};
use crate::util::tuning;

use super::rung_ladder::{holder_entry, rung_of, settle_on_rung};
use super::{Held, Rendezvous, RendezvousParams, RungWatch, Walk, bind};
#[cfg(test)]
use super::{RivalProbe, walk_ladder};

use crate::{lookup, transport};
use iroh_gossip::api::Event;
use n0_future::task;
#[cfg(test)]
use n0_future::time;
#[cfg(test)]
use std::time::Duration;
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
    use crate::util::clock::Instant;
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
        if let Ok(Some(report)) =
            time::timeout(RECLAIM_WINDOW + Duration::from_secs(4), arrivals.recv()).await
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
pub(crate) async fn claim(
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
    let (endpoint, lane) =
        match bind::build_rendezvous_endpoint(params, peer, peer_book, rungs).await {
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
                transport::IceProfile { host_only: false },
            )
        }),
        // The rendezvous serves no caller protocol either — it is a meeting
        // point, not somewhere an application is reachable.
        habilis_network_iroh_transport_util::ProtocolSet::default(),
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
    let ladder: Vec<_> = lookup::relay_ladder(&params.lookups.relay_lookup).collect();
    let monitors_relay = !params.lookups.is_loopback() && !ladder.is_empty();
    let monitor_endpoint = endpoint.clone();
    let monitor_homed = params.bootstrap_relay.is_some();
    let monitor_rung_tx = params.rung_tx.clone();
    let rendezvous_endpoint = endpoint.clone();
    // A bounded channel and `try_send`: a sign that is lost to a burst is one of many.
    let (arrivals_tx, arrivals) = mpsc::channel(32);

    let task = task::spawn(async move {
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
            if let Ok(Event::NeighborUp(id)) = event {
                let _ = arrivals_tx.try_send(id);
            }
        }
    });

    // Relay liveness/discovery, off this gossip task: never stops
    // probing, backs off while relay-less. `None` when relay is disabled
    // (private / empty ladder).
    let monitor = monitors_relay.then(|| {
        lookup::spawn_relay_monitor(monitor_endpoint, ladder, monitor_rung_tx, monitor_homed)
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
