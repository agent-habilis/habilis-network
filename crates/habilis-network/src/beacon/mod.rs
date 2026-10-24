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

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};

use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey};
use iroh_gossip::proto::TopicId;
use n0_future::task::JoinHandle;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::Instrument as _;

use crate::lookup::{
    ProbeAnswer, TransportHandles, add_peer_addr, build_endpoint, build_mesh, probe_answer,
    probe_connect, replace_peer_addr,
};
use crate::protocol::mesh::{LookupOpts, RelayChoice};
use crate::util::clock::Instant;
use crate::util::tuning::{
    HEAL_PROBE, RECLAIM_WINDOW, RENDEZVOUS_CLOSE, RENDEZVOUS_PROBE, heal_interval,
};

/// Everything [`ensure`] needs to (re)build the rendezvous endpoint.
/// Cheap to clone-hold for the event loop's lifetime.
#[derive(Debug)]
pub(crate) struct RendezvousParams {
    pub(crate) topic_id: TopicId,
    /// `rendezvous_secret(seed)` — the shared identity every co-host binds.
    pub(crate) secret: SecretKey,
    /// Empty when the mesh has lookups (ephemeral, address-lookup
    /// discoverable). Non-empty for a loopback-only mesh: the
    /// deterministic loopback port *ladder* in preference order. The
    /// beacon binds the first free rung; an independent mesh squatting a
    /// rung (seed collision) is skipped instead of mistaken for our own
    /// beacon.
    pub(crate) bind_ports: Vec<u16>,
    /// `rendezvous_id`, memoized for neighbor filtering / bootstrap seeding.
    pub(crate) id: EndpointId,
    /// The peer's resolved lookup config. The beacon
    /// endpoint must publish `rendezvous_id` to the *same*
    /// address-lookups (or a joiner using only mDNS/DHT could never
    /// resolve it) — see `beacon_lookups`.
    pub(crate) lookups: LookupOpts,
    /// The mesh's `transport.relay_transport`. With it off, the beacon holds every
    /// inbound gossip connection — a joiner's first link — until iroh selects
    /// a direct path on it, so no frame ever crosses the relay.
    pub(crate) relay_transport: bool,
    /// The single relay **rung** the beacon homes on — initialized to
    /// the first ladder rung (optimistic, unprobed) at setup and
    /// corrected off the event loop: a backgrounded startup probe and
    /// the beacon's own liveness self-monitor publish a new rung through
    /// [`Self::rung_tx`], which the event loop applies back here. The
    /// joiner pre-registers `rendezvous_id` at this exact rung
    /// (`daemon::setup::register_rendezvous`), so the beacon must home
    /// here or that relay-direct dial finds nothing. `None` ⇒ no
    /// reachable relay (private mode, relay disabled, or every rung
    /// down) — joiners fall back to mDNS/DHT.
    pub(crate) bootstrap_relay: Option<RelayUrl>,
    /// How the off-loop rung selectors (the backgrounded startup probe
    /// and the beacon co-host's liveness self-monitor) publish a freshly
    /// chosen rung. The event loop holds the matching receiver and, on a
    /// change, updates [`Self::bootstrap_relay`], re-registers the
    /// rendezvous, and re-homes the beacon — so the heavy ladder walk
    /// never runs on the sole event loop.
    pub(crate) rung_tx: watch::Sender<Option<RelayUrl>>,
}

impl RendezvousParams {
    /// Whether the beacon answers JSEP: only a public one carries a `WebRTC`
    /// transport, and a private ladder rendezvous never does.
    pub(crate) fn answers_jsep(&self) -> bool {
        self.bind_ports.is_empty()
    }
}

/// A live co-hosted rendezvous endpoint. Dropping it aborts both tasks,
/// releasing the endpoint + router (and, private, freeing the
/// deterministic port for the next member to claim).
pub(crate) struct Rendezvous {
    /// The gossip co-host: subscribes, bridges the rendezvous into the
    /// mesh, and re-asserts the peer link each heal tick.
    task: JoinHandle<()>,
    /// The relay-rung liveness/discovery monitor (`spawn_relay_monitor`).
    /// `None` for private / relay-disabled meshes (nothing to monitor).
    monitor: Option<crate::lookup::StoppableTask>,
    /// The co-hosted endpoint itself, retained so [`Self::shed`] and
    /// [`Self::shed_and_wait`] can close it gracefully — a plain drop (task
    /// abort) skips the orderly QUIC close, and the peer's link to its own
    /// dead beacon lingers as a zombie until the idle timeout, stalling the
    /// post-shed re-graft.
    endpoint: Endpoint,
    /// The beacon's own `WebRTC` answerer: the handle a tab's session to the
    /// rendezvous attaches to, and the admission its negotiations hold a
    /// slot in. The peer endpoint has its own pair, which says nothing about
    /// who depends on the beacon. `None` where the beacon carries no lane.
    lane: RendezvousLane,
    /// The members that linked to this beacon, as its gossip task saw them come up. The holder
    /// reads them: a member that it does not know is a sign that another group may exist.
    arrivals: mpsc::Receiver<EndpointId>,
    /// Set by the release paths, which close the endpoint themselves. A drop with it unset is a
    /// beacon that nobody released, and closes the endpoint on its own.
    released: bool,
}

/// A beacon's `WebRTC` answerer and the table that admits its sessions.
type RendezvousLane = Option<(
    habilis_network_iroh_webrtc_transport::WebRtcHandle,
    crate::transport::SignalAdmission,
)>;

/// The sessions in `live` whose remote is none of `own`. A member's own endpoints
/// attach to its beacon's answerer as well, and no other peer hangs off the beacon
/// through them: counted, they made each split holder defer its shed for the full wait.
fn foreign_sessions(live: &[EndpointId], own: &[EndpointId]) -> Vec<EndpointId> {
    live.iter()
        .copied()
        .filter(|id| !own.contains(id))
        .collect()
}

/// Who hangs off a beacon's data channel: the sessions on its answerer, the endpoints that
/// are ours, and the number of rounds still negotiating a session.
#[derive(Debug, Default)]
pub(crate) struct Dependents {
    live: Vec<EndpointId>,
    own: Vec<EndpointId>,
    pub(crate) in_flight: usize,
}

impl Dependents {
    pub(crate) fn count(&self) -> usize {
        foreign_sessions(&self.live, &self.own).len() + self.in_flight
    }

    pub(crate) fn foreign_ids(&self) -> Vec<String> {
        short_ids(&foreign_sessions(&self.live, &self.own))
    }

    pub(crate) fn live_ids(&self) -> Vec<String> {
        short_ids(&self.live)
    }

    pub(crate) fn own_ids(&self) -> Vec<String> {
        short_ids(&self.own)
    }
}

fn short_ids(ids: &[EndpointId]) -> Vec<String> {
    ids.iter().map(|id| id.fmt_short().to_string()).collect()
}

impl Rendezvous {
    /// How many peers depend on this beacon's data channel: sessions attached
    /// to its answerer, plus rounds still negotiating one. `peer` is our own
    /// member endpoint. `in_flight` does not name its peers, so a round counts
    /// whoever it is with.
    pub(crate) fn dependents(&self, peer: EndpointId) -> Dependents {
        self.lane
            .as_ref()
            .map_or_else(Dependents::default, |(handle, admission)| Dependents {
                live: handle.live_peer_ids(),
                own: vec![peer, self.endpoint.id()],
                in_flight: admission.in_flight(),
            })
    }

    /// The index of the rung in `ladder` that this beacon is bound on: `0` is the first rung that a
    /// joiner tries. `None` when it is bound on none of them (a public beacon).
    pub(crate) fn rung_in(&self, ladder: &[u16]) -> Option<usize> {
        rung_of(&self.endpoint, ladder)
    }

    /// Tests only: make this beacon stop answering and keep its rung. The endpoint stays bound and
    /// the co-host task stays alive, as a stopped process or a wedged accept loop leaves them;
    /// no connection of the gossip ALPN is taken any more.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) fn stall(&self) {
        self.endpoint.set_alpns(Vec::new());
    }

    /// The members that linked to this beacon since the last call.
    pub(crate) fn take_arrivals(&mut self) -> Vec<EndpointId> {
        let mut arrived = Vec::new();
        while let Ok(id) = self.arrivals.try_recv() {
            arrived.push(id);
        }
        arrived
    }

    /// A beacon holding `endpoint` whose answerer is `lane`, for a test that
    /// needs a held beacon without a claim.
    #[cfg(test)]
    pub(crate) fn for_test(endpoint: Endpoint, lane: RendezvousLane) -> Self {
        Self {
            task: n0_future::task::spawn(std::future::pending()),
            monitor: None,
            endpoint,
            lane,
            arrivals: mpsc::channel(1).1,
            released: false,
        }
    }

    /// Release the beacon *gracefully*: abort the tasks, then close the
    /// endpoint off-loop so every peer holding a link to it (including our
    /// own peer) sees an immediate `NeighborDown` instead of a
    /// zombie link that only dies at the QUIC idle timeout.
    pub(crate) fn shed(self) {
        drop(self.shed_then());
    }

    /// [`Self::shed`], and a receiver that resolves when the close of the endpoint is done. The
    /// event loop waits on it to re-probe the id at once: the wait that the reclaim tick used to
    /// give is the close, and the close is an event, not a time.
    pub(crate) fn shed_then(mut self) -> oneshot::Receiver<()> {
        self.released = true;
        let endpoint = self.endpoint.clone();
        let (done, closed) = oneshot::channel();
        let shed_at = Instant::now();
        n0_future::task::spawn(async move {
            endpoint.close().await;
            tracing::debug!(
                target: "habilis_network::beacon",
                age_ms = u64::try_from(shed_at.elapsed().as_millis()).unwrap_or(u64::MAX),
                "beacon closed"
            );
            // The last handle of the endpoint goes before the event does, so that whoever waits sees
            // the id free of it.
            drop(endpoint);
            let _ = done.send(());
        });
        // `self` drops here, aborting the co-host task and stopping the monitor.
        closed
    }

    /// The same graceful release, *awaited* — for the event loop's teardown.
    ///
    /// [`Self::shed`] hands the close to a spawned task, which is right
    /// mid-run and useless on the way out: the runtime is about to go away, so
    /// a detached close is never polled and the endpoint reaches its `Drop`
    /// still open. iroh says so — `Endpoint dropped without calling
    /// Endpoint::close. Aborting ungracefully.` — on every departure of every
    /// co-hosting member, which is all of them.
    ///
    /// Bounded, because winding down must not hang on a relay that stopped
    /// answering. See `RENDEZVOUS_CLOSE`. Past the bound we are no worse
    /// off than before this existed.
    ///
    /// The monitor is stopped and waited for in the same budget, not aborted:
    /// mid re-walk it holds a probe endpoint of its own, which an abort drops
    /// open.
    pub(crate) async fn shed_and_wait(mut self) {
        let endpoint = self.endpoint.clone();
        let monitor = self.monitor.take();
        self.released = true;
        // Abort the co-host task first, so it is not still driving the
        // endpoint while it closes.
        drop(self);
        tokio::join!(
            async {
                if n0_future::time::timeout(RENDEZVOUS_CLOSE, endpoint.close())
                    .await
                    .is_err()
                {
                    tracing::debug!(target: "habilis_network::beacon", "rendezvous endpoint close timed out; abandoning it");
                }
            },
            async {
                if let Some(monitor) = monitor {
                    monitor.stop_and_wait().await;
                }
            },
        );
    }
}

/// Aborts the co-host task and stops the monitor (dropping it signals the
/// stop, and the monitor then closes any probe endpoint of its own). A beacon
/// that was not released through [`Rendezvous::shed`] or
/// [`Rendezvous::shed_and_wait`] hands its endpoint to a detached close, because
/// closing is async and `Drop` is not.
///
/// A drop is what a crash leaves, when the daemon task is aborted with the
/// beacon in its slot. Without the close, iroh logs `Endpoint dropped without
/// calling Endpoint::close. Aborting ungracefully.` and every peer linked to
/// that beacon waits out the QUIC idle timeout instead of seeing a
/// `NeighborDown`. The close runs only where a runtime is there to run it. The
/// release sites stay the way to wait for the close.
impl Drop for Rendezvous {
    fn drop(&mut self) {
        self.task.abort();
        if !self.released {
            close_detached(self.endpoint.clone());
        }
    }
}

/// Close `endpoint` on a task of its own, for a `Drop` that cannot wait. Outside a runtime there
/// is nothing to run the close, and the endpoint is dropped as before.
fn close_detached(endpoint: Endpoint) {
    #[cfg(not(target_arch = "wasm32"))]
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    drop(n0_future::task::spawn(async move {
        endpoint.close().await;
    }));
}

/// The rendezvous's **dialable** address: the id plus somewhere to reach it.
///
/// One construction, two callers that must not drift — the hint a joiner
/// pre-registers on its peer endpoint (`daemon::setup::register_rendezvous`)
/// and the target [`spawn_rival_probe`] dials. They are the same address by
/// definition: the probe asks "is anyone serving the identity a joiner would
/// reach?", so asking it anywhere else answers a different question.
///
/// - Private (a non-empty ladder): every loopback rung, because iroh's
///   node-id dial reaches whichever rung our beacon actually bound.
/// - Public: `bootstrap_relay`, the single rung the beacon homes on
///   ([`beacon_lookups`]) — a relay-direct dial with no lookup round-trip.
/// - `None`: relay disabled and no ladder, so there is nothing to name and
///   only mDNS/DHT can resolve the id.
pub(crate) fn rendezvous_addr(params: &RendezvousParams) -> Option<EndpointAddr> {
    let mut addr = EndpointAddr::new(params.id);
    if !params.bind_ports.is_empty() {
        for &port in &params.bind_ports {
            addr = addr.with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }
        return Some(addr);
    }
    Some(addr.with_relay_url(params.bootstrap_relay.clone()?))
}

/// [`rendezvous_addr`] without the rungs of `withheld`: the address that a member registers for the
/// rendezvous id while those rungs are busy and not read as ours ([`RungWatch::withheld_rungs`]).
pub(crate) fn rendezvous_addr_without(
    params: &RendezvousParams,
    withheld: &[u16],
) -> Option<EndpointAddr> {
    rendezvous_addr(params).map(|addr| keeping_rungs(addr, |port| !withheld.contains(&port)))
}

/// The rendezvous id at one rung of the loopback ladder.
fn rendezvous_holder_addr(params: &RendezvousParams, port: u16) -> EndpointAddr {
    EndpointAddr::new(params.id).with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}

/// `addr` without the IP addresses whose port `keep` refuses. An address of another kind stays.
fn keeping_rungs(addr: EndpointAddr, keep: impl Fn(u16) -> bool) -> EndpointAddr {
    EndpointAddr::from_parts(
        addr.id,
        addr.addrs.into_iter().filter(|transport| {
            if let iroh::TransportAddr::Ip(socket) = transport {
                keep(socket.port())
            } else {
                true
            }
        }),
    )
}

/// The index in `ladder` of the rung that `endpoint` is bound on, `None` when it is bound on none of
/// them.
fn rung_of(endpoint: &Endpoint, ladder: &[u16]) -> Option<usize> {
    // A browser binds no socket, so it holds no rung of a loopback ladder.
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (endpoint, ladder);
        None
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let bound: Vec<u16> = endpoint
            .bound_sockets()
            .iter()
            .map(SocketAddr::port)
            .collect();
        ladder.iter().position(|port| bound.contains(port))
    }
}

/// Take the rungs that `forget` names out of the addresses of the rendezvous id: out of the book,
/// and out of what the endpoint knows. A dial of the id tries every address that the endpoint
/// knows for it, and a listener of another identity on one of them (any process on the host can
/// hold a rung) answers with its own identity, or with an alert for an ALPN that it does not
/// serve, and the dial fails as a whole, on every retry.
async fn forget_rungs(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
    forget: impl Fn(u16) -> bool,
) {
    let forgotten = params
        .bind_ports
        .iter()
        .copied()
        .filter(|&port| forget(port))
        .fold(EndpointAddr::new(params.id), |addr, port| {
            addr.with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        });
    if forgotten.addrs.is_empty() {
        return;
    }
    if let Some(info) = peer_book.get_endpoint_info(params.id) {
        replace_peer_addr(
            peer_book,
            keeping_rungs(info.into_endpoint_addr(), |port| !forget(port)),
        );
    }
    peer.remove_endpoint_addr(forgotten).await;
}

/// The rungs of the ladder that somebody holds, read by a bind that fails: instant, no probe. A
/// member that starts does not know yet whether the holder is our beacon, so it keeps these out of
/// the book until a probe answers.
pub(crate) fn busy_rungs(params: &RendezvousParams) -> Vec<u16> {
    params
        .bind_ports
        .iter()
        .copied()
        .filter(|&port| rung_is_busy(port))
        .collect()
}

/// Put the rung `port` back among the addresses of the rendezvous id, when a probe said nothing
/// of it and the book does not name it yet: a host too loaded to answer holds our beacon on it
/// all the same. The endpoint is told too, as in [`settle_on_rung`].
async fn admit_rung(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
    port: u16,
) {
    let held = peer_book
        .get_endpoint_info(params.id)
        .is_some_and(|info| info.ip_addrs().any(|socket| socket.port() == port));
    if held {
        return;
    }
    let holder = rendezvous_holder_addr(params, port);
    add_peer_addr(peer_book, holder.clone());
    if let Err(error) = peer.add_endpoint_addr(holder).await {
        tracing::debug!(target: "habilis_network::beacon", %error, port, "the endpoint did not take the rung");
    }
}

/// The rung `port` serves our beacon: the endpoint reaches the rendezvous id there and nowhere else
/// on the ladder, and the book names that rung. The endpoint is told too, because it does not read
/// the book again for an id that it knows.
async fn settle_on_rung(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
    port: u16,
) {
    forget_rungs(params, peer, peer_book, |rung| rung != port).await;
    let holder = rendezvous_holder_addr(params, port);
    add_peer_addr(peer_book, holder.clone());
    if let Err(error) = peer.add_endpoint_addr(holder).await {
        tracing::debug!(target: "habilis_network::beacon", %error, port, "the endpoint did not take the rung of the holder");
    }
}

/// Read the ladder without claiming a rung: a member that knows a holder skips the walk, and the
/// rung of the holder that it read last may be dead or foreign when the holder moved (it shed or
/// yielded, and another member claimed a rung). The busy rungs are asked, the reports land on the
/// loop, which calls this again, and the rung that reads as ours is settled on.
pub(crate) async fn refresh_holder_rung(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
    rungs: &mut RungWatch,
) {
    let now = Instant::now();
    for &port in &params.bind_ports {
        match rungs.reading(port, now) {
            RungRead::Ours => {
                rungs.clear_foreign(port);
                settle_on_rung(params, peer, peer_book, port).await;
                return;
            }
            RungRead::Unknown if rung_is_busy(port) => {
                rungs.ask(params, peer.id(), port, false);
            }
            RungRead::Unknown
            | RungRead::Foreign
            | RungRead::Silent
            | RungRead::SilentLongEnough => {}
        }
    }
}

/// The entry of the rendezvous id in the book of the member endpoint after a claim: the direct
/// addresses of the new holder, and what the mesh registered for the id by itself, a relay rung or
/// the loopback ladder ([`rendezvous_addr`]). The addresses of a former holder are not in it. A
/// member whose IP transports are cleared dials the bare id and can use only the registered part.
/// A claim on a ladder does not write this entry: it settles on the rung that the beacon bound.
fn holder_entry(holder: EndpointAddr, params: &RendezvousParams, withheld: &[u16]) -> EndpointAddr {
    match rendezvous_addr_without(params, withheld) {
        Some(registered) => {
            EndpointAddr::from_parts(holder.id, holder.addrs.into_iter().chain(registered.addrs))
        }
        None => holder,
    }
}

/// A public probe-before-claim running **off** the event loop.
///
/// The probe answers one question — does a beacon already serve this
/// rendezvous? — and it answers it slowly: a free rendezvous is only
/// provably free once the dial has exhausted its budget, so the common
/// "nobody is home, claim it" case costs the full [`HEAL_PROBE`].
/// Paid inline that was ~5s per heal tick during which the sole event loop
/// polled nothing at all: no gossip, no IPC, and — the reason this exists —
/// no quit. A departure landing in that window missed `Node::leave`'s
/// budget entirely, the caller tore the endpoint down underneath the
/// still-running loop, and the graceful `Left` never went out.
///
/// So the probe rides its own task and publishes its verdict through a
/// channel the loop selects on, exactly as the relay-rung walk does
/// through [`RendezvousParams::rung_tx`]. What stays on the loop is only
/// the bind, which is milliseconds.
pub(crate) struct RivalProbe {
    /// The verdict: `true` ⇒ a beacon already answers, stay a peer.
    /// A dropped sender (the task died) reads as `true` — see
    /// [`probe_verdict`].
    rx: oneshot::Receiver<bool>,
    task: JoinHandle<()>,
    /// The throwaway prober endpoint, retained for the same reason
    /// [`Rendezvous`] retains its own: aborting the task drops the endpoint
    /// open, and iroh tears an unclosed endpoint down ungracefully. The
    /// task closes it on the happy path; this is for the departure that
    /// cancels it first. `None` when the probe never dialed — an
    /// unanswerable target pre-resolves the verdict without an endpoint.
    endpoint: Option<Endpoint>,
    /// Tells the task to stop dialing and go straight to its own close.
    /// `None` when there is no dial to stop.
    cancel: Option<oneshot::Sender<()>>,
}

impl RivalProbe {
    /// Stop the probe and wait for its endpoint to close gracefully — the
    /// departure counterpart to letting the task finish, and the same bounded
    /// shape as [`Rendezvous::shed_and_wait`] for the same reason.
    ///
    /// The task closes its own endpoint, so this cancels the dial and waits for
    /// the task rather than aborting it. An abort could land while the task is
    /// already inside `close()`, which cuts that close short, and a second
    /// `close()` returns at once while one is in flight, so nothing would
    /// finish it.
    pub(crate) async fn abort_and_close(mut self) {
        if self.endpoint.is_none() {
            // Never dialed, nothing to close.
            return;
        }
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if n0_future::time::timeout(RENDEZVOUS_CLOSE, &mut self.task)
            .await
            .is_err()
        {
            tracing::debug!(target: "habilis_network::beacon", "rival-probe endpoint close timed out; abandoning it");
        }
    }
}

/// A drop that no one asked to close (the daemon task was aborted, as a crash does) cancels the
/// dial and leaves the task to run its own close. An abort would drop the last handle of the
/// prober open. A probe with no dial to cancel has no endpoint, so its task is aborted.
impl Drop for RivalProbe {
    fn drop(&mut self) {
        match self.cancel.take() {
            Some(_cancel) => {}
            None => self.task.abort(),
        }
    }
}

/// Await the outstanding rival probe's verdict, or pend forever when none
/// is running — the [`recv_opt`] shape, so the event loop can give this its
/// own `select!` arm.
///
/// Consumes the probe: one verdict per probe, and clearing the slot is what
/// lets the next tick start a fresh one. A dropped sender (the task was
/// aborted, or panicked) reads as "a rival is there": we could not tell, and
/// claiming blind is the one outcome the probe exists to prevent.
///
/// [`recv_opt`]: crate::daemon::event_loop
pub(crate) async fn probe_verdict(probe: &mut Option<RivalProbe>) -> bool {
    let Some(active) = probe.as_mut() else {
        return std::future::pending().await;
    };
    // `&mut Receiver` so a losing `select!` arm drops this future without
    // dropping the receiver — the verdict survives to the next poll.
    let found_rival = verdict_of((&mut active.rx).await);
    *probe = None;
    found_rival
}

/// Read a probe task's outcome. A dropped sender — the task was aborted, or
/// panicked — means we never learned the answer, and "a rival is there" is
/// the safe reading: claiming blind is the duplicate-id collision the probe
/// exists to prevent, while a needless extra tick costs one heal interval.
fn verdict_of(result: Result<bool, oneshot::error::RecvError>) -> bool {
    result.unwrap_or(true)
}

/// Start the probe-before-claim on its own task.
///
/// The prober dials from a **throwaway endpoint**, not the member's `peer`:
/// an ex-holder re-probing after a rival re-check shed carries stale
/// per-id connection state for the shared `rendezvous_id` (the link to its
/// own just-dropped beacon — the reused-endpoint-id pathology of
/// iroh-gossip#10), and a dial from it joins that dead state and times out
/// even while the rival's live addresses sit in the address book. A fresh
/// endpoint has no history to get stuck on.
///
/// Which is exactly why it must be handed [`rendezvous_addr`] rather than a
/// bare id. A throwaway endpoint has no address book, and nothing else will
/// fill the gap: endpoints are built on `presets::Minimal`, which wires **no
/// N0 pkarr/DNS** on purpose (see `lookup::build_endpoint`), and mDNS/DHT are
/// `host`-only. So a bare `EndpointAddr::new(id)` is unresolvable in a browser
/// and in any relay-only mesh — the dial times out, the verdict reads "free",
/// and every surviving member claims a duplicate same-id beacon that captures
/// its own bootstrap dial. Probe-before-claim was a no-op exactly where it
/// mattered most; naming the address is what makes it answer its question.
///
/// When there is nothing to name *and* no lookup that could resolve the bare
/// id, the probe cannot answer its question at all, so it does not dial: it
/// pre-resolves the verdict to "held". `gossip::recv::arms_reclaim`'s widened
/// gate leans on the probe never reading "free" blind, and this branch is
/// what makes that structural rather than configurational.
///
/// The endpoint is built here, on the loop, rather than inside the task:
/// it costs milliseconds, and holding it lets a departure close it (see
/// [`RivalProbe::abort_and_close`]). `None` ⇒ the build failed, so we
/// cannot tell and must not claim blind; the next tick retries.
async fn spawn_rival_probe(params: &RendezvousParams, node: EndpointId) -> Option<RivalProbe> {
    let target = match rendezvous_addr(params) {
        Some(addr) => addr,
        // Nothing to name (relay disabled, no ladder). The bare id is a
        // dialable target only while a lookup can resolve it — mDNS/DHT,
        // when the mesh carries them and this build wires them.
        None if bare_id_resolvable(&params.lookups) => EndpointAddr::new(params.id),
        None => {
            tracing::info!(target: "habilis_network::beacon", node = %node.fmt_short(),
                "rival probe has nothing to dial and no lookup to resolve the id; reading the rendezvous as held");
            let (tx, rx) = oneshot::channel();
            // The receiver is held below; this send cannot fail.
            let _ = tx.send(true);
            return Some(RivalProbe {
                rx,
                task: n0_future::task::spawn(async {}),
                endpoint: None,
                cancel: None,
            });
        }
    };
    let lookups = beacon_lookups(params);
    let prober = match build_endpoint(
        &lookups,
        None,
        None,
        Vec::new(),
        TransportHandles::default(),
    )
    .await
    {
        Ok(prober) => prober,
        Err(error) => {
            tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), %error, "rival probe endpoint build failed; next tick retries");
            return None;
        }
    };
    tracing::debug!(target: "habilis_network::beacon", node = %node.fmt_short(), "rival probe endpoint built");
    // Clamped so at most one probe is outstanding per heal tick even when
    // tests shorten the cadence below the probe cap.
    let budget = HEAL_PROBE.min(heal_interval());
    let (tx, rx) = oneshot::channel();
    let endpoint = prober.clone();
    let (cancel, cancelled) = oneshot::channel();
    // The span names the member that probes, so the `connect-probe finished` line of `lookup`,
    // which knows only the throwaway prober, carries it too.
    let probe_span = tracing::info_span!(
        target: "habilis_network::beacon",
        "rival_probe",
        node = %node.fmt_short()
    );
    let task = n0_future::task::spawn(
        async move {
            let found_rival = tokio::select! {
                found = probe_connect(&prober, target, budget) => found,
                // A departure: no one will read the verdict, but the endpoint
                // must still close below.
                _ = cancelled => true,
            };
            prober.close().await;
            // A closed receiver means the loop moved on (departure, or the
            // beacon arrived another way); the verdict is simply stale.
            let _ = tx.send(found_rival);
        }
        .instrument(probe_span),
    );
    Some(RivalProbe {
        rx,
        task,
        endpoint: Some(endpoint),
        cancel: Some(cancel),
    })
}

/// Whether this build can resolve a bare endpoint id under `lookups` — the
/// only condition a probe may dial one. mDNS and DHT are compile-time
/// features and `host`-only, so a browser or a feature-trimmed build
/// resolves nothing regardless of what the mesh id asks for.
fn bare_id_resolvable(lookups: &LookupOpts) -> bool {
    (cfg!(all(feature = "host", feature = "mdns")) && lookups.mdns)
        || (cfg!(all(feature = "host", feature = "dht")) && lookups.dht)
}

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
fn rung_probes_are_blind(member: EndpointId) -> bool {
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
fn rung_is_busy(port: u16) -> bool {
    std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_err()
}

/// What a busy rung said when it was last asked.
#[derive(Clone, Copy, Debug)]
struct RungReading {
    answer: ProbeAnswer,
    read_at: Instant,
    /// Since when the rung has said nothing, and not answered since. Kept across probes: a rung
    /// that stays silent is bound once it has been silent for the whole reclaim window.
    silent_since: Option<Instant>,
    /// The ask that this reading answers.
    generation: u64,
}

/// A probe task that is out for a rung, and since when.
#[derive(Clone, Copy, Debug)]
struct InFlight {
    generation: u64,
    since: Instant,
}

/// What a probe task found out about one rung. The event loop notes it in its [`RungWatch`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct RungReport {
    port: u16,
    answer: ProbeAnswer,
    /// Which ask of the rung this answers: a task that was given up can still report, and its
    /// report is not the answer that the loop waits for.
    generation: u64,
}

/// How a walk reads a rung that is bound by somebody else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RungRead {
    /// It answered as the beacon of our own mesh.
    Ours,
    /// It answered, and was not ours.
    Foreign,
    /// It has said nothing for the whole reclaim window: read as foreign.
    SilentLongEnough,
    /// It said nothing, and not for long enough yet: the walk waits.
    Silent,
    /// No fresh reading: somebody has to ask.
    Unknown,
}

/// What the event loop knows of the busy rungs of a private ladder, and the probe tasks that find
/// out more.
///
/// The ladder walk is instant: it binds a free rung, reads what is here, and asks for what it does
/// not know by spawning a probe task, as the public path does with `spawn_rival_probe`. It never
/// waits for a rung. The report of a probe task arrives on the loop, which notes it here and walks
/// again at once. A reading is fresh for one heal tick; a silent rung keeps the time it was first
/// read silent until it answers.
#[derive(Debug)]
pub(crate) struct RungWatch {
    readings: BTreeMap<u16, RungReading>,
    /// The rungs that a probe task is out for, and since when. A task that has not reported for
    /// longer than one heal tick is dead (the loop that would have noted it, or the runtime, is
    /// gone) and the rung is asked again.
    in_flight: BTreeMap<u16, InFlight>,
    /// The generation of the next ask. A report of an ask that is no longer the one in flight, or
    /// that is older than the stored reading or than the last clear, is ignored.
    next_generation: u64,
    /// The asks below this generation were made before the last clear of the readings.
    generation_floor: u64,
    /// How many consecutive checks of our own rung did not answer as ours, and the reading that
    /// was counted last, so that one reading is one check however often a tick reads it.
    own_misses: u32,
    own_counted: Option<Instant>,
    /// The rungs that the walk read as held by a foreign listener, and has not read as ours since.
    /// A reading expires after a heal tick, this does not: the book must not take such a rung
    /// back each time the rendezvous is registered again.
    foreign: std::collections::BTreeSet<u16>,
    /// The rungs whose last probe was answered and ended without an identity: a refusal, a close,
    /// an alert that is not about the key. A busy, closing or starting beacon of our own mesh does
    /// that, and so does a listener of another program, so the answer cannot tell them apart. A
    /// dial of the rendezvous id tries every address of the id, and such a listener fails the dial
    /// as a whole, so the rung stays out of the book until it answers as ours. Silence is not
    /// here: a host too loaded to answer reads the same, and its beacon is found by the dial.
    refused: std::collections::BTreeSet<u16>,
    reports: mpsc::UnboundedSender<RungReport>,
    /// The probe tasks that are out. A task reports before it closes its prober, so the loop that
    /// ends has to wait for them: [`Self::finish`].
    tasks: Vec<JoinHandle<()>>,
}

impl RungWatch {
    pub(crate) fn new(reports: mpsc::UnboundedSender<RungReport>) -> Self {
        Self {
            readings: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            next_generation: 1,
            generation_floor: 0,
            own_misses: 0,
            own_counted: None,
            foreign: std::collections::BTreeSet::new(),
            refused: std::collections::BTreeSet::new(),
            reports,
            tasks: Vec::new(),
        }
    }

    /// A watch whose reports go nowhere: for a state that no loop drives.
    pub(crate) fn detached() -> Self {
        Self::new(mpsc::unbounded_channel().0)
    }

    /// The walk read `port` as serving our beacon.
    fn clear_foreign(&mut self, port: u16) {
        self.foreign.remove(&port);
        self.refused.remove(&port);
    }

    /// The walk read `port` as held by a foreign listener.
    fn mark_foreign(&mut self, port: u16) {
        self.foreign.insert(port);
    }

    /// The rungs that stay out of the book: those that the walk read as held by a foreign listener,
    /// and those that answered the last probe without an identity ([`Self::refused`]).
    pub(crate) fn withheld_rungs(&self) -> Vec<u16> {
        self.foreign.union(&self.refused).copied().collect()
    }

    /// Whether the last probe of `port` was answered without an identity.
    fn refused(&self, port: u16) -> bool {
        self.refused.contains(&port)
    }

    /// Whether a probe task is out, and not dead.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> bool {
        let now = Instant::now();
        self.in_flight
            .values()
            .any(|probe| Self::alive(probe.since, now))
    }

    /// Whether a probe that was asked at `since` is still waited for. After one heal tick it is
    /// given up: the task, or the loop that would note its report, is gone.
    fn alive(since: Instant, now: Instant) -> bool {
        now.saturating_duration_since(since) < heal_interval()
    }

    /// Note what a probe task found.
    ///
    /// A probe that was given up can still report. Its report is ignored when the rung was asked
    /// again since, when a newer ask has been noted, and when the readings were cleared after the
    /// ask: it would end the wait for the probe in flight and put an old answer in as fresh.
    pub(crate) fn note(&mut self, report: RungReport, now: Instant) {
        match self.in_flight.get(&report.port) {
            Some(probe) if probe.generation != report.generation => return,
            Some(_) => {
                self.in_flight.remove(&report.port);
            }
            None => {}
        }
        if report.generation < self.generation_floor
            || self
                .readings
                .get(&report.port)
                .is_some_and(|stored| report.generation < stored.generation)
        {
            return;
        }
        let gap = heal_interval().saturating_mul(3);
        let silent_since = match report.answer {
            ProbeAnswer::NoAnswer | ProbeAnswer::Refused => Some(
                self.readings
                    .get(&report.port)
                    .filter(|before| now.saturating_duration_since(before.read_at) < gap)
                    .and_then(|before| before.silent_since)
                    .unwrap_or(now),
            ),
            ProbeAnswer::Ours | ProbeAnswer::Foreign => None,
        };
        if report.answer == ProbeAnswer::Refused {
            self.refused.insert(report.port);
        } else {
            self.refused.remove(&report.port);
        }
        self.readings.insert(
            report.port,
            RungReading {
                answer: report.answer,
                read_at: now,
                silent_since,
                generation: report.generation,
            },
        );
    }

    /// Forget every reading: the ladder is ours now. The asks made so far are over, and the late
    /// report of one of them is ignored.
    fn forget(&mut self) {
        self.readings.clear();
        self.refused.clear();
        self.generation_floor = self.next_generation;
        self.own_misses = 0;
        self.own_counted = None;
    }

    /// Whether the holder of the beacon on `own_port` should shed it: its own rung did not answer
    /// as ours at two consecutive checks, and never at one, so that a busy moment does not take a
    /// healthy beacon from the members that joined through it. A check is a probe task dialing
    /// the rung from a throwaway endpoint, one attempt, never blind; a reading that says ours
    /// resets the count.
    ///
    /// What it does not see: a beacon whose endpoint answers while its gossip is wedged.
    pub(crate) fn own_rung_failed(
        &mut self,
        params: &RendezvousParams,
        node: EndpointId,
        own_port: u16,
    ) -> bool {
        match self.reading(own_port, Instant::now()) {
            RungRead::Ours => {
                self.own_misses = 0;
                self.own_counted = None;
                false
            }
            RungRead::Unknown => {
                self.ask(params, node, own_port, false);
                false
            }
            RungRead::Foreign | RungRead::SilentLongEnough | RungRead::Silent => {
                let read_at = self.readings.get(&own_port).map(|reading| reading.read_at);
                if read_at != self.own_counted {
                    self.own_misses = self.own_misses.saturating_add(1);
                    self.own_counted = read_at;
                }
                self.own_misses >= 2
            }
        }
    }

    /// The count of the checks of our own rung is over: the beacon was shed.
    pub(crate) fn own_check_done(&mut self) {
        self.own_misses = 0;
        self.own_counted = None;
    }

    /// Tests only: every probe task that is out has been out for longer than a heal tick, as when
    /// one has passed: the task is given up and the rung is asked again.
    #[cfg(all(test, feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) fn expire_probes_in_flight(&mut self) {
        let long_ago = heal_interval().saturating_mul(2);
        for probe in self.in_flight.values_mut() {
            probe.since = probe.since.checked_sub(long_ago).unwrap_or(probe.since);
        }
    }

    /// Tests only: every reading is older than a heal tick, as when one has passed.
    #[cfg(test)]
    pub(crate) fn expire_readings(&mut self) {
        let long_ago = heal_interval().saturating_mul(2);
        for reading in self.readings.values_mut() {
            reading.read_at = reading
                .read_at
                .checked_sub(long_ago)
                .unwrap_or(reading.read_at);
        }
    }

    /// How a walk reads `port` now. A reading older than a heal tick is `Unknown` and asks again.
    /// `Ours` and `Foreign` act at once. A silent or refusing rung stays `Silent` until two
    /// reports of silence are a window apart, and then it is `SilentLongEnough`.
    fn reading(&self, port: u16, now: Instant) -> RungRead {
        let Some(reading) = self.readings.get(&port) else {
            return RungRead::Unknown;
        };
        if now.saturating_duration_since(reading.read_at) >= heal_interval() {
            return RungRead::Unknown;
        }
        match reading.answer {
            ProbeAnswer::Ours => RungRead::Ours,
            ProbeAnswer::Foreign => RungRead::Foreign,
            // The window is measured between two reports, not up to now: the reading is fresh
            // for a heal tick, and one report read a window later is still one sample.
            ProbeAnswer::NoAnswer | ProbeAnswer::Refused => match reading.silent_since {
                Some(since)
                    if reading.read_at.saturating_duration_since(since) >= RECLAIM_WINDOW =>
                {
                    RungRead::SilentLongEnough
                }
                _ => RungRead::Silent,
            },
        }
    }

    /// Spawn one probe of `port`, if none is out. `blindable`: the claim walk's probes are the
    /// ones that a test makes read silence; the check of the lower rungs is not.
    fn ask(&mut self, params: &RendezvousParams, node: EndpointId, port: u16, blindable: bool) {
        let now = Instant::now();
        if self
            .in_flight
            .get(&port)
            .is_some_and(|probe| Self::alive(probe.since, now))
        {
            return;
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        self.in_flight.insert(
            port,
            InFlight {
                generation,
                since: now,
            },
        );
        let reports = self.reports.clone();
        let id = params.id;
        let blind = blindable && rung_probes_are_blind(node);
        self.tasks.retain(|task| !task.is_finished());
        self.tasks.push(n0_future::task::spawn(async move {
            // A throwaway identity, for the reason `rung_answer` gives, and with no address
            // lookup: the dial carries the one address that it asks about, and a lookup could
            // hand it another path of the id, which would answer for the id and not the rung.
            let prober = if blind {
                None
            } else {
                build_endpoint(
                    &LookupOpts::loopback(),
                    None,
                    None,
                    Vec::new(),
                    TransportHandles::default(),
                )
                .await
                .ok()
            };
            let answer = match &prober {
                Some(prober) => rung_answer(prober, id, port).await,
                None => ProbeAnswer::NoAnswer,
            };
            // The report goes before the close: closing an endpoint that dialed a silent rung
            // takes about 3 s, and the silence of a rung is timed from the arrival of the report.
            // A closed channel means the loop is gone: the report is stale.
            let _ = reports.send(RungReport {
                port,
                answer,
                generation,
            });
            if let Some(prober) = prober {
                prober.close().await;
            }
        }));
    }

    /// Waits for the probe tasks that are out, so that every prober has closed its endpoint when
    /// this returns. A prober that dials a silent rung gives up after [`RENDEZVOUS_PROBE`] and
    /// then takes about 3 s to close, and the departure of a node would otherwise drop it open.
    /// The bound is the dial and the close, which `NODE_LEAVE` leaves room for.
    pub(crate) async fn finish(&mut self) {
        let tasks = std::mem::take(&mut self.tasks);
        let _ = n0_future::time::timeout(RENDEZVOUS_PROBE + RENDEZVOUS_CLOSE, async {
            for task in tasks {
                let _ = task.await;
            }
        })
        .await;
    }

    /// The port of a rung below `own` that answered as the beacon of our own mesh, if one did.
    /// The busy rungs that have no fresh reading are asked, and the answer comes with a later
    /// call. A rung that said nothing, or refused, or that nobody holds is not an answer: a
    /// holder never gives up its bind on an unknown. A lower rung is asked only when the std
    /// socket check (`rung_is_busy`) reads it busy. If iroh binds a family that the check does
    /// not see, the holder never asks and never sheds. The C, CP and D cases on the fix tree
    /// are the proof of that assumption.
    pub(crate) fn lower_rung_that_answers(
        &mut self,
        params: &RendezvousParams,
        node: EndpointId,
        own: usize,
    ) -> Option<u16> {
        let now = Instant::now();
        let mut answered = None;
        for &port in params.bind_ports.iter().take(own) {
            match self.reading(port, now) {
                RungRead::Ours => {
                    tracing::info!(target: "habilis_network::beacon", node = %node.fmt_short(), port, "a lower rung answers as the beacon of our mesh");
                    answered = Some(port);
                    break;
                }
                RungRead::Unknown if rung_is_busy(port) => self.ask(params, node, port, false),
                RungRead::Foreign
                | RungRead::SilentLongEnough
                | RungRead::Silent
                | RungRead::Unknown => {}
            }
        }
        answered
    }

    /// Tests only: say that `port` has been silent for `by` already.
    #[cfg(test)]
    pub(crate) fn age_silence(&mut self, port: u16, by: std::time::Duration) {
        if let Some(reading) = self.readings.get_mut(&port) {
            reading.silent_since = Instant::now().checked_sub(by);
        }
    }
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
fn beacon_lookups(params: &RendezvousParams) -> LookupOpts {
    LookupOpts {
        mdns: params.lookups.mdns,
        dht: params.lookups.dht,
        relay_lookup: params
            .bootstrap_relay
            .clone()
            .map_or(RelayChoice::Disabled, |rung| {
                RelayChoice::Custom(vec![rung])
            }),
    }
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
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
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

/// What the busy rungs of a private ladder answer to an identity probe, by port, before a joiner's
/// first dial. The book must name the rung that serves our beacon before the joiner subscribes:
/// a first dial with no address that answers is one the gossip layer keeps for seconds before a
/// re-graft can replace it. One throwaway endpoint probes every busy rung, `budget` each; a rung
/// that says nothing in that time is reported as such and read later by the walk. The endpoint
/// closes off this task: closing one that dialed a silent rung takes seconds.
pub(crate) async fn read_busy_rungs(
    params: &RendezvousParams,
    budget: std::time::Duration,
) -> Vec<(u16, ProbeAnswer)> {
    let busy: Vec<u16> = params
        .bind_ports
        .iter()
        .copied()
        .filter(|&port| rung_is_busy(port))
        .collect();
    if busy.is_empty() {
        return Vec::new();
    }
    let Ok(prober) = build_endpoint(
        &LookupOpts::loopback(),
        None,
        None,
        Vec::new(),
        TransportHandles::default(),
    )
    .await
    else {
        return Vec::new();
    };
    let mut read = Vec::with_capacity(busy.len());
    for port in busy {
        let addr = EndpointAddr::new(params.id)
            .with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        let answer = probe_answer(&prober, addr, budget).await;
        tracing::debug!(target: "habilis_network::beacon", port, ?answer, "busy rung read at setup");
        read.push((port, answer));
    }
    drop(n0_future::task::spawn(async move { prober.close().await }));
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
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
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
enum Walk {
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
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
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
    claim_holder(params, peer, peer_book, current, rungs).await
}

/// [`walk_ladder`] for a test that has no loop: it waits for the probe tasks that the walk
/// asked for, and walks again, until the walk has nothing left to wait for.
#[cfg(test)]
pub(crate) async fn ensure_holder(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
    current: &mut Option<Rendezvous>,
    probe_first: bool,
    probe: &mut Option<RivalProbe>,
) -> Held {
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
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
    current: &mut Option<Rendezvous>,
    probe_first: bool,
    probe: &mut Option<RivalProbe>,
) -> bool {
    ensure_holder(params, peer, peer_book, current, probe_first, probe).await == Held::Claimed
}

/// Two holders of one beacon: this node and a rival that it has read. One struct for the pair,
/// because both are an `EndpointId` and a swap compiles and flips the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Contest {
    pub(crate) own: EndpointId,
    pub(crate) rival: EndpointId,
}

impl Contest {
    /// Whether this holder lets go of its beacon for the rival: the lower member id keeps the
    /// rendezvous. Both holders compute it from the same two ids, so exactly one yields.
    pub(crate) fn own_yields(self) -> bool {
        self.rival < self.own
    }
}

/// Apply an off-loop probe's verdict: claim the rendezvous if it is free.
///
/// Re-checks the beacon slot first, because up to [`HEAL_PROBE`] passed
/// while the probe ran and the loop kept moving — a reclaim tick or a
/// re-stand-up may have taken the role in the meantime, and claiming twice
/// binds the duplicate same-id copy the probe exists to prevent.
pub(crate) async fn claim_after_probe(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
    current: &mut Option<Rendezvous>,
    found_rival: bool,
    rungs: &mut RungWatch,
) -> bool {
    if found_rival {
        tracing::debug!(target: "habilis_network::beacon", node = %peer.id().fmt_short(), "public rendezvous already served by a beacon; staying peer");
        return false;
    }
    if !releasable(current) {
        return false;
    }
    claim_holder(params, peer, peer_book, current, rungs).await == Held::Claimed
}

/// Whether the beacon slot is free to (re)claim: empty, or holding a
/// rendezvous whose co-host task has ended.
///
/// A dead one is [`Rendezvous::shed`], never dropped: the co-host *task*
/// ending says nothing about the endpoint, which is still open and still
/// registered under `rendezvous_id`. Dropping it there abandons a live socket
/// — iroh logs `Endpoint dropped without calling Endpoint::close` and joiners
/// keep resolving to a corpse until the QUIC idle timeout.
fn releasable(current: &mut Option<Rendezvous>) -> bool {
    if current
        .as_ref()
        .is_some_and(|rendezvous| !rendezvous.task.is_finished())
    {
        return false;
    }
    if let Some(dead) = current.take() {
        tracing::info!(target: "habilis_network::beacon", "beacon released (co-host task ended); attempting re-stand-up");
        dead.shed();
    }
    true
}

/// Bind the rendezvous endpoint and stand the beacon up on it. The rival
/// question is already settled by the time this runs — either it never
/// applied (private ladder, eager origin) or [`claim_after_probe`] answered
/// it.
#[cfg(test)]
async fn claim(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
    current: &mut Option<Rendezvous>,
) -> bool {
    claim_holder(params, peer, peer_book, current, &mut RungWatch::detached()).await
        == Held::Claimed
}

/// [`claim`], with what the walk read when it did not bind.
async fn claim_holder(
    params: &RendezvousParams,
    peer: &Endpoint,
    peer_book: &iroh::address_lookup::memory::MemoryLookup,
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
        crate::util::tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
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
        params.relay_transport,
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
    let ladder = crate::lookup::relay_ladder(&params.lookups.relay_lookup);
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
    use super::{
        Contest, Endpoint, LookupOpts, Rendezvous, RendezvousParams, RivalProbe, SecretKey,
        TopicId, claim, ensure, foreign_sessions, holder_entry, oneshot, probe_verdict, releasable,
        rendezvous_addr, spawn_rival_probe, verdict_of, watch,
    };
    use habilis_network_test_tracing::test;

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
        let (reports, mut arrivals) = tokio::sync::mpsc::unbounded_channel();
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
        rungs.note(report, crate::util::clock::Instant::now());
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
        let (reports, mut arrivals) = tokio::sync::mpsc::unbounded_channel();
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
            rungs.note(report, crate::util::clock::Instant::now());
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

        let (reports, _arrivals) = tokio::sync::mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);
        let then = crate::util::clock::Instant::now();
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
        let (reports, mut arrivals) = tokio::sync::mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);
        let port = 4242;

        rungs.ask(&params, node, port, true);
        let old = arrivals.recv().await.expect("the first probe reports");
        rungs.expire_probes_in_flight();
        rungs.ask(&params, node, port, true);
        let new = arrivals.recv().await.expect("the second probe reports");

        let now = crate::util::clock::Instant::now();
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

        let (reports, _arrivals) = tokio::sync::mpsc::unbounded_channel();
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
                crate::util::clock::Instant::now(),
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
        let (reports, mut arrivals) = tokio::sync::mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);
        let port = 4242;

        rungs.ask(&params, node, port, true);
        let old = arrivals.recv().await.expect("the first probe reports");
        rungs.expire_probes_in_flight();
        rungs.ask(&params, node, port, true);
        let new = arrivals.recv().await.expect("the second probe reports");

        let first = crate::util::clock::Instant::now();
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
        let (reports, mut arrivals) = tokio::sync::mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);
        let port = 4242;

        rungs.ask(&params, node, port, true);
        let old = arrivals.recv().await.expect("the first probe reports");
        rungs.expire_probes_in_flight();
        rungs.ask(&params, node, port, true);
        let new = arrivals.recv().await.expect("the second probe reports");

        let now = crate::util::clock::Instant::now();
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

        let (reports, _arrivals) = tokio::sync::mpsc::unbounded_channel();
        let mut rungs = RungWatch::new(reports);
        let then = crate::util::clock::Instant::now();
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
        let now = crate::util::clock::Instant::now();

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
        let now = crate::util::clock::Instant::now();
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
            arrivals: tokio::sync::mpsc::channel(1).1,
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
            relay_transport: false,
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
            super::probe_connect(&dialer, target, std::time::Duration::from_millis(200)).await;
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
                arrivals: tokio::sync::mpsc::channel(1).1,
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
        crate::daemon::setup::register_rendezvous(&book, &params, &[]);
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
        crate::lookup::replace_peer_addr(&book, super::rendezvous_holder_addr(&params, stale));
        let (reports, mut arrivals) = super::mpsc::unbounded_channel();
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
        let book = iroh::address_lookup::memory::MemoryLookup::new();
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
            arrivals: tokio::sync::mpsc::channel(1).1,
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
            crate::util::tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
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
            crate::util::tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
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
            crate::util::tuning::GOSSIP_ACTIVE_VIEW_CAPACITY,
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
