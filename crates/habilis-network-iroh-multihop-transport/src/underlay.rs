//! The forwarding **underlay**: a dedicated iroh endpoint that carries opaque
//! QUIC packets hop-by-hop between adjacent relays.
//!
//! The underlay is deliberately a *separate* endpoint from the application
//! endpoint whose packets it relays — the application endpoint is busy being the
//! end-to-end QUIC peer, and could not recursively carry itself. Adjacent hops
//! are link-state neighbours, so their underlay endpoints reach each other over a
//! normal direct/relay path.
//!
//! Outbound: one long-lived writer task per next-hop drains a channel of cells
//! onto a single uni-stream. Inbound ([`ForwardAcceptor`]): each accepted
//! uni-stream is read frame-by-frame; a cell is either forwarded to its next hop
//! or, if this node is the destination, delivered to the local transport — but
//! only after the cell proves it belongs here, since `FORWARD_ALPN` accepts a
//! connection from anyone and an unchecked relay is an amplifying reflector.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use iroh_base::CustomAddr;
use n0_future::time::{Duration, Instant, MissedTickBehavior};
#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use crate::addr::{Route, RouteHop};
use crate::wire::{Cell, read_cell, write_cell};

/// ALPN for the multihop underlay's hop-to-hop forwarding protocol.
pub(crate) const FORWARD_ALPN: &[u8] = b"iroh-multihop/forward/1";

/// Per-next-hop outbound cell queue depth. Dropping past this bounds memory the
/// way a UDP socket's send buffer does — QUIC treats the loss as any other.
/// This is a burst limit; [`FORWARD_QUEUE_BYTES`] is the real ceiling.
const WRITER_QUEUE: usize = 128;

/// Concurrent next-hop writers. A node's honest next-hop set is its direct
/// underlay neighbours, so this is far above any real fan-out; it exists because
/// the map is keyed on a hop id a remote peer chose.
const MAX_WRITERS: usize = 64;

/// Total bytes queued across every writer. Without it the per-hop queue depth is
/// the only bound, and it multiplies by the writer count instead of capping it.
const FORWARD_QUEUE_BYTES: usize = 32 * 1024 * 1024;

/// Dial attempts before a writer task gives up on an unreachable next hop.
const DIAL_ATTEMPTS: usize = 4;

/// A packet that reached its destination on this node, ready for the local
/// transport's `poll_recv` to surface to iroh.
#[derive(Debug)]
pub(crate) struct Delivered {
    /// The sender's return address (a reversed route), reported to iroh as the
    /// remote of this packet so replies route back.
    pub(crate) remote: CustomAddr,
    pub(crate) packet: Vec<u8>,
}

/// How long a reading of a connection's selected path stands. The path moves
/// rarely, and asking for it on every cell would cost more than the cell.
const PATH_RECHECK: Duration = Duration::from_millis(250);

/// The open paths of a connection, each with whether it is the selected one.
fn paths_of(connection: &Connection) -> Vec<(TransportAddr, bool)> {
    connection
        .paths()
        .iter()
        .map(|path| (path.remote_addr().clone(), path.is_selected()))
        .collect()
}

/// Whether a writer sends on a selected path that is not the relay.
/// Nothing selected is not trusted: the engine's own rule for payload
/// (`payload_allowed_on`) refuses until a path is selected.
fn direct_for_writer(paths: &[(TransportAddr, bool)]) -> bool {
    paths
        .iter()
        .any(|(addr, selected)| *selected && !matches!(addr, TransportAddr::Relay(_)))
}

/// Whether a connection that we accepted has an open path that is not the relay.
/// iroh opens paths only from the dialling end. After the dialler's hole-punch
/// round prunes its redundant IP paths, the accepting end chooses no path of its
/// own on this connection: its IP path is open but not selected, and the
/// relay path too. The cells then arrive on the path that the dialler selected,
/// so the selected path here says nothing about them. The cost: a cell that really
/// came over the relay is admitted while an IP path is also open. The dialler's
/// writer gate refuses relay cells, and iroh shows no path per datagram.
fn direct_for_inbound(paths: &[(TransportAddr, bool)]) -> bool {
    paths
        .iter()
        .any(|(addr, _)| !matches!(addr, TransportAddr::Relay(_)))
}

/// Which end of a connection a gate stands on.
#[derive(Debug, Clone, Copy)]
enum GateRole {
    /// The end that dialled and writes the cells.
    Writer,
    /// The end that accepted the connection and reads the cells.
    Inbound,
}

/// The paths of a connection as text, a star on the selected one.
fn path_list(paths: impl IntoIterator<Item = (TransportAddr, bool)>) -> String {
    paths
        .into_iter()
        .map(|(addr, selected)| format!("{addr:?}{}", if selected { "*" } else { "" }))
        .collect::<Vec<_>>()
        .join(" ")
}

/// What the relay may do for cells, set by the mesh policy.
#[derive(Debug, Clone, Copy)]
struct RelayRule {
    /// Whether the relay may carry cells (the mesh's `relay_transport`).
    allow_relay: bool,
    /// How long a hop may stay refused before it is no longer a link.
    stuck_after: Duration,
}

/// Keeps cells off a connection unless it sends on a selected path that is not
/// the relay, unless the mesh lets the relay carry payload. The relay is for
/// lookup alone: a connection starts on it until a direct path opens, and the
/// cells of other peers' traffic must not ride it meanwhile.
struct RelayGate {
    allow_relay: bool,
    role: GateRole,
    reading: Option<(Instant, bool)>,
    /// The path list at the last refusal, so that the log says it once per change.
    last_refused_paths: Option<String>,
}

impl RelayGate {
    fn new(allow_relay: bool, role: GateRole) -> Self {
        Self {
            allow_relay,
            role,
            reading: None,
            last_refused_paths: None,
        }
    }

    /// Whether a cell may cross `connection` now.
    fn admits(&mut self, connection: &Connection) -> bool {
        if self.allow_relay {
            return true;
        }
        let now = Instant::now();
        match self.reading {
            Some((at, admitted)) if now.duration_since(at) < PATH_RECHECK => admitted,
            _ => {
                let paths = paths_of(connection);
                let admitted = match self.role {
                    GateRole::Writer => direct_for_writer(&paths),
                    GateRole::Inbound => direct_for_inbound(&paths),
                };
                self.reading = Some((now, admitted));
                if !admitted {
                    let paths = path_list(paths);
                    if self.last_refused_paths.as_deref() != Some(paths.as_str()) {
                        match self.role {
                            GateRole::Writer => tracing::debug!(
                                %paths,
                                "multihop underlay: no direct path is selected"
                            ),
                            GateRole::Inbound => tracing::debug!(
                                %paths,
                                "multihop underlay: no open path is not the relay"
                            ),
                        }
                        self.last_refused_paths = Some(paths);
                    }
                }
                admitted
            }
        }
    }
}

/// How one next hop's underlay is doing under the relay rule.
///
/// The entry lives as long as the hop's writer: a retiring writer calls
/// `forget`, which clears a stuck mark too. A hop that is still on the relay is
/// then advertised again until its next writer has been refused for the
/// deadline: one retry each time a writer dies, not a loop.
#[derive(Debug)]
struct HopHealth {
    /// The hop's application id: what a link-vector names.
    app_id: EndpointId,
    /// Since when the gate has refused this hop without a break.
    refused_since: Option<Instant>,
    /// Refused for longer than the deadline: not advertised as a link.
    stuck: bool,
}

/// The outbound writer set and its shared byte budget.
///
/// Split out from [`Forwarder`] so a writer task can hold exactly what it needs
/// to retire itself and release its own queued bytes, without a self-reference
/// back into the forwarder.
#[derive(Debug, Default)]
struct WriterPool {
    /// One outbound writer channel per next-hop underlay endpoint id.
    writers: Mutex<HashMap<EndpointId, mpsc::Sender<Cell>>>,
    /// Bytes queued across every writer.
    queued_bytes: AtomicUsize,
    /// Cells a writer dropped because its connection was not on a direct path.
    refused_on_relay: AtomicU64,
    /// The relay rule's verdict per next hop, keyed like `writers`.
    health: Mutex<HashMap<EndpointId, HopHealth>>,
    /// Woken when the gate starts to refuse a hop, and when it admits one that it
    /// refused: the moments at which the best first hop to a peer can change.
    route_wake: Arc<tokio::sync::Notify>,
}

impl WriterPool {
    /// Drop `key`'s entry, but only if it is still `sender`'s. A writer that has
    /// already been replaced must not delete its successor's channel — that race
    /// is how a sibling transport grew a permanent phantom session.
    fn retire(&self, key: EndpointId, sender: &mpsc::Sender<Cell>) {
        let mut writers = self.writers.lock().expect("writers mutex poisoned");
        if writers
            .get(&key)
            .is_some_and(|live| live.same_channel(sender))
        {
            writers.remove(&key);
        }
    }

    fn release(&self, cost: usize) {
        self.queued_bytes.fetch_sub(cost, Ordering::Relaxed);
    }

    fn track(&self, underlay: EndpointId, app_id: EndpointId) {
        self.health.lock().expect("health mutex poisoned").insert(
            underlay,
            HopHealth {
                app_id,
                refused_since: None,
                stuck: false,
            },
        );
    }

    fn forget(&self, underlay: EndpointId) {
        self.health
            .lock()
            .expect("health mutex poisoned")
            .remove(&underlay);
    }

    /// The gate refused this hop just now. Past the deadline the hop is stuck,
    /// said once in the log.
    fn note_refused(&self, underlay: EndpointId, stuck_after: Duration) {
        let mut health = self.health.lock().expect("health mutex poisoned");
        let Some(hop) = health.get_mut(&underlay) else {
            return;
        };
        if hop.refused_since.is_none() {
            self.route_wake.notify_one();
        }
        let since = *hop.refused_since.get_or_insert_with(Instant::now);
        if !hop.stuck && since.elapsed() >= stuck_after {
            hop.stuck = true;
            tracing::warn!(
                hop = %underlay.fmt_short(),
                app_id = %hop.app_id.fmt_short(),
                "multihop underlay stays on the relay: this hop is not advertised as a link"
            );
        }
    }

    /// The gate admitted this hop: it is a link again.
    fn note_admitted(&self, underlay: EndpointId) {
        let mut health = self.health.lock().expect("health mutex poisoned");
        let Some(hop) = health.get_mut(&underlay) else {
            return;
        };
        if hop.refused_since.take().is_some() {
            self.route_wake.notify_one();
        }
        if std::mem::take(&mut hop.stuck) {
            tracing::info!(
                hop = %underlay.fmt_short(),
                app_id = %hop.app_id.fmt_short(),
                "multihop underlay is direct again: this hop is a link"
            );
        }
    }

    /// The hops that the gate refuses now, stuck or not.
    fn refusing_app_ids(&self) -> Vec<EndpointId> {
        self.health
            .lock()
            .expect("health mutex poisoned")
            .values()
            .filter(|hop| hop.refused_since.is_some())
            .map(|hop| hop.app_id)
            .collect()
    }

    fn stuck_app_ids(&self) -> Vec<EndpointId> {
        self.health
            .lock()
            .expect("health mutex poisoned")
            .values()
            .filter(|hop| hop.stuck)
            .map(|hop| hop.app_id)
            .collect()
    }
}

/// Routes cells outbound to next hops and delivers terminal cells locally.
#[derive(Debug)]
pub(crate) struct Forwarder {
    underlay: Endpoint,
    /// This node's application-layer id, the other half of the identity a cell's
    /// current hop must name.
    self_app_id: EndpointId,
    /// The runtime that spawns the writers. `enqueue` runs inside `poll_send`, which
    /// iroh calls from the socket's send path (`Transports::poll_send` in iroh's
    /// `socket/transports.rs`). It is kept so that a native spawn never depends on
    /// that caller being inside the runtime; nothing here shows that it is ever
    /// outside. A browser has no runtime and spawns on its one thread.
    #[cfg(not(target_arch = "wasm32"))]
    runtime: Handle,
    pool: Arc<WriterPool>,
    /// Terminal deliveries destined for the local application endpoint.
    inbound: mpsc::Sender<Delivered>,
    /// Cells refused by the gates in [`Forwarder::handle_cell`] or by a budget.
    dropped: AtomicU64,
    /// Cells passed on to a next hop for other nodes. Our own sends are not counted.
    forwarded: AtomicU64,
    /// What the relay may do for cells.
    rule: RelayRule,
}

impl Forwarder {
    pub(crate) fn new(
        underlay: Endpoint,
        self_app_id: EndpointId,
        inbound: mpsc::Sender<Delivered>,
        allow_relay: bool,
        stuck_after: Duration,
    ) -> Self {
        Self {
            underlay,
            self_app_id,
            #[cfg(not(target_arch = "wasm32"))]
            runtime: Handle::current(),
            pool: Arc::new(WriterPool::default()),
            inbound,
            dropped: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            rule: RelayRule {
                allow_relay,
                stuck_after,
            },
        }
    }

    /// How many cells this node passed on for other nodes.
    pub(crate) fn forwarded_cells(&self) -> u64 {
        self.forwarded.load(Ordering::Relaxed)
    }

    /// The application ids of the hops stuck on the relay past the deadline.
    pub(crate) fn stuck_hops(&self) -> Vec<EndpointId> {
        self.pool.stuck_app_ids()
    }

    /// Woken when the gate starts to refuse a hop, and when it admits one that it
    /// refused.
    pub(crate) fn route_wake(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.pool.route_wake)
    }

    /// The application ids of the hops that the gate refuses now, stuck or not.
    pub(crate) fn refusing_hops(&self) -> Vec<EndpointId> {
        self.pool.refusing_app_ids()
    }

    /// Mark a hop as refused now, without the deadline having passed, as a test of
    /// the choice of a route needs it.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn refuse_hop_for_test(&self, underlay: EndpointId, app_id: EndpointId) {
        self.pool.track(underlay, app_id);
        self.pool.note_refused(underlay, Duration::from_mins(1));
    }

    /// Rate-limited visibility for a refused cell. Whoever is sending them sets
    /// the rate, so logging every one hands them a second amplifier.
    fn note_drop(&self, reason: &str) {
        if let Some(total) = self.count_drop() {
            tracing::warn!(total, reason, "multihop forwarder refusing cells");
        }
    }

    /// The refusal of a cell that came in over `connection` from `hop`, with what
    /// the log needs to tell whose path it was: the hop, this node, and the paths.
    fn note_inbound_refusal(&self, hop: EndpointId, connection: &Connection) {
        if let Some(total) = self.count_drop() {
            tracing::warn!(
                total,
                reason = "cell arrived over the relay",
                hop = %hop.fmt_short(),
                node = %self.underlay.id().fmt_short(),
                paths = %path_list(paths_of(connection)),
                "multihop forwarder refusing cells"
            );
        }
    }

    /// Count a refused cell. The total when it is to be logged: the first, then
    /// every 256th.
    fn count_drop(&self) -> Option<u64> {
        let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        (total == 1 || total.is_multiple_of(256)).then_some(total)
    }

    /// Hand a cell to the writer for `hop`, spawning one if none is live. Never
    /// blocks: a full or dead queue drops the cell (QUIC recovers).
    pub(crate) fn enqueue(&self, hop: &RouteHop, cell: Cell) {
        let cost = cell.packet.len();
        if self.pool.queued_bytes.fetch_add(cost, Ordering::Relaxed) + cost > FORWARD_QUEUE_BYTES {
            self.pool.release(cost);
            self.note_drop("forwarding byte budget exhausted");
            return;
        }
        let key = hop.underlay.id;
        // First attempt on any existing writer.
        if let Some(sender) = self.writer_for(key)
            && sender.try_send(cell.clone()).is_ok()
        {
            return;
        }
        // Stale or absent: (re)spawn a writer, then try once more.
        let Some(sender) = self.spawn_writer(hop.underlay.clone(), hop.app_id) else {
            self.pool.release(cost);
            return;
        };
        if sender.try_send(cell).is_err() {
            self.pool.release(cost);
        }
    }

    /// Deliver a cell that terminated here to the local transport.
    fn deliver(&self, cell: Cell) {
        let Some(route) = Route::reverse_from(cell.path.hops(), cell.source) else {
            self.note_drop("return route is not a legal route");
            return;
        };
        let delivered = Delivered {
            remote: route.encode(),
            packet: cell.packet,
        };
        // A full inbox drops the packet, as a saturated NIC would.
        let _ = self.inbound.try_send(delivered);
    }

    /// Whether `hop` is this node — both identities, since the two endpoints
    /// carry different keys and a cell should not be able to pair our underlay
    /// with somebody else's application id.
    fn is_self(&self, hop: &RouteHop) -> bool {
        hop.underlay.id == self.underlay.id() && hop.app_id == self.self_app_id
    }

    /// The hop that should have sent us this cell: our predecessor on the route,
    /// or the original sender when we are the first hop.
    fn expected_upstream(cell: &Cell) -> Option<&RouteHop> {
        match cell.pos.checked_sub(1) {
            None => Some(&cell.source),
            Some(previous) => cell.path.hop_at(previous as usize),
        }
    }

    /// Process one received cell: forward to the next hop, or deliver if we are
    /// the destination.
    ///
    /// `from` is the authenticated id of the connection the cell arrived on.
    /// Requiring it to be the route's preceding hop is what stops a stranger
    /// injecting a cell at a position it does not occupy — the structural
    /// invariants on [`Route`] bound what a route may look like, but only this
    /// binds a cell to the path it claims to be travelling.
    pub(crate) fn handle_cell(&self, cell: Cell, from: EndpointId) {
        let Some(here) = cell.current_hop() else {
            self.note_drop("position past the end of the route");
            return;
        };
        if !self.is_self(here) {
            self.note_drop("position does not name this node");
            return;
        }
        let is_expected_upstream =
            Self::expected_upstream(&cell).is_some_and(|hop| hop.underlay.id == from);
        if !is_expected_upstream {
            self.note_drop("cell did not arrive from its preceding hop");
            return;
        }
        match cell.next_hop() {
            Some(next) => {
                let next = next.clone();
                self.forwarded.fetch_add(1, Ordering::Relaxed);
                self.enqueue(&next, cell.advanced());
            }
            None => self.deliver(cell),
        }
    }

    fn writer_for(&self, key: EndpointId) -> Option<mpsc::Sender<Cell>> {
        let writers = self.pool.writers.lock().expect("writers mutex poisoned");
        writers.get(&key).cloned()
    }

    /// Insert and spawn a fresh writer task for `dst`, replacing any dead entry.
    /// `None` once [`MAX_WRITERS`] are live.
    ///
    /// Refusing rather than evicting is deliberate: the next-hop id comes off the
    /// wire, so evicting would let a flood of invented hops walk the real
    /// neighbours out of the map. A refused flood instead clears itself, because
    /// each spawned writer gives up after [`DIAL_ATTEMPTS`] and removes its own
    /// entry on the way out.
    fn spawn_writer(&self, dst: EndpointAddr, app_id: EndpointId) -> Option<mpsc::Sender<Cell>> {
        let (tx, rx) = mpsc::channel(WRITER_QUEUE);
        {
            let mut writers = self.pool.writers.lock().expect("writers mutex poisoned");
            if writers.len() >= MAX_WRITERS && !writers.contains_key(&dst.id) {
                drop(writers);
                self.note_drop("next-hop writer ceiling reached");
                return None;
            }
            writers.insert(dst.id, tx.clone());
        }
        self.pool.track(dst.id, app_id);
        let writer = writer_task(
            self.underlay.clone(),
            dst,
            rx,
            tx.clone(),
            Arc::clone(&self.pool),
            self.rule,
        );
        #[cfg(not(target_arch = "wasm32"))]
        self.runtime.spawn(writer);
        #[cfg(target_arch = "wasm32")]
        n0_future::task::spawn(writer);
        Some(tx)
    }
}

/// Drain `rx` onto a single uni-stream to `dst`. Exits on dial failure or a
/// write error, retiring its own entry so the map does not accumulate one dead
/// writer per next-hop id a peer ever named, and releasing whatever it still had
/// queued so a dead hop cannot hold the shared byte budget hostage.
async fn writer_task(
    underlay: Endpoint,
    dst: EndpointAddr,
    mut rx: mpsc::Receiver<Cell>,
    handle: mpsc::Sender<Cell>,
    pool: Arc<WriterPool>,
    rule: RelayRule,
) {
    let outcome = drain_to_hop(&underlay, &dst, &mut rx, &pool, rule).await;
    if let Err(error) = outcome {
        tracing::debug!(hop = %dst.id.fmt_short(), %error, "multihop underlay writer stopping");
    }
    pool.retire(dst.id, &handle);
    pool.forget(dst.id);
    // Whatever never made it onto the wire is still charged to the budget.
    rx.close();
    while let Ok(cell) = rx.try_recv() {
        pool.release(cell.packet.len());
    }
}

async fn drain_to_hop(
    underlay: &Endpoint,
    dst: &EndpointAddr,
    rx: &mut mpsc::Receiver<Cell>,
    pool: &WriterPool,
    rule: RelayRule,
) -> anyhow::Result<()> {
    let conn = dial_with_retry(underlay, dst)
        .await
        .context("underlay dial gave up")?;
    let mut send = conn.open_uni().await.context("open underlay uni-stream")?;
    let mut gate = RelayGate::new(rule.allow_relay, GateRole::Writer);
    // Looks at the path once a second even when no cell comes, so a hop that was
    // withdrawn for staying on the relay (and so carries no cells) is a link
    // again once a direct path opens.
    let mut recheck = n0_future::time::interval(Duration::from_secs(1));
    recheck.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            // A connection that ended under us ends the writer. Without this arm a
            // dead connection with no cell in flight is read by the tick below as
            // a connection with no direct path: the hop would be marked stuck and
            // the writer would never retire.
            reason = conn.closed() => {
                anyhow::bail!("underlay connection closed: {reason}");
            }
            next = rx.recv() => {
                let Some(cell) = next else { break };
                let cost = cell.packet.len();
                if gate.admits(&conn) {
                    pool.note_admitted(dst.id);
                } else {
                    // Dropped like any other loss: QUIC above retransmits, and a
                    // direct path takes over once one opens.
                    pool.release(cost);
                    pool.refused_on_relay.fetch_add(1, Ordering::Relaxed);
                    pool.note_refused(dst.id, rule.stuck_after);
                    continue;
                }
                let written = write_cell(&mut send, &cell).await;
                pool.release(cost);
                written.context("underlay write failed")?;
            }
            _ = recheck.tick(), if !rule.allow_relay => {
                if gate.admits(&conn) {
                    pool.note_admitted(dst.id);
                } else {
                    pool.note_refused(dst.id, rule.stuck_after);
                }
            }
        }
    }
    let _ = send.finish();
    Ok(())
}

async fn dial_with_retry(underlay: &Endpoint, dst: &EndpointAddr) -> Option<Connection> {
    for attempt in 0..DIAL_ATTEMPTS {
        match underlay.connect(dst.clone(), FORWARD_ALPN).await {
            Ok(conn) => return Some(conn),
            Err(error) => {
                tracing::trace!(hop = %dst.id.fmt_short(), attempt, %error, "underlay dial attempt failed");
                // Linear backoff; adjacent hops that are momentarily busy settle fast.
                n0_future::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
            }
        }
    }
    None
}

/// The `FORWARD_ALPN` accept side: read cells off each incoming uni-stream and
/// hand them to the [`Forwarder`].
#[derive(Debug, Clone)]
pub(crate) struct ForwardAcceptor {
    forwarder: Arc<Forwarder>,
}

impl ForwardAcceptor {
    pub(crate) fn new(forwarder: Arc<Forwarder>) -> Self {
        Self { forwarder }
    }

    async fn read_loop(
        self,
        upstream: EndpointId,
        connection: Connection,
        gate: Arc<Mutex<RelayGate>>,
        mut recv: iroh::endpoint::RecvStream,
    ) {
        while let Ok(cell) = read_cell(&mut recv).await {
            let admitted = gate
                .lock()
                .expect("relay gate poisoned")
                .admits(&connection);
            if admitted {
                self.forwarder.handle_cell(cell, upstream);
            } else {
                self.forwarder.note_inbound_refusal(upstream, &connection);
            }
        }
    }
}

impl ProtocolHandler for ForwardAcceptor {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // The peer's QUIC-TLS identity: the one thing about a cell's origin its
        // sender cannot choose, and constant across every stream on this
        // connection. Every cell that arrives here is checked against it.
        let upstream = connection.remote_id();
        let gate = Arc::new(Mutex::new(RelayGate::new(
            self.forwarder.rule.allow_relay,
            GateRole::Inbound,
        )));
        // Loop ends when the upstream hop closes the connection: normal teardown.
        while let Ok(recv) = connection.accept_uni().await {
            n0_future::task::spawn(self.clone().read_loop(
                upstream,
                connection.clone(),
                Arc::clone(&gate),
                recv,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Arc, Delivered, Duration, Forwarder, MAX_WRITERS, Ordering, TransportAddr};
    use crate::addr::{Route, RouteHop};
    use crate::test_support::relay_server;
    use crate::wire::Cell;
    use iroh::endpoint::presets;
    use iroh::endpoint::transports::{PathSelection, PathSelectionContext, PathSelector};
    use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
    use std::net::SocketAddr;
    use tokio::sync::mpsc;

    fn stranger(seed: u8) -> RouteHop {
        let id: EndpointId = SecretKey::from_bytes(&[seed; 32]).public();
        RouteHop {
            app_id: id,
            underlay: EndpointAddr::new(id),
        }
    }

    /// A forwarder over a real loopback underlay, plus the delivery receiver the
    /// local transport would hold. `app_id` is a distinct key from the underlay's,
    /// as it is in production.
    async fn forwarder() -> (Forwarder, EndpointId, mpsc::Receiver<Delivered>) {
        let loopback: SocketAddr = "127.0.0.1:0".parse().expect("loopback addr");
        let underlay = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind_addr(loopback)
            .expect("valid bind addr")
            .bind()
            .await
            .expect("bind underlay endpoint");
        let app_id: EndpointId = SecretKey::from_bytes(&[99; 32]).public();
        let (inbound, received) = mpsc::channel(4);
        (
            Forwarder::new(underlay, app_id, inbound, false, Duration::from_secs(20)),
            app_id,
            received,
        )
    }

    /// This forwarder's own hop, as a legitimate route would name it.
    fn self_hop(forwarder: &Forwarder) -> RouteHop {
        RouteHop {
            app_id: forwarder.self_app_id,
            underlay: forwarder.underlay.addr(),
        }
    }

    fn cell(hops: Vec<RouteHop>, pos: u16, source: RouteHop) -> Cell {
        Cell {
            path: Route::new(hops).expect("legal route"),
            pos,
            source,
            packet: vec![1, 2, 3],
        }
    }

    fn live_writers(forwarder: &Forwarder) -> usize {
        forwarder
            .pool
            .writers
            .lock()
            .expect("writers mutex poisoned")
            .len()
    }

    #[tokio::test]
    async fn a_cell_that_ends_at_us_is_delivered_locally() {
        // The happy path the refusals below are measured against.
        let (forwarder, _app, mut received) = forwarder().await;
        let source = stranger(1);
        let subject = cell(vec![self_hop(&forwarder)], 0, source.clone());
        forwarder.handle_cell(subject, source.underlay.id);
        assert!(received.try_recv().is_ok());
        assert_eq!(
            forwarder.forwarded_cells(),
            0,
            "a delivery is not a forward"
        );
    }

    #[tokio::test]
    async fn a_cell_naming_another_node_is_neither_delivered_nor_forwarded() {
        // The reflector proper: we are nowhere on this route, so relaying it
        // would spend our bandwidth on a stranger's behalf.
        let (forwarder, _app, mut received) = forwarder().await;
        let source = stranger(1);
        let subject = cell(vec![stranger(2), stranger(3)], 0, source.clone());
        forwarder.handle_cell(subject, source.underlay.id);
        assert!(received.try_recv().is_err());
        assert_eq!(live_writers(&forwarder), 0, "no writer, no dial, no bytes");
    }

    #[tokio::test]
    async fn a_cell_from_the_wrong_upstream_is_refused() {
        // A hostile downstream hop bouncing a structurally valid cell back at
        // us. Every hop on this route is real and we genuinely occupy `pos`, so
        // only the authenticated sender id catches it.
        let (forwarder, _app, mut received) = forwarder().await;
        let source = stranger(1);
        let downstream = stranger(4);
        let subject = cell(
            vec![stranger(2), self_hop(&forwarder), downstream.clone()],
            1,
            source,
        );
        forwarder.handle_cell(subject, downstream.underlay.id);
        assert!(received.try_recv().is_err());
        assert_eq!(live_writers(&forwarder), 0);
    }

    #[tokio::test]
    async fn a_cell_positioned_past_the_end_is_not_delivered() {
        let (forwarder, _app, mut received) = forwarder().await;
        let source = stranger(1);
        let subject = cell(vec![self_hop(&forwarder)], 7, source.clone());
        forwarder.handle_cell(subject, source.underlay.id);
        assert!(received.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_cell_passing_through_us_is_queued_for_the_next_hop() {
        let (forwarder, _app, mut received) = forwarder().await;
        let source = stranger(1);
        let next = stranger(5);
        let subject = cell(vec![self_hop(&forwarder), next.clone()], 0, source.clone());
        forwarder.handle_cell(subject, source.underlay.id);
        assert!(received.try_recv().is_err(), "not ours to deliver");
        assert_eq!(live_writers(&forwarder), 1);
        assert_eq!(forwarder.forwarded_cells(), 1);
    }

    #[tokio::test]
    async fn a_refused_cell_is_not_counted_as_forwarded() {
        let (forwarder, _app, _received) = forwarder().await;
        let source = stranger(1);
        let subject = cell(vec![stranger(2), stranger(3)], 0, source.clone());
        forwarder.handle_cell(subject, source.underlay.id);
        assert_eq!(forwarder.forwarded_cells(), 0);
    }

    /// A node whose underlay can only use the relay, as a forwarder with its
    /// accept side running.
    struct RelayNode {
        forwarder: Arc<Forwarder>,
        hop: RouteHop,
        received: mpsc::Receiver<Delivered>,
        _router: iroh::protocol::Router,
    }

    async fn relay_node(seed: u8, url: &iroh::RelayUrl, allow_relay: bool) -> RelayNode {
        let underlay = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .relay_mode(RelayMode::custom([url.clone()]))
            .clear_ip_transports()
            .bind()
            .await
            .expect("bind a relay-only underlay");
        tokio::time::timeout(Duration::from_secs(10), underlay.online())
            .await
            .expect("the underlay reaches the relay");
        let app_id: EndpointId = SecretKey::from_bytes(&[seed.wrapping_add(100); 32]).public();
        let (inbound, received) = mpsc::channel(8);
        let forwarder = Arc::new(Forwarder::new(
            underlay.clone(),
            app_id,
            inbound,
            allow_relay,
            Duration::from_millis(300),
        ));
        let router = iroh::protocol::Router::builder(underlay.clone())
            .accept(
                super::FORWARD_ALPN,
                super::ForwardAcceptor::new(Arc::clone(&forwarder)),
            )
            .spawn();
        let hop = RouteHop {
            app_id,
            underlay: underlay.addr(),
        };
        RelayNode {
            forwarder,
            hop,
            received,
            _router: router,
        }
    }

    /// Send one cell from `from` to `to` over their underlays and say whether it
    /// arrived within a few seconds.
    async fn cell_arrives(from: &RelayNode, to: &mut RelayNode) -> bool {
        let subject = Cell {
            path: Route::new(vec![to.hop.clone()]).expect("legal route"),
            pos: 0,
            source: from.hop.clone(),
            packet: vec![7, 7, 7],
        };
        // Retried: the first attempts can find the connection still being set up.
        for _ in 0..6 {
            from.forwarder.enqueue(&to.hop, subject.clone());
            if tokio::time::timeout(Duration::from_millis(500), to.received.recv())
                .await
                .is_ok_and(|delivered| delivered.is_some())
            {
                return true;
            }
        }
        false
    }

    #[tokio::test]
    async fn the_relay_carries_cells_when_the_mesh_lets_it() {
        let (url, _server) = relay_server().await;
        let from = relay_node(1, &url, true).await;
        let mut to = relay_node(2, &url, true).await;
        assert!(
            cell_arrives(&from, &mut to).await,
            "relay payload is allowed"
        );
    }

    #[tokio::test]
    async fn a_cell_is_not_sent_on_a_relay_selected_path() {
        let (url, _server) = relay_server().await;
        let from = relay_node(3, &url, false).await;
        let mut to = relay_node(4, &url, true).await;
        assert!(
            !cell_arrives(&from, &mut to).await,
            "the sender refuses the relay"
        );
        assert!(
            from.forwarder.pool.refused_on_relay.load(Ordering::Relaxed) > 0,
            "and counts what it refused"
        );
    }

    #[tokio::test]
    async fn a_cell_that_arrives_on_a_relay_selected_path_is_dropped() {
        let (url, _server) = relay_server().await;
        let from = relay_node(5, &url, true).await;
        let mut to = relay_node(6, &url, false).await;
        assert!(
            !cell_arrives(&from, &mut to).await,
            "the receiver refuses the relay"
        );
        assert!(to.forwarder.dropped.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn a_hop_that_stays_on_the_relay_becomes_stuck() {
        let (url, _server) = relay_server().await;
        let from = relay_node(7, &url, false).await;
        let mut to = relay_node(8, &url, true).await;
        assert!(!cell_arrives(&from, &mut to).await);
        // Refused for longer than the deadline: no longer a link.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while from.forwarder.stuck_hops().is_empty() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(from.forwarder.stuck_hops(), vec![to.hop.app_id]);
    }

    #[test]
    fn the_path_list_marks_the_selected_path_with_a_star() {
        let ip = TransportAddr::Ip("127.0.0.1:9".parse().expect("an address"));
        let relay = TransportAddr::Relay("http://127.0.0.1:1".parse().expect("a relay url"));
        let list = super::path_list([(relay, true), (ip, false)]);
        assert!(list.starts_with("Relay("), "{list}");
        assert!(list.ends_with(")* Ip(127.0.0.1:9)"), "{list}");
    }

    /// Whether `wake` holds a wake-up now.
    async fn woke(wake: &tokio::sync::Notify) -> bool {
        tokio::time::timeout(Duration::from_millis(20), wake.notified())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn the_pool_wakes_at_the_first_refusal_of_a_hop_and_at_its_recovery() {
        let (hop, app) = (stranger(13).underlay.id, stranger(14).app_id);
        let pool = super::WriterPool::default();
        let wake = Arc::clone(&pool.route_wake);
        pool.track(hop, app);
        assert!(!woke(&wake).await, "a hop that was never refused");
        pool.note_admitted(hop);
        assert!(!woke(&wake).await, "an admitted hop that was not refused");

        pool.note_refused(hop, Duration::from_mins(1));
        assert!(woke(&wake).await, "the first refusal");
        pool.note_refused(hop, Duration::from_mins(1));
        pool.note_refused(hop, Duration::from_mins(1));
        assert!(!woke(&wake).await, "a refusal that goes on is not news");

        pool.note_admitted(hop);
        assert!(woke(&wake).await, "the recovery of a refused hop");
        pool.note_admitted(hop);
        assert!(!woke(&wake).await, "an admitted hop that stays admitted");
    }

    #[test]
    fn a_stuck_hop_is_a_link_again_once_it_is_admitted() {
        let (hop, app) = (stranger(11).underlay.id, stranger(12).app_id);
        let pool = super::WriterPool::default();
        pool.track(hop, app);
        pool.note_refused(hop, Duration::ZERO);
        assert_eq!(pool.stuck_app_ids(), vec![app], "refused past the deadline");
        pool.note_admitted(hop);
        assert!(pool.stuck_app_ids().is_empty(), "admitted: a link again");
        pool.note_refused(hop, Duration::from_mins(1));
        assert!(
            pool.stuck_app_ids().is_empty(),
            "a fresh refusal is not yet stuck"
        );
    }

    /// A node whose underlay is on loopback, with its accept side running: the
    /// path between two of these is direct.
    async fn loopback_node(seed: u8, stuck_after: Duration) -> RelayNode {
        loopback_node_with(seed, stuck_after, None).await
    }

    /// A [`loopback_node`] whose underlay chooses its paths with `selector`.
    async fn loopback_node_with(
        seed: u8,
        stuck_after: Duration,
        selector: Option<Arc<dyn PathSelector>>,
    ) -> RelayNode {
        let loopback: SocketAddr = "127.0.0.1:0".parse().expect("loopback addr");
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .relay_mode(RelayMode::Disabled)
            .bind_addr(loopback)
            .expect("valid bind addr");
        if let Some(selector) = selector {
            builder = builder.path_selector(selector);
        }
        let underlay = builder.bind().await.expect("bind a loopback underlay");
        let app_id: EndpointId = SecretKey::from_bytes(&[seed.wrapping_add(100); 32]).public();
        let (inbound, received) = mpsc::channel(8);
        let forwarder = Arc::new(Forwarder::new(
            underlay.clone(),
            app_id,
            inbound,
            false,
            stuck_after,
        ));
        let router = iroh::protocol::Router::builder(underlay.clone())
            .accept(
                super::FORWARD_ALPN,
                super::ForwardAcceptor::new(Arc::clone(&forwarder)),
            )
            .spawn();
        let hop = RouteHop {
            app_id,
            underlay: underlay.addr(),
        };
        RelayNode {
            forwarder,
            hop,
            received,
            _router: router,
        }
    }

    /// A selector that never selects a path. iroh opens paths only from the dialling
    /// end, so on the accepting end the chosen path can be none of those open.
    #[derive(Debug)]
    struct NeverSelects;

    impl PathSelector for NeverSelects {
        fn select(&self, _ctx: &PathSelectionContext<'_>) -> PathSelection {
            PathSelection::none()
        }
    }

    fn ip(port: u16) -> TransportAddr {
        TransportAddr::Ip(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn relay() -> TransportAddr {
        TransportAddr::Relay("http://127.0.0.1:1".parse().expect("a relay url"))
    }

    #[test]
    fn an_accepted_connection_is_direct_when_any_open_path_is_not_the_relay() {
        use super::{direct_for_inbound, direct_for_writer};
        assert!(
            direct_for_inbound(&[(ip(9), false), (relay(), false)]),
            "an IP path in backup beside the relay in backup"
        );
        assert!(direct_for_inbound(&[(ip(9), true), (relay(), false)]));
        assert!(
            !direct_for_inbound(&[(relay(), false)]),
            "only the relay is open"
        );
        assert!(
            !direct_for_inbound(&[(relay(), true)]),
            "only the relay, selected"
        );
        assert!(!direct_for_inbound(&[]), "no path is open");
        // The writer keeps the stricter rule: it sends on the selected path.
        assert!(!direct_for_writer(&[(ip(9), false), (relay(), false)]));
        assert!(direct_for_writer(&[(ip(9), true), (relay(), false)]));
    }

    #[tokio::test]
    async fn a_cell_arrives_when_the_accepting_end_selected_no_path() {
        // The dialling end sends on a selected IP path. The accepting end opened no
        // path of its own and selects none, but its connection has the IP path open.
        let stuck_after = Duration::from_millis(300);
        let from = loopback_node(31, stuck_after).await;
        let mut to = loopback_node_with(32, stuck_after, Some(Arc::new(NeverSelects))).await;
        assert!(
            cell_arrives(&from, &mut to).await,
            "a cell that came over IP is not a cell over the relay"
        );
        assert_eq!(to.forwarder.dropped.load(Ordering::Relaxed), 0);
        assert_eq!(
            from.forwarder.pool.refused_on_relay.load(Ordering::Relaxed),
            0,
            "and the writer did not refuse the relay on the way"
        );
    }

    #[tokio::test]
    async fn a_writer_retires_when_its_connection_closes_under_it() {
        // A direct hop, then the far underlay goes away while no cell is in
        // flight. The writer must see the close: a dead connection read as one
        // with no direct path would mark the hop stuck and never end the writer.
        let stuck_after = Duration::from_millis(300);
        let from = loopback_node(21, stuck_after).await;
        let mut to = loopback_node(22, stuck_after).await;
        assert!(cell_arrives(&from, &mut to).await, "the hop is direct");
        assert_eq!(live_writers(&from.forwarder), 1, "a writer carries it");

        to.forwarder.underlay.close().await;

        // Longer than the deadline and the one-second tick, twice over.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while live_writers(&from.forwarder) > 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            live_writers(&from.forwarder),
            0,
            "the writer retires with its connection"
        );
        assert!(
            from.forwarder.stuck_hops().is_empty(),
            "a hop whose connection closed is not stuck on the relay"
        );
    }

    #[tokio::test]
    async fn a_writer_retires_itself_and_releases_its_bytes_when_it_gives_up() {
        // The unpruned-map leak: every next-hop id a peer ever names used to
        // leave an entry behind, and its queued bytes charged, for the life of
        // the process. The hop here is unreachable, so the writer gives up after
        // its dial backoff and must clean up after itself.
        let (forwarder, _app, _received) = forwarder().await;
        let source = stranger(1);
        let next = stranger(7);
        forwarder.enqueue(&next, cell(vec![next.clone()], 0, source));
        assert_eq!(live_writers(&forwarder), 1, "writer spawned");

        // DIAL_ATTEMPTS with linear backoff is ~1s; allow margin.
        for _ in 0..40 {
            if live_writers(&forwarder) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(live_writers(&forwarder), 0, "writer retired its own entry");
        assert_eq!(
            forwarder.pool.queued_bytes.load(Ordering::Relaxed),
            0,
            "a dead hop must not hold the shared byte budget"
        );
    }

    #[tokio::test]
    async fn writer_spawns_stop_at_the_ceiling() {
        // Each cell names a fresh next hop, which is how a remote peer turns an
        // unpruned writer map into unbounded tasks and dials.
        let (forwarder, _app, _received) = forwarder().await;
        let source = stranger(1);
        for seed in 0..u8::try_from(MAX_WRITERS + 8).expect("fits") {
            let next = stranger(seed.wrapping_add(100));
            if next.underlay.id == forwarder.underlay.id() {
                continue;
            }
            forwarder.enqueue(&next, cell(vec![next.clone()], 0, source.clone()));
        }
        assert!(live_writers(&forwarder) <= MAX_WRITERS);
    }
}
