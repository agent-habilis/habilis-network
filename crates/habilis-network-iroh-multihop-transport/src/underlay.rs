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
use habilis_network_iroh_transport_util::{Rung, custom_rung, is_blocked_to, remote_id_of};
use iroh::endpoint::Connection;
use iroh::endpoint::transports::Addr;
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use n0_future::StreamExt;
use n0_future::time::{Duration, Instant, MissedTickBehavior};
use tokio::sync::mpsc;

use crate::app_id::{AppId, UnderlayId};
use crate::cell::{Cell, write_cell};

use n0_future::time as n0future_time;
use std::mem;
use tokio::sync;
mod delivered;
mod forward_acceptor;
mod forwarder;

pub(crate) use delivered::Delivered;
pub(crate) use forward_acceptor::ForwardAcceptor;
pub(crate) use forwarder::Forwarder;

/// The log target of the forwarder, kept apart from the module path so that moving code does not rename it.
pub(super) const LOG_TARGET: &str = "habilis_network_iroh_multihop_transport::underlay";

/// ALPN for the multihop underlay's hop-to-hop forwarding protocol.
pub(crate) const FORWARD_ALPN: &[u8] = b"iroh-multihop/forward/2";

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

/// How long a reading of a connection's paths stands. The path moves
/// rarely, and asking for it on every cell would cost more than the cell.
const PATH_RECHECK: Duration = Duration::from_millis(250);

/// The open paths of a connection, each with whether it is the selected one.
fn paths_of(connection: &Connection) -> Vec<(TransportAddr, bool)> {
    let mut out = Vec::new();
    for path in connection.paths().iter() {
        out.push((path.remote_addr().clone(), path.is_selected()));
    }
    out
}

/// Whether a writer sends on a selected path that is not the relay.
/// Nothing selected is not trusted: the engine's own rule for payload
/// (`payload_allowed_on`) refuses until a path is selected.
fn direct_for_writer<'a>(paths: impl IntoIterator<Item = &'a (TransportAddr, bool)>) -> bool {
    paths
        .into_iter()
        .any(|(address, selected)| *selected && !matches!(address, TransportAddr::Relay(_)))
}

/// Whether a connection that we accepted has an open path that is not the relay.
/// iroh opens paths only from the dialling end. After the dialler's hole-punch
/// round prunes its redundant IP paths, the accepting end chooses no path of its
/// own on this connection: its IP path is open but not selected, and the
/// relay path too. The cells then arrive on the path that the dialler selected,
/// so the selected path here says nothing about them. The cost: a cell that really
/// came over the relay is admitted while an IP path is also open. The dialler's
/// writer gate refuses relay cells, and iroh shows no path per datagram.
fn direct_for_inbound<'a>(paths: impl IntoIterator<Item = &'a (TransportAddr, bool)>) -> bool {
    paths
        .into_iter()
        .any(|(address, _)| !matches!(address, TransportAddr::Relay(_)))
}

/// The paths that a test has not taken from this node: `blocked` names the ones it took.
///
/// A test cut changes what the selector may select, and iroh selects again only when a path
/// opens or closes. A connection that stood on a path before the cut keeps it selected, and
/// the gate would read a direct path for ever: the cut would not reach a live writer. So the
/// gate leaves the blocked paths out of what it reads.
fn unblocked(
    paths: &[(TransportAddr, bool)],
    blocked: impl Fn(&TransportAddr) -> bool,
) -> impl Iterator<Item = &(TransportAddr, bool)> {
    paths.iter().filter(move |entry| !blocked(&entry.0))
}

/// Whether a test took `path` away from the endpoint `local`: the question that the selector
/// of the underlay asks of its paths. Without the `test-hooks` of
/// `habilis-network-iroh-transport-util` nothing is ever blocked, so a build without them reads
/// every path as before.
fn blocked_by_test(local: EndpointId, path: &TransportAddr) -> bool {
    let (rung, ip_remote, remote_id) = match path {
        TransportAddr::Ip(remote) => (Rung::Ip, Some(*remote), None),
        TransportAddr::Relay(_) => (Rung::Relay, None, None),
        TransportAddr::Custom(custom) => (
            custom_rung(custom.id()),
            None,
            remote_id_of(&Addr::Custom(custom.clone())),
        ),
        _ => (Rung::Other, None, None),
    };
    is_blocked_to(local, rung, ip_remote, remote_id)
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
    let parts: Vec<String> = paths
        .into_iter()
        .map(|(address, selected)| format!("{address:?}{}", if selected { "*" } else { "" }))
        .collect();
    parts.join(" ")
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
    /// The underlay endpoint that the gate stands on: the node whose blocks a test may set.
    local: EndpointId,
    role: GateRole,
    /// The paths at the last reading. A test cut is applied to them on every call.
    reading: Option<(Instant, Vec<(TransportAddr, bool)>)>,
    /// The verdict of the last call, so that the log text is built when it changes.
    last_admitted: Option<bool>,
    /// The path list at the last refusal, so that the log says it once per change.
    last_refused_paths: Option<String>,
}

impl RelayGate {
    fn new(allow_relay: bool, local: EndpointId, role: GateRole) -> Self {
        Self {
            allow_relay,
            local,
            role,
            reading: None,
            last_admitted: None,
            last_refused_paths: None,
        }
    }

    /// The next call reads the paths of the connection again: a path event says that they changed.
    fn forget_reading(&mut self) {
        self.reading = None;
    }

    /// Whether a cell may cross `connection` now.
    fn admits(&mut self, connection: &Connection) -> bool {
        self.admits_paths(|| paths_of(connection))
    }

    /// `admits`, with the paths of the connection read by `read_paths`, which runs only when
    /// the last reading is old.
    fn admits_paths(&mut self, read_paths: impl FnOnce() -> Vec<(TransportAddr, bool)>) -> bool {
        if self.allow_relay {
            return true;
        }
        let now = Instant::now();
        let fresh =
            matches!(&self.reading, Some((at, _)) if now.duration_since(*at) < PATH_RECHECK);
        if !fresh {
            self.reading = Some((now, read_paths()));
        }
        let paths = self
            .reading
            .as_ref()
            .map_or(&[][..], |(_, paths)| paths.as_slice());
        let direct = unblocked(paths, |path| blocked_by_test(self.local, path));
        let admitted = match self.role {
            GateRole::Writer => direct_for_writer(direct),
            GateRole::Inbound => direct_for_inbound(direct),
        };
        // The cell path allocates nothing: the text of the paths is built only when the
        // reading is new or the verdict changed.
        let changed = !fresh || self.last_admitted != Some(admitted);
        self.last_admitted = Some(admitted);
        if !admitted && changed {
            let paths = path_list(paths.iter().cloned());
            if self.last_refused_paths.as_deref() != Some(paths.as_str()) {
                match self.role {
                    GateRole::Writer => {
                        tracing::debug!(%paths, "multihop underlay: no direct path is selected");
                    }
                    GateRole::Inbound => {
                        tracing::debug!(%paths, "multihop underlay: no open path is not the relay");
                    }
                }
                self.last_refused_paths = Some(paths);
            }
        }
        admitted
    }
}

/// How the gate of this node sees the connection to one next hop.
///
/// The hop is in one of three states, and only the third leaves the candidates of a cell:
///
/// - `Admit`: a selected path that is not the relay, and the gate may read it. Cells go out.
/// - `Wait`: no such path now, whatever the history of the connection: a path came and was lost, or none
///   came yet. The hop stays a candidate, behind every hop that admits. Its cells wait in the bounded queue of
///   its writer, and the wait ends when a path is selected, when the connection closes, or at the deadline.
/// - `Stuck`: the wait lasted the deadline. The hop is no candidate and is not advertised as a link, and the
///   cells that waited are dropped and counted.
#[derive(Debug, Clone, Copy)]
enum HopState {
    Admit,
    Wait { since: Instant },
    Stuck,
}

impl HopState {
    /// Whether two states are the same state, the time of a wait aside.
    fn same_kind(self, other: Self) -> bool {
        mem::discriminant(&self) == mem::discriminant(&other)
    }
}

/// How one next hop's underlay is doing under the relay rule.
///
/// The entry lives as long as the hop's writer: a retiring writer calls
/// `forget`, which clears a stuck mark too. A hop that is still on the relay is
/// then advertised again until its next writer has waited for the
/// deadline: one retry each time a writer dies, not a loop.
#[derive(Debug, Clone, Copy)]
struct HopHealth {
    /// The hop's application id: what a link-vector names.
    app_id: AppId,
    state: HopState,
}

/// A cell that is charged to the shared byte budget of the writers. The bytes go back to the budget when the
/// value is dropped, so no exit of a writer (a close, a write error, a drop at the deadline) can forget them.
#[derive(Debug)]
struct Charged {
    cell: Cell,
    // the pool is shared by every writer and every charge that it made
    pool: Arc<WriterPool>,
}

impl Drop for Charged {
    fn drop(&mut self) {
        self.pool.release(self.cell.packet.len());
    }
}

/// The outbound writer set and its shared byte budget.
///
/// Split out from [`Forwarder`] so a writer task can hold exactly what it needs
/// to retire itself and release its own queued bytes, without a self-reference
/// back into the forwarder.
#[derive(Debug, Default)]
struct WriterPool {
    /// One outbound writer channel per next-hop underlay endpoint id.
    writers: Mutex<HashMap<UnderlayId, mpsc::Sender<Charged>>>,
    /// Bytes queued across every writer.
    queued_bytes: AtomicUsize,
    /// Cells a writer dropped because its connection was not on a direct path.
    refused_on_relay: AtomicU64,
    /// The relay rule's verdict per next hop, keyed like `writers`.
    health: Mutex<HashMap<UnderlayId, HopHealth>>,
    /// Woken when the gate starts to refuse a hop, and when it admits one that it
    /// refused: the moments at which the best first hop to a peer can change.
    route_wake: Arc<sync::Notify>,
    /// Raised each time a hop changes its state (admit, wait, stuck), so a next hop that was computed from the
    /// states can tell that it is stale.
    gate_generation: AtomicU64,
    /// The connection of each live writer, keyed like `writers`, for a test that reads its paths.
    #[cfg(feature = "test-hooks")]
    connections: Mutex<HashMap<UnderlayId, Connection>>,
}

impl WriterPool {
    /// Drop `key`'s entry, but only if it is still `sender`'s. A writer that has
    /// already been replaced must not delete its successor's channel — that race
    /// is how a sibling transport grew a permanent phantom session.
    ///
    /// Says whether the entry was `sender`'s: a writer that was replaced must leave the health of its successor
    /// alone too.
    fn retire(&self, key: UnderlayId, sender: &mpsc::Sender<Charged>) -> bool {
        let mut writers = self.writers.lock().expect("writers mutex poisoned");
        let mine = writers
            .get(&key)
            .is_some_and(|live| live.same_channel(sender));
        if mine {
            writers.remove(&key);
        }
        mine
    }

    /// Charge `cell` to the byte budget. `None` when the budget is spent: the bytes are given back.
    fn charge(pool: &Arc<Self>, cell: Cell) -> Option<Charged> {
        let cost = cell.packet.len();
        let total = pool.queued_bytes.fetch_add(cost, Ordering::Relaxed) + cost;
        let charged = Charged {
            cell,
            pool: Arc::clone(pool),
        };
        (total <= FORWARD_QUEUE_BYTES).then_some(charged)
    }

    /// The number of changes of state that the hops have had.
    fn gate_generation(&self) -> u64 {
        self.gate_generation.load(Ordering::Relaxed)
    }

    fn release(&self, cost: usize) {
        self.queued_bytes.fetch_sub(cost, Ordering::Relaxed);
    }

    fn track(&self, underlay: UnderlayId, app_id: AppId) {
        let replaced = self.health.lock().expect("health mutex poisoned").insert(
            underlay,
            HopHealth {
                app_id,
                state: HopState::Admit,
            },
        );
        if replaced.is_some_and(|hop| !hop.state.same_kind(HopState::Admit)) {
            self.gate_generation.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn forget(&self, underlay: UnderlayId) {
        let removed = self
            .health
            .lock()
            .expect("health mutex poisoned")
            .remove(&underlay);
        if removed.is_some_and(|hop| !hop.state.same_kind(HopState::Admit)) {
            self.gate_generation.fetch_add(1, Ordering::Relaxed);
        }
        #[cfg(feature = "test-hooks")]
        self.connections
            .lock()
            .expect("connections mutex poisoned")
            .remove(&underlay);
    }

    /// The gate does not admit this hop just now. A hop that admitted goes into wait. A hop that has waited
    /// for the deadline is stuck, said once in the log. Gives the state of the hop after the call.
    fn note_waiting(&self, underlay: UnderlayId, stuck_after: Duration) -> HopState {
        let mut health = self.health.lock().expect("health mutex poisoned");
        let Some(hop) = health.get_mut(&underlay) else {
            // No entry: nobody advertises this hop and no cell may wait for it for ever. A writer reaches this
            // only when its entry was forgotten under it, which `retire` prevents.
            return HopState::Stuck;
        };
        match hop.state {
            HopState::Admit => {
                hop.state = HopState::Wait {
                    since: Instant::now(),
                };
                self.gate_generation.fetch_add(1, Ordering::Relaxed);
                self.route_wake.notify_one();
            }
            HopState::Wait { since } if since.elapsed() >= stuck_after => {
                hop.state = HopState::Stuck;
                self.gate_generation.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    hop = %underlay.fmt_short(),
                    app_id = %hop.app_id.fmt_short(),
                    "multihop underlay stays on the relay: this hop is not advertised as a link"
                );
            }
            HopState::Wait { .. } | HopState::Stuck => {}
        }
        hop.state
    }

    /// The gate admitted this hop: it is a link again.
    fn note_admitted(&self, underlay: UnderlayId) {
        let mut health = self.health.lock().expect("health mutex poisoned");
        let Some(hop) = health.get_mut(&underlay) else {
            return;
        };
        let before = mem::replace(&mut hop.state, HopState::Admit);
        if !before.same_kind(HopState::Admit) {
            self.gate_generation.fetch_add(1, Ordering::Relaxed);
            self.route_wake.notify_one();
        }
        if matches!(before, HopState::Stuck) {
            tracing::info!(
                hop = %underlay.fmt_short(),
                app_id = %hop.app_id.fmt_short(),
                "multihop underlay is direct again: this hop is a link"
            );
        }
    }

    /// The hops that wait for a direct path now: candidates, behind the hops that admit.
    #[cfg(test)]
    fn waiting_app_ids(&self) -> Vec<AppId> {
        let health = self.health.lock().expect("health mutex poisoned");
        let waiting = health
            .values()
            .filter(|hop| matches!(hop.state, HopState::Wait { .. }));
        waiting.map(|hop| hop.app_id).collect()
    }

    /// The hops that are stuck and the hops that wait, read under one lock: a hop that goes from wait to stuck
    /// between two reads would be in neither set and would read as admitting.
    fn gate_sets(&self) -> (Vec<AppId>, Vec<AppId>) {
        let health = self.health.lock().expect("health mutex poisoned");
        let mut stuck = Vec::new();
        let mut waiting = Vec::new();
        for hop in health.values() {
            match hop.state {
                HopState::Stuck => stuck.push(hop.app_id),
                HopState::Wait { .. } => waiting.push(hop.app_id),
                HopState::Admit => {}
            }
        }
        (stuck, waiting)
    }

    /// The hops that waited for the whole deadline: no candidates, and not advertised as links.
    fn stuck_app_ids(&self) -> Vec<AppId> {
        let health = self.health.lock().expect("health mutex poisoned");
        let stuck = health
            .values()
            .filter(|hop| matches!(hop.state, HopState::Stuck));
        stuck.map(|hop| hop.app_id).collect()
    }
}

/// A cell that this node does not send: counted, and its bytes go back to the budget with the charge.
fn drop_cell(pool: &WriterPool, charged: Charged) {
    pool.refused_on_relay.fetch_add(1, Ordering::Relaxed);
    drop(charged);
}

/// Ask the gate about the connection of `key` and tell the pool: the state of the hop after the call.
fn settle(
    gate: &mut RelayGate,
    connection: &Connection,
    pool: &WriterPool,
    key: UnderlayId,
    rule: RelayRule,
) -> HopState {
    if gate.admits(connection) {
        pool.note_admitted(key);
        HopState::Admit
    } else {
        pool.note_waiting(key, rule.stuck_after)
    }
}

/// Drain `rx` onto a single uni-stream to `dst`. Exits on dial failure or a
/// write error, retiring its own entry so the map does not accumulate one dead
/// writer per next-hop id a peer ever named, and releasing whatever it still had
/// queued so a dead hop cannot hold the shared byte budget hostage.
async fn writer_task(
    underlay: Endpoint,
    dst: EndpointAddr,
    mut rx: mpsc::Receiver<Charged>,
    handle: mpsc::Sender<Charged>,
    // the writer pool is shared by the forwarder and its accept loops
    pool: Arc<WriterPool>,
    rule: RelayRule,
) {
    let outcome = drain_to_hop(&underlay, &dst, &mut rx, &pool, rule).await;
    if let Err(error) = outcome {
        tracing::debug!(hop = %dst.id.fmt_short(), %error, "multihop underlay writer stopping");
    }
    let key = UnderlayId::new(dst.id);
    if pool.retire(key, &handle) {
        pool.forget(key);
    }
    // Whatever never made it onto the wire is still charged: the charges of the queue go back with `rx`.
    rx.close();
}

/// The loop of one writer: it sends the cells of its queue to one next hop, while the gate admits the hop.
///
/// A write that never ends is not covered: a peer that keeps its connection alive and reads nothing fills the
/// flow control of the stream, `write_cell` waits for room, and `connection.closed()` cannot end it, because the
/// write runs in the body of the arm and not in the select. The hop stays in the state "admit", its queue fills,
/// and the cells for it are dropped at the queue and counted. A hostile neighbor costs only its own hop.
async fn drain_to_hop(
    underlay: &Endpoint,
    dst: &EndpointAddr,
    rx: &mut mpsc::Receiver<Charged>,
    pool: &WriterPool,
    rule: RelayRule,
) -> anyhow::Result<()> {
    let connection = dial_with_retry(underlay, dst)
        .await
        .context("underlay dial gave up")?;
    #[cfg(feature = "test-hooks")]
    pool.connections
        .lock()
        .expect("connections mutex poisoned")
        .insert(UnderlayId::new(dst.id), connection.clone());
    let mut send = connection
        .open_uni()
        .await
        .context("open underlay uni-stream")?;
    let mut gate = RelayGate::new(rule.allow_relay, underlay.id(), GateRole::Writer);
    let key = UnderlayId::new(dst.id);
    // Looks at the path once a second even when no cell comes, so a hop that waits for a direct path is a
    // link again once one is selected, and a hop that waited for the deadline is stuck.
    let mut recheck = n0future_time::interval(Duration::from_secs(1));
    recheck.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // A path event says at once that the paths changed, so a wait ends when the path is selected and not up to
    // a second later.
    let mut path_events = connection.path_events();
    let mut events_open = true;
    // A cell that the writer took from its queue while the hop was in wait. It goes first when the wait ends.
    let mut held: Option<Charged> = None;
    let mut state = settle(&mut gate, &connection, pool, key, rule);
    loop {
        // While the hop waits, the queue is not read: the cells stay in its bounded channel.
        let reading = !matches!(state, HopState::Wait { .. });
        tokio::select! {
            // A connection that ended under us ends the writer. Without this arm a
            // dead connection with no cell in flight is read by the tick below as
            // a connection with no direct path: the hop would be marked stuck and
            // the writer would never retire.
            reason = connection.closed() => {
                anyhow::bail!("underlay connection closed: {reason}");
            }
            next = rx.recv(), if reading => {
                let Some(cell) = next else { break };
                state = settle(&mut gate, &connection, pool, key, rule);
                match state {
                    HopState::Admit => {
                        write_cell(&mut send, &cell.cell)
                            .await
                            .context("underlay write failed")?;
                    }
                    HopState::Wait { .. } => held = Some(cell),
                    // Dropped like any other loss: QUIC above retransmits, and a direct path takes over
                    // once one opens.
                    HopState::Stuck => drop_cell(pool, cell),
                }
            }
            event = path_events.next(), if events_open && !rule.allow_relay => {
                events_open = event.is_some();
                gate.forget_reading();
                state = settle(&mut gate, &connection, pool, key, rule);
            }
            _ = recheck.tick(), if !rule.allow_relay => {
                state = settle(&mut gate, &connection, pool, key, rule);
            }
        }
        match state {
            HopState::Admit => {
                if let Some(cell) = held.take() {
                    write_cell(&mut send, &cell.cell)
                        .await
                        .context("underlay write failed")?;
                }
            }
            HopState::Wait { .. } => {}
            HopState::Stuck => {
                if let Some(cell) = held.take() {
                    drop_cell(pool, cell);
                }
                while let Ok(cell) = rx.try_recv() {
                    drop_cell(pool, cell);
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
            Ok(connection) => return Some(connection),
            Err(error) => {
                tracing::trace!(hop = %dst.id.fmt_short(), attempt, %error, "underlay dial attempt failed");
                // Linear backoff; adjacent hops that are momentarily busy settle fast.
                n0future_time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{Arc, Delivered, Duration, Forwarder, MAX_WRITERS, Ordering, TransportAddr};
    use crate::app_id::{AppId, UnderlayId};
    use crate::cell::{Cell, MAX_CELL_HOPS};
    use crate::destination::Destination;
    use crate::next_hop::NextHop;
    use crate::test_support;
    use crate::topology::{LinkVector, Topology};
    use iroh::endpoint::presets;
    use iroh::endpoint::transports::{PathSelection, PathSelectionContext, PathSelector};
    use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
    use std::net::SocketAddr;
    use std::sync::RwLock;
    use tokio::sync::mpsc;

    use crate::topology;
    use iroh::protocol;
    use std::time::Instant as std_Instant;
    use tokio::{sync, time, time as tokio_time};

    /// The two ids that name a node: the application id that cells name, and the underlay id of its connection.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Hop {
        app_id: AppId,
        underlay_id: UnderlayId,
    }

    fn stranger(seed: u8) -> Hop {
        let id: EndpointId = SecretKey::from_bytes(&[seed; 32]).public();
        Hop {
            app_id: AppId::new(id),
            underlay_id: UnderlayId::new(id),
        }
    }

    /// Closes the endpoint at the end of the test, so that it does not drop open.
    fn close_at_end(endpoint: &Endpoint) {
        let endpoint = endpoint.clone();
        habilis_network_test_tracing::at_end(async move { endpoint.close().await });
    }

    /// A forwarder over a real loopback underlay, plus the delivery receiver the
    /// local transport would hold. `app_id` is a distinct key from the underlay's,
    /// as it is in production.
    async fn forwarder() -> (Forwarder, AppId, mpsc::Receiver<Delivered>) {
        let loopback: SocketAddr = "127.0.0.1:0".parse().expect("loopback addr");
        let builder = Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled);
        let bound = builder.bind_addr(loopback).expect("valid bind addr");
        let underlay: Endpoint = bound.bind().await.expect("bind underlay endpoint");
        close_at_end(&underlay);
        let app_id = AppId::new(SecretKey::from_bytes(&[99; 32]).public());
        let (inbound, received) = mpsc::channel(4);
        (
            Forwarder::new(
                underlay,
                app_id,
                inbound,
                false,
                Duration::from_secs(20),
                // the topology is shared by the forwarder and the handle
                Arc::new(RwLock::new(Topology::default())),
            ),
            app_id,
            received,
        )
    }

    /// A cell for `dst` from `src` with `hops_left` forwards left.
    fn cell(dst: AppId, src: AppId, hops_left: u8) -> Cell {
        Cell {
            dst,
            src,
            hops_left,
            packet: vec![1, 2, 3],
        }
    }

    /// Make the node `node` known to `forwarder` by a vector that it signed: the vector holds its underlay address
    /// and the neighbors that it links to.
    fn learn_vector(
        forwarder: &Forwarder,
        node: u8,
        address: &EndpointAddr,
        links: &[(AppId, u32)],
    ) {
        learn_vector_at(forwarder, node, topology::wall_clock_ms(), address, links);
    }

    /// [`learn_vector`] with the `seq` of the vector: a newer one replaces the older.
    fn learn_vector_at(
        forwarder: &Forwarder,
        node: u8,
        seq: u64,
        address: &EndpointAddr,
        links: &[(AppId, u32)],
    ) {
        let app = SecretKey::from_bytes(&[node; 32]);
        let vector = LinkVector::signed(&app, seq, address.clone(), links.to_vec());
        let mut table = forwarder.topology.write().expect("topology lock poisoned");
        table.ingest(vector);
    }

    /// The address that a node of `seed` would advertise for its underlay: its id, and no way to dial it.
    fn underlay_of(seed: u8) -> EndpointAddr {
        EndpointAddr::new(SecretKey::from_bytes(&[seed.wrapping_add(100); 32]).public())
    }

    /// Whether a writer for the underlay `key` is live.
    fn has_writer(forwarder: &Forwarder, key: UnderlayId) -> bool {
        let writers = forwarder
            .pool
            .writers
            .lock()
            .expect("writers mutex poisoned");
        writers.contains_key(&key)
    }

    fn live_writers(forwarder: &Forwarder) -> usize {
        forwarder
            .pool
            .writers
            .lock()
            .expect("writers mutex poisoned")
            .len()
    }

    #[test]
    fn a_cell_that_ends_at_us_is_delivered_locally() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // The happy path the refusals below are measured against.
            let (forwarder, app, mut received) = forwarder().await;
            let source = stranger(1);
            let subject = cell(app, source.app_id, MAX_CELL_HOPS);
            forwarder.handle_cell(subject, source.underlay_id);
            assert!(
                received.try_recv().is_ok(),
                "a cell that ends at us is delivered locally"
            );
            assert_eq!(
                forwarder.forwarded_cells(),
                0,
                "a delivery is not a forward"
            );
        });
    }

    #[test]
    fn a_cell_that_ends_at_us_reports_its_source_as_the_remote() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, app, mut received) = forwarder().await;
            let source = stranger(1);
            forwarder.handle_cell(cell(app, source.app_id, 3), source.underlay_id);
            let delivered = received.try_recv().expect("delivered");
            assert_eq!(
                Destination::decode(&delivered.remote),
                Some(Destination::new(source.app_id)),
                "the remote of the packet is the address of the node that made the cell"
            );
            assert_eq!(delivered.packet, vec![1, 2, 3], "the packet is not touched");
        });
    }

    #[test]
    fn a_cell_that_ends_at_us_is_counted_as_delivered() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, app, _received) = forwarder().await;
            let source = stranger(1);
            let subject = cell(app, source.app_id, MAX_CELL_HOPS);
            forwarder.handle_cell(subject, source.underlay_id);
            let counters = forwarder.counters();
            assert_eq!(
                (counters.delivered, counters.dropped, counters.forwarded),
                (1, 0, 0),
                "a cell that ends at us is counted as delivered"
            );
        });
    }

    #[test]
    fn a_full_inbox_drops_the_cell_and_counts_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network_iroh_multihop_transport::underlay",
                "reason=\"inbox of the local transport is full\"",
            );
            // The inbox of the fixture holds 4 cells and nothing drains it, as on a transport
            // that is never polled: the fifth and sixth cell are lost, and the counters say so.
            let (forwarder, app, _received) = forwarder().await;
            let source = stranger(1);
            for _ in 0..6 {
                let subject = cell(app, source.app_id, MAX_CELL_HOPS);
                forwarder.handle_cell(subject, source.underlay_id);
            }
            let counters = forwarder.counters();
            assert_eq!(
                (counters.delivered, counters.dropped),
                (4, 2),
                "a full inbox drops the cell and counts it"
            );
        });
    }

    #[test]
    fn a_packet_that_does_not_fit_the_buffer_is_counted_as_dropped() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network_iroh_multihop_transport::underlay",
                "multihop transport dropping packets",
            );
            let (forwarder, _app, _received) = forwarder().await;
            forwarder.note_oversized(2000, 1500);
            assert_eq!(
                forwarder.counters().dropped,
                1,
                "a packet that does not fit the buffer is counted as dropped"
            );
        });
    }

    /// 9a. A stale way cannot exist. A node sends a cell for D to D; its table then changes (its own vector drops D
    /// and a neighbor H holds D); the NEXT cell for D goes to H, with no dial and no lookup between the two.
    #[test]
    fn the_next_cell_takes_the_new_way_when_the_table_changes() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, _app, _received) = forwarder().await;
            let (source, destination, helper) = (stranger(1), stranger(2), stranger(3));
            let (destination_key, helper_key) = (
                UnderlayId::new(underlay_of(2).id),
                UnderlayId::new(underlay_of(3).id),
            );
            let now = topology::wall_clock_ms();
            learn_vector_at(
                &forwarder,
                99,
                now,
                &forwarder.underlay.addr(),
                &[(destination.app_id, 1)],
            );
            learn_vector_at(&forwarder, 2, now, &underlay_of(2), &[]);
            learn_vector_at(
                &forwarder,
                3,
                now,
                &underlay_of(3),
                &[(destination.app_id, 1)],
            );

            forwarder.handle_cell(
                cell(destination.app_id, source.app_id, MAX_CELL_HOPS),
                source.underlay_id,
            );
            {
                assert!(
                    has_writer(&forwarder, destination_key),
                    "the first cell goes to D"
                );
                assert!(!has_writer(&forwarder, helper_key), "and not to H");
            }

            // The node drops D from its own links. H still holds D.
            learn_vector_at(
                &forwarder,
                99,
                now + 1,
                &forwarder.underlay.addr(),
                &[(helper.app_id, 1)],
            );
            forwarder.handle_cell(
                cell(destination.app_id, source.app_id, MAX_CELL_HOPS),
                source.underlay_id,
            );
            assert!(
                has_writer(&forwarder, helper_key),
                "the next cell goes to H: no route was kept for D"
            );
            forwarder.underlay.close().await;
        });
    }

    /// 9b. The node at a dead link switches at once: its gate refuses D, it has H, and the cell for D goes to H.
    /// Before, the cell was refused at that node, and the origin was told by the vectors a deadline later.
    #[test]
    fn a_node_whose_gate_refuses_the_next_hop_sends_the_cell_on_another_way_at_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, _app, _received) = forwarder().await;
            let (source, destination, helper) = (stranger(1), stranger(2), stranger(3));
            let (destination_key, helper_key) = (
                UnderlayId::new(underlay_of(2).id),
                UnderlayId::new(underlay_of(3).id),
            );
            learn_vector(
                &forwarder,
                99,
                &forwarder.underlay.addr(),
                &[(destination.app_id, 1), (helper.app_id, 5)],
            );
            learn_vector(&forwarder, 2, &underlay_of(2), &[]);
            learn_vector(&forwarder, 3, &underlay_of(3), &[(destination.app_id, 1)]);
            forwarder.hold_hop_for_test(destination_key, destination.app_id);

            forwarder.handle_cell(
                cell(destination.app_id, source.app_id, MAX_CELL_HOPS),
                source.underlay_id,
            );
            assert!(
                has_writer(&forwarder, helper_key),
                "the cell goes to H, a neighbor that is not on a shortest path of this node"
            );
            assert!(
                !has_writer(&forwarder, destination_key),
                "and not to the refused hop"
            );
            forwarder.underlay.close().await;
        });
    }

    /// 9c. A loop ends at the limit. Three nodes whose tables form a ring (each believes that the next one reaches `destination`)
    /// pass one cell round and round: it is forwarded 8 times at most, one node counts a `hop_limit`, and nothing is
    /// delivered.
    #[test]
    fn a_cell_in_a_ring_of_tables_is_forwarded_eight_times_and_then_dropped() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (first, second, third) = (
                loopback_node(11, Duration::from_secs(20)).await,
                loopback_node(12, Duration::from_secs(20)).await,
                loopback_node(13, Duration::from_secs(20)).await,
            );
            let destination = stranger(50).app_id;
            // each node: its own vector (it links to the next one), and the vector of the next one (it links to D)
            let ring = [(&first, &second), (&second, &third), (&third, &first)];
            for (node, next) in ring {
                let own = LinkVector::signed(
                    &node.app_secret,
                    topology::wall_clock_ms(),
                    node.underlay_addr.clone(),
                    vec![(next.hop.app_id, 1)],
                );
                let theirs = LinkVector::signed(
                    &next.app_secret,
                    topology::wall_clock_ms(),
                    next.underlay_addr.clone(),
                    vec![(destination, 1)],
                );
                let mut topology = node
                    .forwarder
                    .topology
                    .write()
                    .expect("topology lock poisoned");
                topology.ingest(own);
                topology.ingest(theirs);
            }

            assert_eq!(
                first.forwarder.originate(destination, vec![9, 9]),
                Ok(()),
                "the first node sends"
            );

            let nodes = [&first, &second, &third];
            let total = |read: fn(&crate::MultihopCounters) -> u64| -> u64 {
                let mut sum = 0;
                for node in nodes {
                    sum += read(&node.forwarder.counters());
                }
                sum
            };
            let deadline = std_Instant::now() + Duration::from_secs(20);
            while total(|counters| counters.hop_limit) == 0 && std_Instant::now() < deadline {
                time::sleep(Duration::from_millis(50)).await;
            }

            assert_eq!(
                total(|counters| counters.hop_limit),
                1,
                "one node dropped the cell at the limit"
            );
            assert_eq!(
                total(|counters| counters.forwarded),
                u64::from(MAX_CELL_HOPS),
                "the cell was forwarded as many times as the limit allows, and no more"
            );
            assert_eq!(
                total(|counters| counters.delivered),
                0,
                "nothing was delivered"
            );
        });
    }

    /// A cell for a node that no neighbor of ours reaches is neither delivered nor forwarded: relaying it would
    /// spend our bandwidth on a stranger's behalf. It is counted as `no_next_hop`.
    #[test]
    fn a_cell_for_a_node_that_no_neighbor_reaches_is_dropped_and_counted() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, _app, mut received) = forwarder().await;
            let source = stranger(1);
            let subject = cell(stranger(2).app_id, source.app_id, MAX_CELL_HOPS);
            forwarder.handle_cell(subject, source.underlay_id);
            assert!(
                received.try_recv().is_err(),
                "a cell for another node is not delivered"
            );
            assert_eq!(live_writers(&forwarder), 0, "no writer, no dial, no bytes");
            let counters = forwarder.counters();
            assert_eq!(
                (counters.no_next_hop, counters.forwarded),
                (1, 0),
                "counted as no_next_hop, not as forwarded"
            );
        });
    }

    /// A cell that has no forward left is dropped at a node that is not its destination, and a cell that claims
    /// more forwards than the limit is refused. Both are `hop_limit`: this is what ends a loop.
    #[test]
    fn a_cell_with_no_forward_left_or_above_the_limit_is_dropped_as_hop_limit() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, _app, mut received) = forwarder().await;
            let source = stranger(1);
            let other = stranger(2).app_id;
            forwarder.handle_cell(cell(other, source.app_id, 0), source.underlay_id);
            forwarder.handle_cell(
                cell(other, source.app_id, MAX_CELL_HOPS + 1),
                source.underlay_id,
            );
            assert!(received.try_recv().is_err(), "nothing is delivered");
            let counters = forwarder.counters();
            assert_eq!(
                (counters.hop_limit, counters.forwarded, counters.no_next_hop),
                (2, 0, 0),
                "both are hop_limit, and neither reached the choice of a next hop"
            );
        });
    }

    /// A cell that reaches this node with 0 forwards left is still delivered when it is for this node.
    #[test]
    fn a_cell_for_us_with_no_forward_left_is_delivered() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, app, mut received) = forwarder().await;
            let source = stranger(1);
            forwarder.handle_cell(cell(app, source.app_id, 0), source.underlay_id);
            assert!(
                received.try_recv().is_ok(),
                "the last forward brings the cell to its destination"
            );
        });
    }

    /// The best next hop is the node that the cell came from: the tables disagree, so the cell is dropped and the
    /// second best is not taken. This is what a loop between 2 nodes looks like.
    #[test]
    fn a_cell_is_not_sent_back_to_the_hop_it_came_from() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, app, mut received) = forwarder().await;
            let (upstream, destination) = (stranger(1), stranger(2));
            // This node links to its upstream, and the upstream alone reaches the destination.
            learn_vector(&forwarder, 1, &underlay_of(1), &[(destination.app_id, 1)]);
            learn_vector(
                &forwarder,
                99,
                &forwarder.underlay.addr(),
                &[(upstream.app_id, 1)],
            );
            let _ = app;
            let table = forwarder.topology.read().expect("topology lock poisoned");
            let advertised = table.underlay_of(upstream.app_id);
            let from: EndpointId = advertised.expect("the vector of the upstream is held").id;
            drop(table);
            forwarder.handle_cell(
                cell(destination.app_id, upstream.app_id, MAX_CELL_HOPS),
                UnderlayId::new(from),
            );
            assert!(received.try_recv().is_err(), "not delivered");
            assert_eq!(live_writers(&forwarder), 0, "no writer is spawned");
            let counters = forwarder.counters();
            assert_eq!(
                (counters.turned_back, counters.forwarded),
                (1, 0),
                "counted as turned back, not as forwarded"
            );
        });
    }

    #[test]
    fn a_cell_passing_through_us_is_queued_for_the_next_hop() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, _app, mut received) = forwarder().await;
            let (source, next) = (stranger(1), stranger(5));
            // This node links to the next node, which has a vector, and the next node is the destination.
            learn_vector(
                &forwarder,
                99,
                &forwarder.underlay.addr(),
                &[(next.app_id, 1)],
            );
            learn_vector(&forwarder, 5, &underlay_of(5), &[]);
            let subject = cell(next.app_id, source.app_id, MAX_CELL_HOPS);
            forwarder.handle_cell(subject, source.underlay_id);
            assert!(received.try_recv().is_err(), "not ours to deliver");
            assert_eq!(
                live_writers(&forwarder),
                1,
                "a cell passing through us is queued for the next hop"
            );
            assert_eq!(
                forwarder.forwarded_cells(),
                1,
                "one cell is forwarded to the next hop"
            );
        });
    }

    #[test]
    fn a_refused_cell_is_not_counted_as_forwarded() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, _app, _received) = forwarder().await;
            let source = stranger(1);
            let subject = cell(stranger(2).app_id, source.app_id, MAX_CELL_HOPS);
            forwarder.handle_cell(subject, source.underlay_id);
            assert_eq!(
                forwarder.forwarded_cells(),
                0,
                "a refused cell is not counted as forwarded"
            );
        });
    }

    /// A node whose underlay can only use the relay, as a forwarder with its
    /// accept side running.
    struct RelayNode {
        // the test harness shares the forwarder with its writers
        forwarder: Arc<Forwarder>,
        hop: Hop,
        /// The key of the application endpoint, which signs the link vector of the node.
        app_secret: SecretKey,
        /// The address that the node would advertise for its underlay.
        underlay_addr: EndpointAddr,
        received: mpsc::Receiver<Delivered>,
        _router: protocol::Router,
    }

    impl RelayNode {
        /// Make `other` known to this node, as the link vector of `other` would: signed by
        /// its application key, with its underlay address. A route names a hop by ids, and
        /// the forwarder dials the address of the topology.
        fn learns(&self, other: &RelayNode) {
            let vector = LinkVector::signed(
                &other.app_secret,
                topology::wall_clock_ms(),
                other.underlay_addr.clone(),
                Vec::new(),
            );
            self.forwarder
                .topology
                .write()
                .expect("topology lock poisoned")
                .ingest(vector);
        }
    }

    async fn relay_node(seed: u8, url: &iroh::RelayUrl, allow_relay: bool) -> RelayNode {
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .relay_mode(RelayMode::custom([url.clone()]));
        let underlay = builder
            .clear_ip_transports()
            .bind()
            .await
            .expect("bind a relay-only underlay");
        close_at_end(&underlay);
        tokio_time::timeout(Duration::from_secs(10), underlay.online())
            .await
            .expect("the underlay reaches the relay");
        let app_secret = SecretKey::from_bytes(&[seed.wrapping_add(100); 32]);
        let app_id = AppId::new(app_secret.public());
        let (inbound, received) = mpsc::channel(8);
        // the forwarder is shared with the accept loop the test runs
        let forwarder = Arc::new(Forwarder::new(
            underlay.clone(),
            app_id,
            inbound,
            allow_relay,
            Duration::from_millis(300),
            // the topology is shared with the forwarder
            Arc::new(RwLock::new(Topology::default())),
        ));
        let router = protocol::Router::builder(underlay.clone())
            .accept(
                super::FORWARD_ALPN,
                super::ForwardAcceptor::new(Arc::clone(&forwarder)),
            )
            .spawn();
        let hop = Hop {
            app_id,
            underlay_id: UnderlayId::new(underlay.id()),
        };
        RelayNode {
            forwarder,
            hop,
            app_secret,
            underlay_addr: underlay.addr(),
            received,
            _router: router,
        }
    }

    /// Send one cell from `from` to `to` over their underlays and say whether it
    /// arrived within a few seconds.
    async fn cell_arrives(from: &RelayNode, to: &mut RelayNode) -> bool {
        from.learns(to);
        let subject = Cell {
            dst: to.hop.app_id,
            src: from.hop.app_id,
            hops_left: MAX_CELL_HOPS,
            packet: vec![7, 7, 7],
        };
        // Retried: the first attempts can find the connection still being set up.
        for _ in 0..6 {
            from.forwarder.enqueue(to.hop.app_id, subject.clone());
            if tokio_time::timeout(Duration::from_millis(500), to.received.recv())
                .await
                .is_ok_and(|delivered| delivered.is_some())
            {
                return true;
            }
        }
        false
    }

    #[test]
    fn the_relay_carries_cells_when_the_mesh_lets_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (url, _server) = test_support::relay_server().await;
            let from = relay_node(1, &url, true).await;
            let mut to = relay_node(2, &url, true).await;
            assert!(
                cell_arrives(&from, &mut to).await,
                "relay payload is allowed"
            );
        });
    }

    #[test]
    fn a_cell_is_not_sent_on_a_relay_selected_path() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network_iroh_multihop_transport::underlay",
                "multihop underlay stays on the relay: this hop is not advertised as a link",
            );
            let (url, _server) = test_support::relay_server().await;
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
        });
    }

    #[test]
    fn a_cell_that_arrives_on_a_relay_selected_path_is_dropped() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network_iroh_multihop_transport::underlay",
                "reason=\"cell arrived over the relay\"",
            );
            let (url, _server) = test_support::relay_server().await;
            let from = relay_node(5, &url, true).await;
            let mut to = relay_node(6, &url, false).await;
            assert!(
                !cell_arrives(&from, &mut to).await,
                "the receiver refuses the relay"
            );
            assert!(
                to.forwarder.dropped.load(Ordering::Relaxed) > 0,
                "a cell on a relay-selected path is dropped"
            );
        });
    }

    #[test]
    fn a_hop_that_stays_on_the_relay_becomes_stuck() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network_iroh_multihop_transport::underlay",
                "multihop underlay stays on the relay: this hop is not advertised as a link",
            );
            let (url, _server) = test_support::relay_server().await;
            let from = relay_node(7, &url, false).await;
            let mut to = relay_node(8, &url, true).await;
            assert!(
                !cell_arrives(&from, &mut to).await,
                "a hop that stays on the relay becomes stuck"
            );
            // Refused for longer than the deadline: no longer a link.
            let deadline = std_Instant::now() + Duration::from_secs(5);
            while from.forwarder.stuck_hops().is_empty() && std_Instant::now() < deadline {
                tokio_time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(
                from.forwarder.stuck_hops(),
                vec![to.hop.app_id],
                "the stuck hop is the one that stayed on the relay"
            );
        });
    }

    /// The port of the IP address that `node` advertises, which a test blocks to cut the direct path to it.
    fn ip_port_of(node: &RelayNode) -> u16 {
        node.underlay_addr
            .ip_addrs()
            .next()
            .expect("a loopback address")
            .port()
    }

    /// The writer of a node that has no direct path to its hop keeps the cells of that hop. The hop waits, a cell
    /// is neither dropped nor counted as refused, and the cell goes out when a path is admitted. Before the wait
    /// state the writer dropped the cell at once, and QUIC above had to send it again.
    #[test]
    fn a_cell_for_a_hop_in_wait_stays_in_the_queue_and_arrives_when_a_path_is_admitted() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let from = loopback_node(41, Duration::from_secs(30)).await;
            let mut to = loopback_node(42, Duration::from_secs(30)).await;
            from.learns(&to);
            let local = from.forwarder.underlay.id();
            habilis_network_iroh_transport_util::block_ip_to(local, [ip_port_of(&to)]);

            from.forwarder.enqueue(
                to.hop.app_id,
                cell(to.hop.app_id, from.hop.app_id, MAX_CELL_HOPS),
            );
            let early = tokio_time::timeout(Duration::from_millis(1500), to.received.recv()).await;
            assert!(
                early.is_err(),
                "no path is admitted: the cell does not cross"
            );
            assert_eq!(
                from.forwarder.pool.refused_on_relay.load(Ordering::Relaxed),
                0,
                "and it was not dropped: it waits"
            );
            assert_eq!(
                from.forwarder.pool.waiting_app_ids(),
                vec![to.hop.app_id],
                "the hop is in wait, and not stuck"
            );
            assert!(
                from.forwarder.stuck_hops().is_empty(),
                "before the deadline"
            );

            habilis_network_iroh_transport_util::block_ip_to(local, []);
            let late = tokio_time::timeout(Duration::from_secs(5), to.received.recv()).await;
            assert!(
                late.is_ok_and(|delivered| delivered.is_some()),
                "the path is admitted: the cell that waited goes out"
            );
            assert!(
                from.forwarder.pool.waiting_app_ids().is_empty(),
                "the hop admits again"
            );
        });
    }

    /// A writer that was replaced does not retire its successor: `retire` says that the entry is not its own, so
    /// the health of the successor stays. A hop with no entry in the health map is stuck, and not a wait with no end.
    #[test]
    fn a_replaced_writer_leaves_the_entry_of_its_successor_and_an_untracked_hop_is_stuck() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (hop, app) = (stranger(61).underlay_id, stranger(62).app_id);
            let pool = super::WriterPool::default();
            let (old, _old_rx) = mpsc::channel(1);
            let (new, _new_rx) = mpsc::channel(1);
            pool.writers
                .lock()
                .expect("writers mutex poisoned")
                .insert(hop, new.clone());
            pool.track(hop, app);

            assert!(!pool.retire(hop, &old), "the entry is not the old writer's");
            assert!(
                pool.writers
                    .lock()
                    .expect("writers mutex poisoned")
                    .contains_key(&hop),
                "the successor stays"
            );
            assert!(pool.retire(hop, &new), "the successor retires itself");

            pool.forget(hop);
            assert!(
                matches!(
                    pool.note_waiting(hop, Duration::from_mins(1)),
                    super::HopState::Stuck
                ),
                "a hop with no entry never waits for ever"
            );
        });
    }

    /// One try of the scenario below with the nodes of `seed`: the bytes still charged after the connection of a
    /// writer that holds a cell in wait closed. `None` when the writer did not hold the cell (the one-second tick
    /// can put the hop in wait before the cell comes, and the cell then stays in the channel).
    async fn bytes_charged_after_a_close_with_a_held_cell(seed: u8) -> Option<usize> {
        let from = loopback_node(seed, Duration::from_secs(30)).await;
        let mut to = loopback_node(seed + 1, Duration::from_secs(30)).await;
        assert!(cell_arrives(&from, &mut to).await, "the hop admits first");
        let local = from.forwarder.underlay.id();
        // The writer reads its queue while the hop admits. The cut puts the hop in wait on the next cell, and
        // that cell is the one that the writer holds.
        habilis_network_iroh_transport_util::block_ip_to(local, [ip_port_of(&to)]);
        from.forwarder.enqueue(
            to.hop.app_id,
            cell(to.hop.app_id, from.hop.app_id, MAX_CELL_HOPS),
        );
        tokio_time::sleep(Duration::from_millis(300)).await;
        let free_places = {
            let writers = from
                .forwarder
                .pool
                .writers
                .lock()
                .expect("writers mutex poisoned");
            writers.get(&to.hop.underlay_id).map(mpsc::Sender::capacity)
        };
        let held = free_places == Some(super::WRITER_QUEUE);
        if held {
            to.forwarder.underlay.close().await;
            let deadline = std_Instant::now() + Duration::from_secs(8);
            while from.forwarder.pool.queued_bytes.load(Ordering::Relaxed) > 0
                && std_Instant::now() < deadline
            {
                tokio_time::sleep(Duration::from_millis(100)).await;
            }
        }
        let charged = from.forwarder.pool.queued_bytes.load(Ordering::Relaxed);
        habilis_network_iroh_transport_util::block_ip_to(local, []);
        held.then_some(charged)
    }

    /// A cell that the writer took from its queue while the hop waits is charged to the shared budget, and the
    /// connection then dies: the bytes go back. A writer that held the cell as a local and ended on the close of
    /// the connection kept the bytes for ever, and the budget of the node only shrank.
    #[test]
    fn the_cell_that_a_writer_holds_in_wait_gives_its_bytes_back_when_the_connection_closes() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            for attempt in 0..6_u8 {
                if let Some(charged) =
                    bytes_charged_after_a_close_with_a_held_cell(47 + 2 * attempt).await
                {
                    assert_eq!(
                        charged, 0,
                        "the writer ended with its connection: no byte stays charged"
                    );
                    return;
                }
            }
            panic!("the writer never held a cell in wait in 6 tries");
        });
    }

    /// A wait that lasts the deadline makes the hop stuck: it leaves the candidates, and the cells that waited
    /// are dropped, counted, and give their bytes back to the budget.
    #[test]
    fn a_wait_that_lasts_the_deadline_makes_the_hop_stuck_and_drops_its_queue() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network_iroh_multihop_transport::underlay",
                "multihop underlay stays on the relay: this hop is not advertised as a link",
            );
            let from = loopback_node(43, Duration::from_secs(2)).await;
            let to = loopback_node(44, Duration::from_secs(2)).await;
            from.learns(&to);
            let local = from.forwarder.underlay.id();
            habilis_network_iroh_transport_util::block_ip_to(local, [ip_port_of(&to)]);

            for _ in 0..2 {
                from.forwarder.enqueue(
                    to.hop.app_id,
                    cell(to.hop.app_id, from.hop.app_id, MAX_CELL_HOPS),
                );
            }
            tokio_time::sleep(Duration::from_millis(500)).await;
            assert_eq!(
                from.forwarder.pool.refused_on_relay.load(Ordering::Relaxed),
                0,
                "before the deadline nothing is dropped"
            );
            assert_eq!(
                from.forwarder.pool.queued_bytes.load(Ordering::Relaxed),
                6,
                "the 2 cells wait, 3 bytes each"
            );

            let deadline = std_Instant::now() + Duration::from_secs(8);
            while from.forwarder.stuck_hops().is_empty() && std_Instant::now() < deadline {
                tokio_time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(
                from.forwarder.stuck_hops(),
                vec![to.hop.app_id],
                "the hop is stuck at the deadline"
            );
            assert_eq!(
                from.forwarder.pool.refused_on_relay.load(Ordering::Relaxed),
                2,
                "the cells that waited are dropped and counted"
            );
            assert_eq!(
                from.forwarder.pool.queued_bytes.load(Ordering::Relaxed),
                0,
                "and their bytes are back in the budget"
            );
            habilis_network_iroh_transport_util::block_ip_to(local, []);
        });
    }

    /// The queue of a hop in wait is bounded: a cell past the bound is dropped and counted, and the live writer
    /// is not replaced by a new one.
    #[test]
    fn the_queue_of_a_hop_in_wait_is_bounded_and_its_writer_stays() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let from = loopback_node(45, Duration::from_secs(30)).await;
            let to = loopback_node(46, Duration::from_secs(30)).await;
            from.learns(&to);
            let local = from.forwarder.underlay.id();
            habilis_network_iroh_transport_util::block_ip_to(local, [ip_port_of(&to)]);
            from.forwarder.enqueue(
                to.hop.app_id,
                cell(to.hop.app_id, from.hop.app_id, MAX_CELL_HOPS),
            );
            // The writer does not read its queue while the hop waits, so the first cell is in the channel too.
            tokio_time::sleep(Duration::from_millis(1500)).await;

            let extra = 20;
            for _ in 0..(super::WRITER_QUEUE + extra) {
                from.forwarder.enqueue(
                    to.hop.app_id,
                    cell(to.hop.app_id, from.hop.app_id, MAX_CELL_HOPS),
                );
            }
            assert_eq!(
                from.forwarder.dropped.load(Ordering::Relaxed),
                u64::try_from(extra + 1).expect("small"),
                "the cells past the bound are dropped and counted: the first cell takes one place"
            );
            assert_eq!(live_writers(&from.forwarder), 1, "one writer, not replaced");
            assert_eq!(
                from.forwarder.pool.refused_on_relay.load(Ordering::Relaxed),
                0,
                "the cells inside the bound still wait"
            );
            habilis_network_iroh_transport_util::block_ip_to(local, []);
        });
    }

    /// A node whose only neighbor waits for a path has a next hop: the origin sends, it does not refuse. A stuck
    /// neighbor is no next hop.
    #[test]
    fn the_origin_sends_toward_a_hop_in_wait_and_refuses_toward_a_stuck_hop() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network_iroh_multihop_transport::underlay",
                "multihop underlay stays on the relay: this hop is not advertised as a link",
            );
            let (forwarder, _app, _received) = forwarder().await;
            let neighbor = stranger(2);
            learn_vector(
                &forwarder,
                99,
                &forwarder.underlay.addr(),
                &[(neighbor.app_id, 1)],
            );
            learn_vector(&forwarder, 2, &underlay_of(2), &[]);
            let key = UnderlayId::new(underlay_of(2).id);

            forwarder.hold_hop_for_test(key, neighbor.app_id);
            assert!(
                forwarder.originate(neighbor.app_id, vec![1]).is_ok(),
                "the only neighbor waits for a path: the origin sends"
            );
            assert_eq!(
                forwarder.counters().no_next_hop,
                0,
                "and it counts no missing next hop"
            );

            forwarder.stick_hop_for_test(key, neighbor.app_id);
            assert!(
                forwarder.originate(neighbor.app_id, vec![1]).is_err(),
                "a stuck neighbor is no next hop"
            );
            assert_eq!(forwarder.counters().no_next_hop, 1, "counted once");
            forwarder.underlay.close().await;
        });
    }

    #[test]
    fn the_path_list_marks_the_selected_path_with_a_star() {
        let _guard = ::habilis_network_test_tracing::init();
        let ip = TransportAddr::Ip("127.0.0.1:9".parse().expect("an address"));
        let relay = TransportAddr::Relay("http://127.0.0.1:1".parse().expect("a relay url"));
        let list = super::path_list([(relay, true), (ip, false)]);
        assert!(list.starts_with("Relay("), "{list}");
        assert!(list.ends_with(")* Ip(127.0.0.1:9)"), "{list}");
    }

    /// Whether `wake` holds a wake-up now.
    async fn woke(wake: &sync::Notify) -> bool {
        tokio_time::timeout(Duration::from_millis(20), wake.notified())
            .await
            .is_ok()
    }

    /// A cell is queued on the writer of the address that the vector of the next hop signed, and on no other.
    #[test]
    fn a_cell_is_queued_on_the_writer_of_the_address_that_the_vector_signed() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, _app, _received) = forwarder().await;
            let neighbor = stranger(5);
            let signed: EndpointAddr =
                EndpointAddr::new(SecretKey::from_bytes(&[124; 32]).public())
                    .with_ip_addr("10.0.0.9:4000".parse().expect("an address"));
            learn_vector(&forwarder, 5, &signed, &[]);

            forwarder.enqueue(
                neighbor.app_id,
                cell(neighbor.app_id, stranger(1).app_id, 3),
            );
            assert!(
                has_writer(&forwarder, UnderlayId::new(signed.id)),
                "the writer is keyed by the underlay id that the vector signed"
            );
            assert_eq!(live_writers(&forwarder), 1, "no other writer");
            forwarder.underlay.close().await;
        });
    }

    /// A neighbor that has no vector has no address that we can dial: a cell for it is dropped with its bytes
    /// released, and no writer is spawned.
    #[test]
    fn a_cell_for_a_next_hop_without_a_vector_is_dropped_and_releases_its_bytes() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network_iroh_multihop_transport::underlay",
                "reason=\"next hop has no vector\"",
            );
            let (forwarder, _app, _received) = forwarder().await;
            let stranger_hop = stranger(7);

            forwarder.enqueue(
                stranger_hop.app_id,
                cell(stranger_hop.app_id, stranger(1).app_id, 3),
            );

            assert_eq!(live_writers(&forwarder), 0, "no writer is spawned");
            assert_eq!(
                forwarder.pool.queued_bytes.load(Ordering::Relaxed),
                0,
                "the bytes of the cell are released"
            );
            assert_eq!(forwarder.counters().dropped, 1, "the drop is counted");
            forwarder.underlay.close().await;
        });
    }

    /// A neighbor that this node links to and that has no vector yet is no candidate: this node cannot dial it.
    /// With its vector it is the next hop, and with a longer way open the next best is taken in the meantime.
    #[test]
    fn a_neighbor_without_a_vector_is_no_candidate_until_its_vector_is_here() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, _app, _received) = forwarder().await;
            let (near, far, dst) = (stranger(5), stranger(6), stranger(8));
            // This node links to `near` (cost 1) and to `far` (cost 9). `near` is the destination itself and has no
            // vector. `far` has one, and reaches the destination.
            learn_vector(
                &forwarder,
                99,
                &forwarder.underlay.addr(),
                &[(near.app_id, 1), (far.app_id, 9)],
            );
            learn_vector(&forwarder, 6, &underlay_of(6), &[(near.app_id, 1)]);

            assert_eq!(
                forwarder.next_hop(near.app_id, None),
                NextHop::Forward(far.app_id),
                "the near neighbor has no vector, so the way through the far one is taken"
            );

            learn_vector(&forwarder, 5, &underlay_of(5), &[]);
            assert_eq!(
                forwarder.next_hop(near.app_id, None),
                NextHop::Forward(near.app_id),
                "with its vector the near neighbor is the next hop"
            );
            let _ = dst;
            forwarder.underlay.close().await;
        });
    }

    /// A packet that starts here: with no next hop the send is refused and counted, and with one the cell is
    /// queued with the whole limit of forwards.
    #[test]
    fn a_packet_that_starts_here_is_queued_with_the_full_limit_or_refused() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (forwarder, app, _received) = forwarder().await;
            let neighbor = stranger(5);

            assert_eq!(
                forwarder.originate(neighbor.app_id, vec![1]),
                Err(super::forwarder::NotSent::NoNextHop),
                "no vector, no way"
            );
            assert_eq!(
                forwarder.counters().no_next_hop,
                1,
                "the refusal is counted"
            );
            assert_eq!(
                forwarder.originate(app, vec![1]),
                Err(super::forwarder::NotSent::ToSelf),
                "a packet to ourselves needs no transport"
            );

            learn_vector(
                &forwarder,
                99,
                &forwarder.underlay.addr(),
                &[(neighbor.app_id, 1)],
            );
            learn_vector(&forwarder, 5, &underlay_of(5), &[]);
            assert_eq!(
                forwarder.originate(neighbor.app_id, vec![1, 2]),
                Ok(()),
                "a way exists"
            );
            assert_eq!(
                live_writers(&forwarder),
                1,
                "the cell is queued for the neighbor"
            );
            forwarder.underlay.close().await;
        });
    }

    #[test]
    fn the_pool_wakes_at_the_first_refusal_of_a_hop_and_at_its_recovery() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (hop, app) = (stranger(13).underlay_id, stranger(14).app_id);
            let pool = super::WriterPool::default();
            let wake = Arc::clone(&pool.route_wake);
            pool.track(hop, app);
            assert!(!woke(&wake).await, "a hop that was never refused");
            pool.note_admitted(hop);
            assert!(!woke(&wake).await, "an admitted hop that was not refused");

            pool.note_waiting(hop, Duration::from_mins(1));
            assert!(woke(&wake).await, "the first refusal");
            pool.note_waiting(hop, Duration::from_mins(1));
            pool.note_waiting(hop, Duration::from_mins(1));
            assert!(!woke(&wake).await, "a refusal that goes on is not news");

            pool.note_admitted(hop);
            assert!(woke(&wake).await, "the recovery of a refused hop");
            pool.note_admitted(hop);
            assert!(!woke(&wake).await, "an admitted hop that stays admitted");
        });
    }

    /// The generation of the refused set rises at the first refusal of a hop, at its recovery, and when a
    /// refused hop is forgotten or tracked again; a refusal that goes on, and an admitted hop, change nothing.
    #[test]
    fn the_refusing_generation_rises_when_the_refused_set_changes() {
        let _guard = ::habilis_network_test_tracing::init();
        let (hop, app) = (stranger(21).underlay_id, stranger(22).app_id);
        let pool = super::WriterPool::default();
        let mut seen = pool.gate_generation();
        let mut moved = |watched: &super::WriterPool| {
            let now = watched.gate_generation();
            let moved = now != seen;
            seen = now;
            moved
        };

        pool.track(hop, app);
        assert!(!moved(&pool), "a hop that was tracked and never refused");
        pool.note_admitted(hop);
        assert!(!moved(&pool), "an admitted hop that was not refused");
        pool.note_waiting(hop, Duration::from_mins(1));
        assert!(moved(&pool), "the first refusal");
        pool.note_waiting(hop, Duration::from_mins(1));
        assert!(!moved(&pool), "a refusal that goes on");
        pool.note_admitted(hop);
        assert!(moved(&pool), "the recovery");
        pool.note_waiting(hop, Duration::from_mins(1));
        assert!(moved(&pool), "a second first refusal");
        pool.forget(hop);
        assert!(
            moved(&pool),
            "a refused hop that is forgotten leaves the set"
        );
        pool.track(hop, app);
        pool.note_waiting(hop, Duration::from_mins(1));
        assert!(moved(&pool), "refused again");
        pool.track(hop, app);
        assert!(
            moved(&pool),
            "a refused hop that is tracked again starts clean"
        );
    }

    #[test]
    fn a_stuck_hop_is_a_link_again_once_it_is_admitted() {
        let _guard = ::habilis_network_test_tracing::init();
        ::habilis_network_test_tracing::expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "multihop underlay stays on the relay: this hop is not advertised as a link",
        );
        let (hop, app) = (stranger(11).underlay_id, stranger(12).app_id);
        let pool = super::WriterPool::default();
        pool.track(hop, app);
        pool.note_waiting(hop, Duration::ZERO);
        assert!(
            pool.stuck_app_ids().is_empty(),
            "the first call only starts the wait"
        );
        pool.note_waiting(hop, Duration::ZERO);
        assert_eq!(pool.stuck_app_ids(), vec![app], "waited for the deadline");
        pool.note_admitted(hop);
        assert!(pool.stuck_app_ids().is_empty(), "admitted: a link again");
        pool.note_waiting(hop, Duration::from_mins(1));
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
        // trait object: the selector is chosen per test
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
        close_at_end(&underlay);
        let app_secret = SecretKey::from_bytes(&[seed.wrapping_add(100); 32]);
        let app_id = AppId::new(app_secret.public());
        let (inbound, received) = mpsc::channel(8);
        // the forwarder is shared with the accept loop the test runs
        let forwarder = Arc::new(Forwarder::new(
            underlay.clone(),
            app_id,
            inbound,
            false,
            stuck_after,
            // the topology is shared with the forwarder
            Arc::new(RwLock::new(Topology::default())),
        ));
        let router = protocol::Router::builder(underlay.clone())
            .accept(
                super::FORWARD_ALPN,
                super::ForwardAcceptor::new(Arc::clone(&forwarder)),
            )
            .spawn();
        let hop = Hop {
            app_id,
            underlay_id: UnderlayId::new(underlay.id()),
        };
        RelayNode {
            forwarder,
            hop,
            app_secret,
            underlay_addr: underlay.addr(),
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
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            direct_for_inbound(&[(ip(9), false), (relay(), false)]),
            "an IP path in backup beside the relay in backup"
        );
        assert!(
            direct_for_inbound(&[(ip(9), true), (relay(), false)]),
            "an accepted connection is direct when any open path is not the relay"
        );
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
        assert!(
            !direct_for_writer(&[(ip(9), false), (relay(), false)]),
            "a writer with only relay paths is not direct"
        );
        assert!(
            direct_for_writer(&[(ip(9), true), (relay(), false)]),
            "a writer with one open direct path is direct"
        );
    }

    /// A test cut takes a path away from the selector, and iroh does not select again for a
    /// connection that already stands on it. The gate must read the cut itself: a path that the
    /// test blocked is not a direct path, so that a live writer gives the hop up.
    #[test]
    fn a_selected_direct_path_that_a_test_blocked_is_not_a_direct_path() {
        use super::{direct_for_writer, unblocked};
        let _guard = ::habilis_network_test_tracing::init();
        let paths = vec![(ip(9), true), (relay(), false)];
        assert!(
            direct_for_writer(&paths),
            "before the cut the writer is admitted"
        );
        assert!(
            !direct_for_writer(unblocked(&paths, |path| *path == ip(9))),
            "the blocked path is gone, and nothing direct is selected"
        );
        assert!(
            unblocked(&paths, |path| *path == ip(9)).any(|(path, _)| *path == relay()),
            "the relay stays in the list"
        );
    }

    #[test]
    fn the_accepting_end_gives_up_a_path_that_a_test_blocked_too() {
        use super::{direct_for_inbound, unblocked};
        let _guard = ::habilis_network_test_tracing::init();
        let paths = vec![(ip(9), false), (relay(), false)];
        assert!(
            direct_for_inbound(&paths),
            "the accepting end keeps a path that is direct"
        );
        assert!(
            !direct_for_inbound(unblocked(&paths, |path| matches!(
                path,
                TransportAddr::Ip(_)
            ))),
            "only the relay is left, and it is not direct"
        );
    }

    #[test]
    fn a_path_that_no_test_blocked_is_kept() {
        let _guard = ::habilis_network_test_tracing::init();
        let paths = vec![(ip(9), true), (relay(), false)];
        let kept: Vec<_> = super::unblocked(&paths, |_| false).cloned().collect();
        assert_eq!(kept, paths, "a path that no test blocked is kept");
    }

    #[test]
    fn an_ip_path_that_a_test_blocked_for_this_node_is_blocked() {
        let _guard = ::habilis_network_test_tracing::init();
        let local = SecretKey::from_bytes(&[141; 32]).public();
        let other = SecretKey::from_bytes(&[142; 32]).public();
        habilis_network_iroh_transport_util::block_ip_to(local, [9]);
        assert!(super::blocked_by_test(local, &ip(9)), "the blocked port");
        assert!(!super::blocked_by_test(local, &ip(10)), "another port");
        assert!(!super::blocked_by_test(local, &relay()), "the relay");
        assert!(!super::blocked_by_test(other, &ip(9)), "another node");
        habilis_network_iroh_transport_util::block_ip_to(local, []);
        assert!(
            !super::blocked_by_test(local, &ip(9)),
            "an empty set clears"
        );
    }

    #[test]
    fn a_webrtc_path_that_a_test_blocked_toward_one_remote_is_blocked() {
        use habilis_network_iroh_transport_util::{Rung, WEBRTC_TRANSPORT_ID, block_rung_to};
        use iroh_base::CustomAddr;
        let _guard = ::habilis_network_test_tracing::init();
        let local = SecretKey::from_bytes(&[143; 32]).public();
        let cut = SecretKey::from_bytes(&[144; 32]).public();
        let kept = SecretKey::from_bytes(&[145; 32]).public();
        let webrtc = |remote: EndpointId| {
            TransportAddr::Custom(CustomAddr::from_parts(
                WEBRTC_TRANSPORT_ID,
                remote.as_bytes(),
            ))
        };
        block_rung_to(local, Rung::WebRtc, cut, true);
        assert!(
            super::blocked_by_test(local, &webrtc(cut)),
            "the cut remote"
        );
        assert!(
            !super::blocked_by_test(local, &webrtc(kept)),
            "another remote"
        );
        assert!(!super::blocked_by_test(local, &ip(9)), "another rung");
        block_rung_to(local, Rung::WebRtc, cut, false);
        assert!(!super::blocked_by_test(local, &webrtc(cut)), "cleared");
    }

    #[test]
    fn a_cell_arrives_when_the_accepting_end_selected_no_path() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // The dialling end sends on a selected IP path. The accepting end opened no
            // path of its own and selects none, but its connection has the IP path open.
            let stuck_after = Duration::from_millis(300);
            let from = loopback_node(31, stuck_after).await;
            // trait object: the test passes a selector that never selects
            let mut to = loopback_node_with(32, stuck_after, Some(Arc::new(NeverSelects))).await;
            assert!(
                cell_arrives(&from, &mut to).await,
                "a cell that came over IP is not a cell over the relay"
            );
            assert_eq!(
                to.forwarder.dropped.load(Ordering::Relaxed),
                0,
                "the accepting end drops the cell it selected no path for"
            );
            assert_eq!(
                from.forwarder.pool.refused_on_relay.load(Ordering::Relaxed),
                0,
                "and the writer did not refuse the relay on the way"
            );
        });
    }

    #[test]
    fn a_writer_retires_when_its_connection_closes_under_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
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
            let deadline = std_Instant::now() + Duration::from_secs(5);
            while live_writers(&from.forwarder) > 0 && std_Instant::now() < deadline {
                tokio_time::sleep(Duration::from_millis(100)).await;
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
        });
    }

    #[test]
    fn a_writer_retires_itself_and_releases_its_bytes_when_it_gives_up() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // The unpruned-map leak: every next-hop id a peer ever names used to
            // leave an entry behind, and its queued bytes charged, for the life of
            // the process. The hop here is unreachable, so the writer gives up after
            // its dial backoff and must clean up after itself.
            let (forwarder, _app, _received) = forwarder().await;
            let source = stranger(1);
            let next = stranger(7);
            learn_vector(&forwarder, 7, &underlay_of(7), &[]);
            forwarder.enqueue(next.app_id, cell(next.app_id, source.app_id, 3));
            assert_eq!(live_writers(&forwarder), 1, "writer spawned");

            // DIAL_ATTEMPTS with linear backoff is ~1s; allow margin.
            for _ in 0..40 {
                if live_writers(&forwarder) == 0 {
                    break;
                }
                time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(live_writers(&forwarder), 0, "writer retired its own entry");
            assert_eq!(
                forwarder.pool.queued_bytes.load(Ordering::Relaxed),
                0,
                "a dead hop must not hold the shared byte budget"
            );
        });
    }

    #[test]
    fn writer_spawns_stop_at_the_ceiling() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            ::habilis_network_test_tracing::expect_warn(
                "habilis_network_iroh_multihop_transport::underlay",
                "reason=\"next-hop writer ceiling reached\"",
            );
            // Each cell goes to a fresh next hop, which is how a remote peer turns an
            // unpruned writer map into unbounded tasks and dials.
            let (forwarder, _app, _received) = forwarder().await;
            let source = stranger(1);
            for seed in 0..u8::try_from(MAX_WRITERS + 8).expect("fits") {
                let next = stranger(seed.wrapping_add(100));
                learn_vector(
                    &forwarder,
                    seed.wrapping_add(100),
                    &underlay_of(seed.wrapping_add(100)),
                    &[],
                );
                forwarder.enqueue(next.app_id, cell(next.app_id, source.app_id, 3));
            }
            assert!(
                live_writers(&forwarder) <= MAX_WRITERS,
                "the writers stop at the ceiling"
            );
        });
    }

    /// A test cut reaches a gate at once. The reading of the paths stands for `PATH_RECHECK`,
    /// but a cut made inside that span must not: the cell would leave on the relay, and the
    /// forwarder at the other end would refuse it.
    #[test]
    fn a_writer_gate_refuses_at_once_when_a_test_cuts_the_selected_path() {
        use super::{GateRole, RelayGate};
        use habilis_network_iroh_transport_util::{Rung, block_rung};

        let _guard = ::habilis_network_test_tracing::init();
        let local: EndpointId = SecretKey::from_bytes(&[41; 32]).public();
        let relay: iroh::RelayUrl = "http://127.0.0.1:1".parse().expect("relay url");
        let ip: SocketAddr = "127.0.0.1:2".parse().expect("ip addr");
        let paths = || {
            vec![
                (TransportAddr::Relay(relay.clone()), false),
                (TransportAddr::Ip(ip), true),
            ]
        };
        let mut gate = RelayGate::new(false, local, GateRole::Writer);
        assert!(gate.admits_paths(paths), "a selected IP path admits");

        block_rung(local, Rung::Ip, true);
        let admitted = gate.admits_paths(paths);
        block_rung(local, Rung::Ip, false);

        assert!(
            !admitted,
            "a cut IP path must not admit, even inside the recheck span"
        );
    }
}
