use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[cfg(feature = "test-hooks")]
use iroh::TransportAddr;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr};
use n0_future::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use crate::app_id::{AppId, UnderlayId};
use crate::cell::Cell;
use crate::route::{Route, RouteHop};
use crate::topology::Topology;

use super::delivered::Delivered;
use super::{
    FORWARD_QUEUE_BYTES, HEARD_HOPS_CAP, HeardHops, LOG_TARGET, MAX_WRITERS, RelayRule,
    UNRESOLVED_SEEN_CAP, WRITER_QUEUE, WriterPool, path_list, paths_of, writer_task,
};

use tokio::sync;
/// Routes cells outbound to next hops and delivers terminal cells locally.
#[derive(Debug)]
pub(crate) struct Forwarder {
    pub(super) underlay: Endpoint,
    /// This node's application-layer id, the other half of the identity a cell's
    /// current hop must name.
    pub(super) self_app_id: AppId,
    /// The runtime that spawns the writers. `enqueue` runs inside `poll_send`, which
    /// iroh calls from the socket's send path (`Transports::poll_send` in iroh's
    /// `socket/transports.rs`). It is kept so that a native spawn never depends on
    /// that caller being inside the runtime; nothing here shows that it is ever
    /// outside. A browser has no runtime and spawns on its one thread.
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) runtime: Handle,
    // the writer pool is shared by the forwarder and its accept loops
    pub(super) pool: Arc<WriterPool>,
    /// Terminal deliveries destined for the local application endpoint.
    pub(super) inbound: mpsc::Sender<Delivered>,
    /// Cells refused by the gates in [`Forwarder::handle_cell`] or by a budget.
    pub(super) dropped: AtomicU64,
    /// Cells passed on to a next hop for other nodes. Our own sends are not counted.
    pub(super) forwarded: AtomicU64,
    /// Cells that ended here and went into the inbox of the local transport.
    pub(super) delivered: AtomicU64,
    /// What the relay may do for cells.
    pub(super) rule: RelayRule,
    /// Where the dial address of a next hop comes from: a route names a hop by two ids,
    /// and the address is the one that the hop signed in its link vector.
    pub(super) topology: Arc<RwLock<Topology>>,
    /// Hops that a writer was spawned for with no vector in the topology: a hop without a vector.
    pub(super) unresolved_hops: AtomicU64,
    /// The hops that got a log line, and whether it was a warning: see [`UNRESOLVED_SEEN_CAP`].
    pub(super) unresolved_seen: Mutex<HashMap<UnderlayId, bool>>,
    /// The hops that named a cell this node delivered: the sender and the hops of its route. A
    /// reply goes back along that route reversed, so these are the hops that can lack a vector
    /// for a normal reason: see [`HEARD_HOPS_CAP`].
    pub(super) heard_hops: Mutex<HeardHops>,
}

impl Forwarder {
    pub(crate) fn new(
        underlay: Endpoint,
        self_app_id: AppId,
        inbound: mpsc::Sender<Delivered>,
        allow_relay: bool,
        stuck_after: Duration,
        // shared with the handle, which updates the vectors
        topology: Arc<RwLock<Topology>>,
    ) -> Self {
        Self {
            underlay,
            self_app_id,
            #[cfg(not(target_arch = "wasm32"))]
            runtime: Handle::current(),
            // the writer pool is shared by the forwarder and its accept loops
            pool: Arc::new(WriterPool::default()),
            inbound,
            dropped: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            rule: RelayRule {
                allow_relay,
                stuck_after,
            },
            topology,
            unresolved_hops: AtomicU64::new(0),
            unresolved_seen: Mutex::new(HashMap::new()),
            heard_hops: Mutex::new(HeardHops::default()),
        }
    }

    /// How many writers were spawned for a hop without a vector in the topology.
    #[cfg(test)]
    pub(crate) fn unresolved_hops(&self) -> u64 {
        self.unresolved_hops.load(Ordering::Relaxed)
    }

    /// The address to dial for `hop`: the one that its node signed in its link vector, if the
    /// vector names the same underlay endpoint as the hop. A hop without a vector is dialed
    /// by its id alone, never at an address that a cell carries, and counted: it may still be reachable by what iroh
    /// knows of the id, and if it is not, the cells are lost like any other.
    ///
    /// Logged at debug when the hop is explained. A cell that this node delivered named it: a
    /// reply goes back along the reversed route of a cell, and the sender's first link-vector
    /// arrives some 15 s after it starts. Or it is a link of this node: the origin of a route
    /// saw the vector of a new neighbor before this node did, and the link reaches it. Or this
    /// node held the vector and removed it, because the peer left or the vector expired: the
    /// cells in flight to the peer still name it, and the origin of the route is behind. Any
    /// other hop without a vector is a warning.
    pub(super) fn dial_addr(&self, hop: &RouteHop) -> EndpointAddr {
        let (known, gone) = {
            let topology = self.topology.read().expect("topology lock poisoned");
            let known = topology
                .underlay_of(hop.app_id)
                .filter(|address| UnderlayId::new(address.id) == hop.underlay_id);
            (known, topology.is_gone(hop.app_id))
        };
        known.unwrap_or_else(|| {
            let total = self.unresolved_hops.fetch_add(1, Ordering::Relaxed) + 1;
            let explained =
                gone || self.heard_hop(hop.underlay_id) || self.is_link_of_ours(hop.app_id);
            if self.line_is_due(hop.underlay_id, total, explained) {
                if gone {
                    tracing::debug!(
                        target: LOG_TARGET,
                        total,
                        hop = %hop.underlay_id.fmt_short(),
                        app_id = %hop.app_id.fmt_short(),
                        "multihop forwarder: hop whose vector is gone, dialing it by id"
                    );
                } else if explained {
                    tracing::debug!(
                        target: LOG_TARGET,
                        total,
                        hop = %hop.underlay_id.fmt_short(),
                        app_id = %hop.app_id.fmt_short(),
                        "multihop forwarder: hop without a vector, dialing it by id"
                    );
                } else {
                    tracing::warn!(
                        target: LOG_TARGET,
                        total,
                        hop = %hop.underlay_id.fmt_short(),
                        app_id = %hop.app_id.fmt_short(),
                        "multihop forwarder: hop without a vector that no delivered cell named, dialing it by id"
                    );
                }
            }
            EndpointAddr::new(hop.underlay_id.get())
        })
    }

    /// Whether `app_id` is a link in the vector that this node published of itself.
    fn is_link_of_ours(&self, app_id: AppId) -> bool {
        let topology = self.topology.read().expect("topology lock poisoned");
        topology
            .links_of(self.self_app_id)
            .is_some_and(|links| links.contains(&app_id))
    }

    /// Whether a cell that this node delivered named the hop `underlay_id`.
    fn heard_hop(&self, underlay_id: UnderlayId) -> bool {
        self.heard_hops
            .lock()
            .expect("heard hops poisoned")
            .set
            .contains(&underlay_id)
    }

    /// Remember the hops of the reply route of a delivered cell. Past [`HEARD_HOPS_CAP`] hops
    /// the oldest is forgotten.
    fn note_heard(&self, reply_route: &Route) {
        let mut heard = self.heard_hops.lock().expect("heard hops poisoned");
        for hop in reply_route.hops() {
            if !heard.set.insert(hop.underlay_id) {
                continue;
            }
            heard.order.push_back(hop.underlay_id);
            if heard.order.len() > HEARD_HOPS_CAP
                && let Some(oldest) = heard.order.pop_front()
            {
                heard.set.remove(&oldest);
            }
        }
    }

    /// Whether a log line is due for the hop `underlay_id`, found without a vector for the
    /// `total`-th time, `explained` or not: one line per distinct hop, and one warning per hop,
    /// which a hop that was explained the first time still gets when it is not any more. The ids
    /// come off the wire, so the map that remembers them is bounded; past [`UNRESOLVED_SEEN_CAP`]
    /// hops the rule is one line in 256.
    pub(super) fn line_is_due(&self, underlay_id: UnderlayId, total: u64, explained: bool) -> bool {
        let mut seen = self
            .unresolved_seen
            .lock()
            .expect("unresolved set poisoned");
        if let Some(warned) = seen.get_mut(&underlay_id) {
            if *warned || explained {
                return false;
            }
            *warned = true;
            return true;
        }
        if seen.len() < UNRESOLVED_SEEN_CAP {
            seen.insert(underlay_id, !explained);
            return true;
        }
        total.is_multiple_of(256)
    }

    /// How many cells this node passed on for other nodes.
    pub(crate) fn forwarded_cells(&self) -> u64 {
        self.forwarded.load(Ordering::Relaxed)
    }

    /// The counters of the data path: what was passed on, refused, dropped and delivered.
    pub(crate) fn counters(&self) -> crate::MultihopCounters {
        crate::MultihopCounters {
            forwarded: self.forwarded.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            refused_on_relay: self.pool.refused_on_relay.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
        }
    }

    /// The local transport dropped a packet that did not fit the buffer that iroh handed it.
    pub(crate) fn note_oversized(&self, len: usize, capacity: usize) {
        if let Some(total) = self.count_drop() {
            tracing::warn!(
                target: LOG_TARGET,
                total,
                len,
                capacity,
                reason = "packet larger than the receive buffer",
                "multihop transport dropping packets"
            );
        }
    }

    /// The application ids of the hops stuck on the relay past the deadline.
    pub(crate) fn stuck_hops(&self) -> Vec<AppId> {
        self.pool.stuck_app_ids()
    }

    /// Woken when the gate starts to refuse a hop, and when it admits one that it
    /// refused.
    pub(crate) fn route_wake(&self) -> Arc<sync::Notify> {
        Arc::clone(&self.pool.route_wake)
    }

    /// The application ids of the hops that the gate refuses now, stuck or not.
    pub(crate) fn refusing_hops(&self) -> Vec<AppId> {
        self.pool.refusing_app_ids()
    }

    /// Mark a hop as refused now, without the deadline having passed, as a test of
    /// the choice of a route needs it.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn refuse_hop_for_test(&self, underlay: UnderlayId, app_id: AppId) {
        self.pool.track(underlay, app_id);
        self.pool.note_refused(underlay, Duration::from_mins(1));
    }

    /// The open paths of the connection that our writer holds toward the underlay `hop`, now,
    /// each with whether it is the selected one: the reading that the gate takes.
    #[cfg(feature = "test-hooks")]
    pub(crate) fn writer_paths(&self, hop: UnderlayId) -> Option<Vec<(TransportAddr, bool)>> {
        let connection = {
            let connections = self
                .pool
                .connections
                .lock()
                .expect("connections mutex poisoned");
            connections.get(&hop).cloned()
        }?;
        Some(paths_of(&connection))
    }

    /// Rate-limited visibility for a refused cell. Whoever is sending them sets
    /// the rate, so logging every one hands them a second amplifier.
    fn note_drop(&self, reason: &str) {
        if let Some(total) = self.count_drop() {
            tracing::warn!(target: LOG_TARGET, total, reason, "multihop forwarder refusing cells");
        }
    }

    /// The refusal of a cell that came in over `connection` from `hop`, with what
    /// the log needs to tell whose path it was: the hop, this node, and the paths.
    pub(super) fn note_inbound_refusal(&self, hop: UnderlayId, connection: &Connection) {
        if let Some(total) = self.count_drop() {
            tracing::warn!(
                target: LOG_TARGET,
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
        let key = hop.underlay_id;
        // First attempt on any existing writer.
        if let Some(sender) = self.writer_for(key)
            && sender.try_send(cell.clone()).is_ok()
        {
            return;
        }
        // Stale or absent: (re)spawn a writer, then try once more.
        let Some(sender) = self.spawn_writer(hop) else {
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
        self.note_heard(&route);
        let delivered = Delivered {
            remote: route.encode(),
            packet: cell.packet,
        };
        // A full inbox drops the packet, as a saturated NIC would. It is counted and the first
        // drop is logged: an inbox that nobody drains is a silent black hole otherwise.
        if self.inbound.try_send(delivered).is_ok() {
            self.delivered.fetch_add(1, Ordering::Relaxed);
        } else {
            self.note_drop("inbox of the local transport is full");
        }
    }

    /// Whether `hop` is this node — both identities, since the two endpoints
    /// carry different keys and a cell should not be able to pair our underlay
    /// with somebody else's application id.
    fn is_self(&self, hop: &RouteHop) -> bool {
        hop.underlay_id == UnderlayId::new(self.underlay.id()) && hop.app_id == self.self_app_id
    }

    /// The hop that should have sent us this cell: our predecessor on the route,
    /// or the original sender when we are the first hop.
    fn expected_upstream(cell: &Cell) -> Option<&RouteHop> {
        match cell.position.checked_sub(1) {
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
    pub(crate) fn handle_cell(&self, cell: Cell, from: UnderlayId) {
        let Some(here) = cell.current_hop() else {
            self.note_drop("position past the end of the route");
            return;
        };
        if !self.is_self(here) {
            self.note_drop("position does not name this node");
            return;
        }
        let is_expected_upstream =
            Self::expected_upstream(&cell).is_some_and(|hop| hop.underlay_id == from);
        if !is_expected_upstream {
            self.note_drop("cell did not arrive from its preceding hop");
            return;
        }
        match cell.next_hop() {
            Some(next) => {
                let next = *next;
                self.forwarded.fetch_add(1, Ordering::Relaxed);
                self.enqueue(&next, cell.advanced());
            }
            None => self.deliver(cell),
        }
    }

    fn writer_for(&self, key: UnderlayId) -> Option<mpsc::Sender<Cell>> {
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
    fn spawn_writer(&self, hop: &RouteHop) -> Option<mpsc::Sender<Cell>> {
        let dst = self.dial_addr(hop);
        let key = UnderlayId::new(dst.id);
        let app_id = hop.app_id;
        let (tx, rx) = mpsc::channel(WRITER_QUEUE);
        {
            let mut writers = self.pool.writers.lock().expect("writers mutex poisoned");
            if writers.len() >= MAX_WRITERS && !writers.contains_key(&key) {
                drop(writers);
                self.note_drop("next-hop writer ceiling reached");
                return None;
            }
            writers.insert(key, tx.clone());
        }
        self.pool.track(key, app_id);
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
