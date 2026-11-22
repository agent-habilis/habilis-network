use std::collections::HashSet;
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
use crate::cell::{Cell, MAX_CELL_HOPS};
use crate::destination::Destination;
use crate::next_hop::NextHop;
use crate::next_hop_cache::{CacheKey, NextHopCache};
use crate::topology::Topology;

use super::delivered::Delivered;
use super::{
    FORWARD_QUEUE_BYTES, LOG_TARGET, MAX_WRITERS, RelayRule, WRITER_QUEUE, WriterPool, path_list,
    paths_of, writer_task,
};

#[cfg(target_arch = "wasm32")]
use n0_future::task;
use tokio::sync;

/// Why a cell that starts at this node could not leave it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotSent {
    /// The destination is this node: a packet to ourselves needs no transport.
    ToSelf,
    /// No neighbor of this node can reach the destination now.
    NoNextHop,
}

impl NotSent {
    /// The words of the error that the transport gives to iroh.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::ToSelf => "multihop destination is this node",
            Self::NoNextHop => "multihop has no next hop to the destination",
        }
    }
}

/// Picks the next hop of each cell from the table of this node, sends cells outbound to the next hops, and
/// delivers terminal cells locally.
#[derive(Debug)]
pub(crate) struct Forwarder {
    pub(super) underlay: Endpoint,
    /// This node's application-layer id: the destination that a cell must name to end here.
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
    /// Cells dropped because the best next hop is the hop that they came from.
    pub(super) turned_back: AtomicU64,
    /// Cells dropped because no neighbor of this node can reach their destination now.
    pub(super) no_next_hop: AtomicU64,
    /// Cells dropped because they had no forward left, or claimed more than the limit.
    pub(super) hop_limit: AtomicU64,
    /// What the relay may do for cells.
    pub(super) rule: RelayRule,
    /// The vectors that this node holds: the table that each next hop and each dial address come from.
    // shared with the handle, which updates the vectors
    pub(super) topology: Arc<RwLock<Topology>>,
    /// The next hop of each destination, kept while the topology and the set of refused hops do not change.
    next_hops: Mutex<NextHopCache>,
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
            turned_back: AtomicU64::new(0),
            no_next_hop: AtomicU64::new(0),
            hop_limit: AtomicU64::new(0),
            rule: RelayRule {
                allow_relay,
                stuck_after,
            },
            topology,
            next_hops: Mutex::new(NextHopCache::default()),
        }
    }

    /// The next hop of a cell for `dst` that came from `from` (`None` for a cell that starts here), from the
    /// vectors that this node holds and the hops that its gate refuses now.
    ///
    /// The generation of the refused set is read BEFORE the set. The pool changes the set under its lock and
    /// raises the generation after it, so a value can be kept under an older key than the set that it was made
    /// from, never under a newer one, and the next call then makes it again. Do not swap the two reads.
    pub(crate) fn next_hop(&self, dst: AppId, from: Option<AppId>) -> NextHop {
        let topology = self.topology.read().expect("topology lock poisoned");
        let key = CacheKey {
            topology: topology.generation(),
            refusing: self.pool.refusing_generation(),
        };
        let mut cache = self.next_hops.lock().expect("next hop cache poisoned");
        let kept = cache.get_or_compute(key, dst, || {
            let refusing = self.pool.refusing_app_ids();
            let refused: HashSet<AppId> = refusing.into_iter().collect();
            topology.next_hop(self.self_app_id, dst, &refused)
        });
        kept.unless_from(from)
    }

    /// Send a packet that starts at this node: one cell for `dst`, to the next hop that this node picks now.
    pub(crate) fn originate(&self, dst: AppId, packet: Vec<u8>) -> Result<(), NotSent> {
        if dst == self.self_app_id {
            return Err(NotSent::ToSelf);
        }
        let NextHop::Forward(neighbor) = self.next_hop(dst, None) else {
            self.no_next_hop.fetch_add(1, Ordering::Relaxed);
            return Err(NotSent::NoNextHop);
        };
        let cell = Cell {
            dst,
            src: self.self_app_id,
            hops_left: MAX_CELL_HOPS,
            packet,
        };
        self.enqueue(neighbor, cell);
        Ok(())
    }

    pub(crate) fn forwarded_cells(&self) -> u64 {
        self.forwarded.load(Ordering::Relaxed)
    }

    pub(crate) fn counters(&self) -> crate::MultihopCounters {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        crate::MultihopCounters {
            forwarded: read(&self.forwarded),
            dropped: read(&self.dropped),
            refused_on_relay: read(&self.pool.refused_on_relay),
            delivered: read(&self.delivered),
            turned_back: read(&self.turned_back),
            no_next_hop: read(&self.no_next_hop),
            hop_limit: read(&self.hop_limit),
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

    /// Mark a hop as refused now, without the deadline having passed, as a test of
    /// the choice of a next hop needs it.
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

    /// Count a refused cell, and say so in the log for the first one and for each 256th.
    fn note_drop(&self, reason: &str) {
        if let Some(total) = self.count_drop() {
            tracing::warn!(target: LOG_TARGET, total, reason, "multihop forwarder refusing cells");
        }
    }

    /// Count a cell that this node dropped because its table and the tables around it do not agree (no next hop, a
    /// cell sent back, no forward left): normal while the vectors travel after a link came or went, so the line is
    /// a debug line, for the first one and for each 256th. The counters say how many.
    fn note_disagreement(&self, reason: &str) {
        if let Some(total) = self.count_drop() {
            tracing::debug!(target: LOG_TARGET, total, reason, "multihop forwarder dropping cells: the tables disagree");
        }
    }

    /// The inbound gate refused a cell: it came over the relay, and this node does not take the relay.
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

    fn count_drop(&self) -> Option<u64> {
        let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        (total == 1 || total.is_multiple_of(256)).then_some(total)
    }

    /// Queue `cell` on the writer of `neighbor`, spawning the writer if there is none. The dial address of the
    /// neighbor is the one that it signed in its vector: a neighbor that has no vector now is no next hop, and the
    /// cell is dropped (the table can change between the choice and this call).
    ///
    /// Bounded: the queue of a writer holds [`WRITER_QUEUE`] cells and all the writers hold
    /// [`FORWARD_QUEUE_BYTES`] bytes. A cell that does not fit is dropped, as a full NIC queue drops a packet.
    pub(crate) fn enqueue(&self, neighbor: AppId, cell: Cell) {
        let cost = cell.packet.len();
        if self.pool.queued_bytes.fetch_add(cost, Ordering::Relaxed) + cost > FORWARD_QUEUE_BYTES {
            self.pool.release(cost);
            self.note_drop("forwarding byte budget exhausted");
            return;
        }
        let address = {
            let topology = self.topology.read().expect("topology lock poisoned");
            topology.underlay_of(neighbor)
        };
        let Some(address) = address else {
            self.pool.release(cost);
            self.note_drop("next hop has no vector");
            return;
        };
        let key = UnderlayId::new(address.id);
        if let Some(sender) = self.writer_for(key)
            && sender.try_send(cell.clone()).is_ok()
        {
            return;
        }
        let Some(sender) = self.spawn_writer(address, neighbor) else {
            self.pool.release(cost);
            return;
        };
        if sender.try_send(cell).is_err() {
            self.pool.release(cost);
        }
    }

    /// A cell ended here: hand its packet to the local transport, with the address of its source as the remote.
    fn deliver(&self, cell: Cell) {
        let delivered = Delivered {
            remote: Destination::new(cell.src).encode(),
            packet: cell.packet,
        };
        if self.inbound.try_send(delivered).is_ok() {
            self.delivered.fetch_add(1, Ordering::Relaxed);
        } else {
            self.note_drop("inbox of the local transport is full");
        }
    }

    /// What this node does with a cell that arrived from the underlay endpoint `from`: deliver it if it is for
    /// this node, and else give it to the next hop that this node picks now, with one forward fewer.
    ///
    /// `from` is the identity that the QUIC-TLS connection proves, and the one thing about a cell that its sender
    /// cannot choose. Who may open such a connection: any peer that can dial the underlay endpoint and speaks
    /// the forward protocol; the acceptor does not check membership. The work that a stranger can make is bounded
    /// by the limit of forwards, and by the drop of a cell that has no next hop.
    pub(crate) fn handle_cell(&self, cell: Cell, from: UnderlayId) {
        if cell.hops_left > MAX_CELL_HOPS {
            self.hop_limit.fetch_add(1, Ordering::Relaxed);
            self.note_disagreement("cell claims more forwards than the limit");
            return;
        }
        if cell.dst == self.self_app_id {
            self.deliver(cell);
            return;
        }
        if cell.hops_left == 0 {
            self.hop_limit.fetch_add(1, Ordering::Relaxed);
            self.note_disagreement("cell has no forward left");
            return;
        }
        let from_app = {
            let topology = self.topology.read().expect("topology lock poisoned");
            topology.app_id_of(from)
        };
        match self.next_hop(cell.dst, from_app) {
            NextHop::Forward(neighbor) => {
                self.forwarded.fetch_add(1, Ordering::Relaxed);
                self.enqueue(neighbor, cell.forwarded());
            }
            NextHop::TurnedBack => {
                self.turned_back.fetch_add(1, Ordering::Relaxed);
                self.note_disagreement("the best next hop is the hop that the cell came from");
            }
            NextHop::Unreachable => {
                self.no_next_hop.fetch_add(1, Ordering::Relaxed);
                self.note_disagreement("no neighbor reaches the destination");
            }
        }
    }

    fn writer_for(&self, key: UnderlayId) -> Option<mpsc::Sender<Cell>> {
        let writers = self.pool.writers.lock().expect("writers mutex poisoned");
        writers.get(&key).cloned()
    }

    /// Insert and spawn a fresh writer task for `dst`, replacing any dead entry.
    /// `None` once [`MAX_WRITERS`] are live.
    ///
    /// Refusing rather than evicting is deliberate: a flood of cells for invented destinations must not walk the
    /// real neighbours out of the map. Each spawned writer gives up after `DIAL_ATTEMPTS` and removes its own
    /// entry on the way out, so a refused flood clears itself.
    fn spawn_writer(&self, dst: EndpointAddr, app_id: AppId) -> Option<mpsc::Sender<Cell>> {
        let key = UnderlayId::new(dst.id);
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
        task::spawn(writer);
        Some(tx)
    }
}
