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
use std::time::Duration;

use anyhow::Context;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_base::CustomAddr;
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
}

/// Routes cells outbound to next hops and delivers terminal cells locally.
#[derive(Debug)]
pub(crate) struct Forwarder {
    underlay: Endpoint,
    /// This node's application-layer id, the other half of the identity a cell's
    /// current hop must name.
    self_app_id: EndpointId,
    runtime: Handle,
    pool: Arc<WriterPool>,
    /// Terminal deliveries destined for the local application endpoint.
    inbound: mpsc::Sender<Delivered>,
    /// Cells refused by the gates in [`Forwarder::handle_cell`] or by a budget.
    dropped: AtomicU64,
}

impl Forwarder {
    pub(crate) fn new(
        underlay: Endpoint,
        self_app_id: EndpointId,
        inbound: mpsc::Sender<Delivered>,
    ) -> Self {
        Self {
            underlay,
            self_app_id,
            runtime: Handle::current(),
            pool: Arc::new(WriterPool::default()),
            inbound,
            dropped: AtomicU64::new(0),
        }
    }

    /// Rate-limited visibility for a refused cell. Whoever is sending them sets
    /// the rate, so logging every one hands them a second amplifier.
    fn note_drop(&self, reason: &str) {
        let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if total == 1 || total.is_multiple_of(256) {
            tracing::warn!(total, reason, "multihop forwarder refusing cells");
        }
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
        let Some(sender) = self.spawn_writer(hop.underlay.clone()) else {
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
    fn spawn_writer(&self, dst: EndpointAddr) -> Option<mpsc::Sender<Cell>> {
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
        self.runtime.spawn(writer_task(
            self.underlay.clone(),
            dst,
            rx,
            tx.clone(),
            Arc::clone(&self.pool),
        ));
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
) {
    let outcome = drain_to_hop(&underlay, &dst, &mut rx, &pool).await;
    if let Err(error) = outcome {
        tracing::debug!(hop = %dst.id.fmt_short(), %error, "multihop underlay writer stopping");
    }
    pool.retire(dst.id, &handle);
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
) -> anyhow::Result<()> {
    let conn = dial_with_retry(underlay, dst)
        .await
        .context("underlay dial gave up")?;
    let mut send = conn.open_uni().await.context("open underlay uni-stream")?;
    while let Some(cell) = rx.recv().await {
        let cost = cell.packet.len();
        let written = write_cell(&mut send, &cell).await;
        pool.release(cost);
        written.context("underlay write failed")?;
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
                tokio::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
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

    async fn read_loop(self, upstream: EndpointId, mut recv: iroh::endpoint::RecvStream) {
        while let Ok(cell) = read_cell(&mut recv).await {
            self.forwarder.handle_cell(cell, upstream);
        }
    }
}

impl ProtocolHandler for ForwardAcceptor {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // The peer's QUIC-TLS identity: the one thing about a cell's origin its
        // sender cannot choose, and constant across every stream on this
        // connection. Every cell that arrives here is checked against it.
        let upstream = connection.remote_id();
        // Loop ends when the upstream hop closes the connection: normal teardown.
        while let Ok(recv) = connection.accept_uni().await {
            tokio::spawn(self.clone().read_loop(upstream, recv));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Delivered, Duration, Forwarder, MAX_WRITERS, Ordering};
    use crate::addr::{Route, RouteHop};
    use crate::wire::Cell;
    use iroh::endpoint::presets;
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
        (Forwarder::new(underlay, app_id, inbound), app_id, received)
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
