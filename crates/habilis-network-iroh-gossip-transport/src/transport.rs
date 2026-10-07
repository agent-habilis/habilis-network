//! The iroh custom transport: the three traits, and the handle that owns them.
//!
//! The transport exists before the endpoint, and the gossip topic after it, so a
//! handle is made without a sink and the engine attaches one once the topic is
//! joined. Before that, the path is not valid and a packet is dropped, which QUIC
//! treats as loss.

use std::collections::HashSet;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use iroh::EndpointId;
use iroh::address_lookup::AddressLookup;
use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use iroh_base::CustomAddr;
use n0_future::time::Instant;
use tokio::sync::mpsc;

use crate::budget::Budget;
use crate::counters::{Counters, Stats};
use crate::frame::{self, EncodeError};
use crate::{gossip_addr, parse_gossip_addr};

/// The guard of `mutex`. A poisoned lock holds data with no invariant to break
/// (a sink slot, a queue end), so it is used as it is and not turned into a panic.
pub(crate) fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Packets waiting for iroh to read them.
const INBOUND_CAP: usize = 256;

/// Where a frame goes: the mesh gossip topic, once the engine has joined it.
/// It never blocks. `false` means the frame was not accepted.
pub trait FrameSink: std::fmt::Debug + Send + Sync + 'static {
    fn try_send(&self, frame: Bytes) -> bool;

    /// Whether the sink can still carry a frame. A sink whose topic has closed
    /// says no, and the path is not valid until the next `attach`.
    fn is_alive(&self) -> bool {
        true
    }
}

/// What became of a frame that arrived from the topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Queued for iroh.
    Queued,
    /// Addressed to another member.
    NotForUs,
    /// Not a frame this build reads.
    Malformed,
    /// iroh is not reading fast enough, or has stopped.
    QueueFull,
}

/// A packet from another member, on its way to iroh.
#[derive(Debug)]
struct Packet {
    remote: CustomAddr,
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) app_id: EndpointId,
    local_addr: CustomAddr,
    sink: Mutex<Option<Arc<dyn FrameSink>>>,
    pub(crate) attached: AtomicBool,
    /// Destinations that the engine stopped, because a higher rung carries them.
    blocked: Mutex<HashSet<EndpointId>>,
    /// The byte budget of this node, if one is set.
    budget: Mutex<Option<Budget>>,
    /// Destinations that have an established connection. A frame to any other
    /// destination is a handshake and is not charged to the budget.
    established: Mutex<HashSet<EndpointId>>,
    counters: Counters,
}

impl Shared {
    /// A path is valid while a sink is attached and alive.
    pub(crate) fn path_is_valid(&self) -> bool {
        self.attached.load(Ordering::SeqCst)
            && locked(&self.sink)
                .as_ref()
                .is_some_and(|sink| sink.is_alive())
    }

    /// One QUIC datagram to `dst`: framed and handed to the sink. A datagram that
    /// does not fit a frame, or that has no sink to go to, is dropped and the call
    /// still succeeds, as a NIC drops what it cannot carry. QUIC recovers.
    pub(crate) fn send_datagram(&self, dst: EndpointId, datagram: &[u8]) {
        if locked(&self.blocked).contains(&dst) {
            return self.counters.dropped_not_allowed();
        }
        let frame = match frame::encode(dst, self.app_id, datagram) {
            Ok(frame) => frame,
            Err(EncodeError::Empty) => return self.counters.dropped_empty(),
            Err(EncodeError::TooLarge { .. }) => return self.counters.dropped_too_large(),
        };
        let sink = locked(&self.sink).clone().filter(|sink| sink.is_alive());
        let Some(sink) = sink else {
            return self.counters.dropped_no_sink();
        };
        let bytes = frame.len();
        // A frame to a destination with a connection is charged to the budget. A
        // frame to any other is a handshake and passes: a new pair must not be
        // starved by a bulk flow that has used the budget up.
        let charged = locked(&self.established).contains(&dst);
        let mut budgeted = false;
        if let Some(budget) = locked(&self.budget).as_mut() {
            budgeted = true;
            if charged && !budget.take(Instant::now(), bytes as u64) {
                return self.counters.dropped_budget();
            }
        }
        if sink.try_send(frame) {
            self.counters.sent(bytes);
            if budgeted && !charged {
                self.counters.exempt();
            }
        } else {
            self.counters.dropped_sink_refused();
        }
    }
}

/// A handle to a gossip transport. Clone-cheap. Register `custom_transport()` on
/// the endpoint builder, and `attach` a sink once the topic is joined.
#[derive(Debug, Clone)]
pub struct GossipHandle {
    pub(crate) shared: Arc<Shared>,
    inbound: mpsc::Sender<Packet>,
    transport: Arc<GossipTransport>,
}

impl GossipHandle {
    #[must_use]
    pub fn new(app_id: EndpointId) -> Self {
        let shared = Arc::new(Shared {
            app_id,
            local_addr: gossip_addr(app_id),
            sink: Mutex::new(None),
            attached: AtomicBool::new(false),
            blocked: Mutex::new(HashSet::new()),
            budget: Mutex::new(None),
            established: Mutex::new(HashSet::new()),
            counters: Counters::default(),
        });
        let (inbound, receiver) = mpsc::channel(INBOUND_CAP);
        let transport = Arc::new(GossipTransport {
            shared: Arc::clone(&shared),
            inbound: Mutex::new(Some(receiver)),
        });
        Self {
            shared,
            inbound,
            transport,
        }
    }

    #[must_use]
    pub fn app_id(&self) -> EndpointId {
        self.shared.app_id
    }

    /// Send frames on `sender`, the mesh topic, from now on.
    ///
    /// The engine calls this when it joins the topic, and again where it replaces
    /// the topic's sender after a resubscribe.
    pub fn attach_gossip(&self, sender: iroh_gossip::api::GossipSender) {
        self.attach(Arc::new(crate::sink::GossipSink::spawn(sender)));
    }

    /// The address lookup, for `Builder::address_lookup`: it answers the first dial
    /// of a peer with the gossip address.
    #[must_use]
    pub fn address_lookup(&self) -> impl AddressLookup + use<> {
        crate::lookup::GossipLookup {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Allow frames to `dst`, or stop them. The engine calls this when the selected
    /// path of a pair changes: a pair that a higher rung carries has no use for the
    /// flood. A destination that was never named is allowed, so that a handshake to
    /// a new peer is not dropped.
    pub fn allow(&self, dst: EndpointId, allowed: bool) {
        let mut blocked = locked(&self.shared.blocked);
        if allowed {
            blocked.remove(&dst);
        } else {
            blocked.insert(dst);
        }
    }

    /// Limit the bytes per second that this node puts on the topic, or lift the
    /// limit with `None`. See [`crate::DEFAULT_BUDGET_BYTES_PER_SEC`].
    pub fn set_budget(&self, bytes_per_sec: Option<u64>) {
        *locked(&self.shared.budget) = bytes_per_sec.map(|rate| Budget::new(rate, Instant::now()));
    }

    /// Tell the handle whether `dst` has an established connection. Frames to a
    /// destination that has none are handshakes: they are not charged to the
    /// budget, so a new pair is not starved by a bulk flow. The engine calls this
    /// from where it knows the connections.
    pub fn set_established(&self, dst: EndpointId, established: bool) {
        let mut destinations = locked(&self.shared.established);
        if established {
            destinations.insert(dst);
        } else {
            destinations.remove(&dst);
        }
    }

    /// What this handle has counted so far.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.shared.counters.snapshot()
    }

    /// The transport, for `Builder::add_custom_transport`.
    #[must_use]
    pub fn custom_transport(&self) -> Arc<dyn CustomTransport> {
        Arc::clone(&self.transport) as Arc<dyn CustomTransport>
    }

    /// Send frames to `sink` from now on, and make the path valid.
    pub fn attach(&self, sink: Arc<dyn FrameSink>) {
        *locked(&self.shared.sink) = Some(sink);
        self.shared.attached.store(true, Ordering::SeqCst);
    }

    /// Stop sending. The path is not valid again until the next `attach`.
    pub fn detach(&self) {
        self.shared.attached.store(false, Ordering::SeqCst);
        *locked(&self.shared.sink) = None;
    }

    /// A frame from the topic. Never blocks: the engine's receive loop calls this.
    #[must_use]
    pub fn deliver(&self, frame: &[u8]) -> Delivery {
        let counters = &self.shared.counters;
        counters.arrived(frame.len());
        let Ok(frame) = frame::decode(frame) else {
            counters.malformed();
            return Delivery::Malformed;
        };
        if frame.dst != self.shared.app_id {
            counters.not_for_us();
            return Delivery::NotForUs;
        }
        let packet = Packet {
            remote: gossip_addr(frame.src),
            bytes: frame.datagram.to_vec(),
        };
        if self.inbound.try_send(packet).is_err() {
            counters.queue_full();
            return Delivery::QueueFull;
        }
        counters.queued();
        Delivery::Queued
    }
}

#[derive(Debug)]
struct GossipTransport {
    shared: Arc<Shared>,
    /// Taken by the single `bind` call. `None` afterwards.
    inbound: Mutex<Option<mpsc::Receiver<Packet>>>,
}

impl CustomTransport for GossipTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let inbound = locked(&self.inbound)
            .take()
            .ok_or_else(|| io::Error::other("gossip transport already bound"))?;
        let local = n0_watcher::Watchable::new(vec![self.shared.local_addr.clone()]);
        Ok(Box::new(GossipEndpoint {
            shared: Arc::clone(&self.shared),
            inbound,
            local,
        }))
    }
}

#[derive(Debug)]
struct GossipEndpoint {
    shared: Arc<Shared>,
    inbound: mpsc::Receiver<Packet>,
    local: n0_watcher::Watchable<Vec<CustomAddr>>,
}

impl CustomEndpoint for GossipEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.local.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(GossipSender {
            shared: Arc::clone(&self.shared),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        let cap = bufs.len().min(metas.len()).min(recv_infos.len());
        if cap == 0 {
            return Poll::Ready(Ok(0));
        }
        loop {
            let mut batch = Vec::with_capacity(cap);
            match self.inbound.poll_recv_many(cx, &mut batch, cap) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(0) => {
                    return Poll::Ready(Err(io::Error::other("gossip inbound closed")));
                }
                Poll::Ready(_) => {}
            }
            let mut count = 0;
            for packet in batch {
                let len = packet.bytes.len();
                if bufs[count].len() < len {
                    // Larger than the buffer iroh handed us: dropped, as a NIC
                    // drops a jumbo frame on a path with a smaller MTU.
                    self.shared.counters.dropped_oversized_in();
                    continue;
                }
                bufs[count][..len].copy_from_slice(&packet.bytes);
                recv_infos[count] =
                    RecvInfo::new(packet.remote, Some(self.shared.local_addr.clone()));
                metas[count].len = len;
                metas[count].stride = len;
                count += 1;
            }
            if count > 0 {
                return Poll::Ready(Ok(count));
            }
            // Everything dequeued was too large. Poll the queue again: that
            // either finds more or returns `Pending` with this task's waker
            // registered, so there is no busy loop and no manual wake.
        }
    }
}

#[derive(Debug)]
struct GossipSender {
    shared: Arc<Shared>,
}

impl CustomSender for GossipSender {
    /// Valid only for a gossip address, and only while a sink is attached: a path
    /// that cannot carry a packet must not be selected.
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        parse_gossip_addr(addr).is_some() && self.shared.path_is_valid()
    }

    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(dst) = parse_gossip_addr(dst) else {
            return Poll::Ready(Err(io::Error::other("not a gossip address")));
        };
        // A GSO batch is several datagrams; each is one QUIC packet and one frame.
        for datagram in habilis_network_iroh_transport_util::datagrams(transmit) {
            self.shared.send_datagram(dst, datagram);
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;
    use std::time::Duration;

    use iroh::endpoint::presets;
    use iroh::protocol::{AcceptError, ProtocolHandler, Router};
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};

    use super::*;
    use crate::memory::MemoryHub;
    use crate::{GOSSIP_TRANSPORT_ID, frame};

    const ECHO_ALPN: &[u8] = b"habilis-network-gossip/test-echo/0";

    fn secret(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    /// A sink that keeps what it is given.
    #[derive(Debug, Default)]
    struct Recorder(Mutex<Vec<Bytes>>);

    impl FrameSink for Recorder {
        fn try_send(&self, frame: Bytes) -> bool {
            locked(&self.0).push(frame);
            true
        }
    }

    #[derive(Debug, Clone)]
    struct Echo;

    impl ProtocolHandler for Echo {
        async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
            // One echo per stream, until the client closes the connection.
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                tokio::io::copy(&mut recv, &mut send).await?;
                send.finish()?;
            }
            Ok(())
        }
    }

    /// An endpoint whose only transport is gossip.
    async fn endpoint(secret: SecretKey, handle: &GossipHandle) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .relay_mode(RelayMode::Disabled)
            .add_custom_transport(handle.custom_transport())
            .clear_ip_transports()
            .clear_relay_transports()
            .bind()
            .await
            .expect("bind an endpoint with gossip only")
    }

    fn dial(id: EndpointId) -> EndpointAddr {
        EndpointAddr::from_parts(id, [TransportAddr::Custom(gossip_addr(id))])
    }

    async fn echo_once(connection: &iroh::endpoint::Connection, message: &[u8]) {
        let (mut send, mut recv) = connection.open_bi().await.expect("open a stream");
        send.write_all(message).await.expect("write");
        send.finish().expect("finish");
        let echoed = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(1024))
            .await
            .expect("the echo timed out")
            .expect("read the echo");
        assert_eq!(echoed, message);
    }

    /// Two nodes with gossip as the only transport, joined by an in-memory flood.
    async fn pair() -> (
        MemoryHub,
        (Endpoint, GossipHandle),
        (Endpoint, GossipHandle),
        Router,
    ) {
        let hub = MemoryHub::new();
        let alice_handle = GossipHandle::new(secret(1).public());
        let bob_handle = GossipHandle::new(secret(2).public());
        hub.join(&alice_handle);
        hub.join(&bob_handle);
        let alice = endpoint(secret(1), &alice_handle).await;
        let bob = endpoint(secret(2), &bob_handle).await;
        let router = Router::builder(bob.clone()).accept(ECHO_ALPN, Echo).spawn();
        (hub, (alice, alice_handle), (bob, bob_handle), router)
    }

    #[tokio::test]
    async fn a_quic_echo_completes_with_gossip_as_the_only_transport() {
        let (_hub, (alice, _), (bob, _), router) = pair().await;

        let connection = tokio::time::timeout(
            Duration::from_secs(10),
            alice.connect(dial(bob.id()), ECHO_ALPN),
        )
        .await
        .expect("connect timed out")
        .expect("connect over gossip");

        echo_once(&connection, b"hello over gossip").await;
        let selected_is_gossip = connection.paths().iter().any(|path| {
            path.is_selected()
                && matches!(path.remote_addr(), TransportAddr::Custom(addr) if addr.id() == GOSSIP_TRANSPORT_ID)
        });
        assert!(selected_is_gossip, "the selected path is not gossip");
        connection.close(0u32.into(), b"done");
        router.shutdown().await.expect("shutdown");
    }

    #[test]
    fn a_path_is_not_valid_until_a_sink_is_attached() {
        let handle = GossipHandle::new(secret(1).public());
        let endpoint = handle.transport.bind().expect("bind");
        let sender = endpoint.create_sender();
        let to_bob = gossip_addr(secret(2).public());

        assert!(!sender.is_valid_send_addr(&to_bob), "before attach");
        handle.attach(Arc::new(Recorder::default()));
        assert!(sender.is_valid_send_addr(&to_bob), "after attach");
        handle.detach();
        assert!(!sender.is_valid_send_addr(&to_bob), "after detach");
    }

    /// The guard is on the frame, and the frame holds 3774 bytes of datagram.
    #[test]
    fn a_datagram_over_the_frame_budget_is_dropped_by_the_sender() {
        let handle = GossipHandle::new(secret(1).public());
        let recorder = Arc::new(Recorder::default());
        handle.attach(recorder.clone());
        let bob = secret(2).public();

        handle
            .shared
            .send_datagram(bob, &vec![1u8; frame::MAX_DATAGRAM_LEN + 1]);
        assert!(locked(&recorder.0).is_empty(), "3775 bytes");
        handle
            .shared
            .send_datagram(bob, &vec![1u8; frame::MAX_DATAGRAM_LEN]);
        assert_eq!(locked(&recorder.0).len(), 1, "3774 bytes");
    }

    #[derive(Default)]
    struct CountingWaker(AtomicUsize);

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// An empty queue returns `Pending` and wakes nobody; a delivered frame wakes
    /// the task once and is then read. A busy loop would show as wakes with no push.
    #[test]
    fn an_empty_queue_is_pending_and_a_delivery_wakes_the_task() {
        let me = secret(1).public();
        let handle = GossipHandle::new(me);
        let mut endpoint = handle.transport.bind().expect("bind");
        let waker = Arc::new(CountingWaker::default());
        let std_waker = std::task::Waker::from(Arc::clone(&waker));
        let mut cx = Context::from_waker(&std_waker);
        let mut storage = [0u8; 2048];
        let mut bufs = [io::IoSliceMut::new(&mut storage)];
        let mut metas = [noq_udp::RecvMeta::default()];
        let mut infos = [RecvInfo::new(gossip_addr(me), None)];

        let first = endpoint.poll_recv(&mut cx, &mut bufs, &mut metas, &mut infos);
        assert!(first.is_pending(), "an empty queue");
        assert_eq!(
            waker.0.load(Ordering::SeqCst),
            0,
            "woken with nothing queued"
        );

        let from_bob = frame::encode(me, secret(2).public(), &[5u8; 100]).expect("a frame");
        assert_eq!(handle.deliver(&from_bob), Delivery::Queued);
        assert_eq!(waker.0.load(Ordering::SeqCst), 1, "one wake per delivery");

        let second = endpoint.poll_recv(&mut cx, &mut bufs, &mut metas, &mut infos);
        assert!(matches!(second, Poll::Ready(Ok(1))), "{second:?}");
        assert_eq!(metas[0].len, 100);
    }

    #[test]
    fn a_frame_for_another_member_or_a_bad_frame_is_not_queued() {
        let handle = GossipHandle::new(secret(1).public());
        let for_carol = frame::encode(secret(3).public(), secret(2).public(), &[1]).expect("frame");

        assert_eq!(handle.deliver(&for_carol), Delivery::NotForUs);
        assert_eq!(handle.deliver(b"{\"kind\":\"chat\"}"), Delivery::Malformed);
    }

    /// A frame with a forged source arrives for a connection that exists. It must
    /// not move the connection or stop it: QUIC authenticates every packet. This
    /// test was green on its first run; it stays as a guard.
    #[tokio::test]
    async fn a_forged_source_does_not_move_or_break_an_established_connection() {
        let (hub, (alice, alice_handle), (bob, _), router) = pair().await;
        let connection = alice
            .connect(dial(bob.id()), ECHO_ALPN)
            .await
            .expect("connect over gossip");
        echo_once(&connection, b"before").await;

        let real = hub.sent().into_iter().next().expect("a frame was sent");
        let real = frame::decode(&real).expect("a frame");
        let forged = frame::encode(alice_handle.app_id(), secret(9).public(), real.datagram)
            .expect("a frame");
        for _ in 0..5 {
            let _ = alice_handle.deliver(&forged);
        }

        echo_once(&connection, b"after").await;
        assert!(connection.close_reason().is_none(), "the connection closed");
        let selected: Vec<_> = connection
            .paths()
            .iter()
            .filter(iroh::endpoint::Path::is_selected)
            .map(|path| path.remote_addr().clone())
            .collect();
        assert_eq!(
            selected,
            [TransportAddr::Custom(gossip_addr(bob.id()))],
            "the selected path moved"
        );
        connection.close(0u32.into(), b"done");
        router.shutdown().await.expect("shutdown");
    }

    /// A frame is counted where it leaves and where it arrives, and the two ends
    /// agree with what the flood carried.
    #[tokio::test]
    async fn an_echo_moves_the_counters_of_both_ends() {
        let (hub, (alice, alice_handle), (bob, bob_handle), router) = pair().await;
        let connection = alice
            .connect(dial(bob.id()), ECHO_ALPN)
            .await
            .expect("connect over gossip");
        echo_once(&connection, b"count me").await;

        let (alice_stats, bob_stats) = (alice_handle.stats(), bob_handle.stats());
        assert!(
            alice_stats.frames_out > 0 && bob_stats.frames_out > 0,
            "{alice_stats:?} {bob_stats:?}"
        );
        assert!(
            alice_stats.queued > 0 && bob_stats.queued > 0,
            "{alice_stats:?} {bob_stats:?}"
        );
        let sent = hub.sent();
        assert_eq!(
            alice_stats.frames_out + bob_stats.frames_out,
            sent.len() as u64
        );
        let flooded: usize = sent.iter().map(Bytes::len).sum();
        assert_eq!(alice_stats.bytes_out + bob_stats.bytes_out, flooded as u64);
        assert_eq!(
            alice_stats.frames_in, bob_stats.frames_out,
            "alice reads what bob sent"
        );
        assert_eq!(
            bob_stats.frames_in, alice_stats.frames_out,
            "bob reads what alice sent"
        );
        connection.close(0u32.into(), b"done");
        router.shutdown().await.expect("shutdown");
    }

    #[test]
    fn a_dropped_datagram_is_counted_by_its_reason() {
        let handle = GossipHandle::new(secret(1).public());
        let bob = secret(2).public();

        handle.shared.send_datagram(bob, &[1u8; 100]);
        handle.attach(Arc::new(Recorder::default()));
        handle
            .shared
            .send_datagram(bob, &vec![1u8; frame::MAX_DATAGRAM_LEN + 1]);
        handle.shared.send_datagram(bob, &[]);
        handle.shared.send_datagram(bob, &[1u8; 100]);

        let stats = handle.stats();
        assert_eq!(stats.dropped_no_sink, 1);
        assert_eq!(stats.dropped_too_large, 1);
        assert_eq!(stats.dropped_empty, 1);
        assert_eq!(stats.frames_out, 1);
        assert_eq!(stats.bytes_out, (frame::HEADER_LEN + 100) as u64);
    }

    #[test]
    fn a_frame_that_arrives_is_counted_by_what_became_of_it() {
        let me = secret(1).public();
        let handle = GossipHandle::new(me);
        let for_me = frame::encode(me, secret(2).public(), &[1u8; 50]).expect("frame");
        let for_carol = frame::encode(secret(3).public(), secret(2).public(), &[1]).expect("frame");

        let _ = handle.deliver(&for_me);
        let _ = handle.deliver(&for_carol);
        let _ = handle.deliver(b"{}");
        for _ in 0..INBOUND_CAP {
            let _ = handle.deliver(&for_me);
        }

        let stats = handle.stats();
        assert_eq!(stats.frames_in, INBOUND_CAP as u64 + 3);
        assert_eq!(
            stats.queued, INBOUND_CAP as u64,
            "the queue holds its capacity"
        );
        assert_eq!(stats.queue_full, 1);
        assert_eq!(stats.not_for_us, 1);
        assert_eq!(stats.malformed, 1);
        assert_eq!(
            stats.bytes_in,
            (INBOUND_CAP as u64 + 1) * (frame::HEADER_LEN as u64 + 50)
                + (frame::HEADER_LEN as u64 + 1)
                + 2
        );
    }

    /// A destination that the engine does not allow gets no frame, and the drop is
    /// counted. The others are not affected, and allowing it again lets frames go.
    #[test]
    fn a_destination_that_is_not_allowed_gets_no_frame() {
        let handle = GossipHandle::new(secret(1).public());
        let recorder = Arc::new(Recorder::default());
        handle.attach(recorder.clone());
        let (bob, carol) = (secret(2).public(), secret(3).public());

        handle.allow(bob, false);
        handle.shared.send_datagram(bob, &[1u8; 100]);
        handle.shared.send_datagram(carol, &[1u8; 100]);

        let sent = locked(&recorder.0).clone();
        assert_eq!(sent.len(), 1, "only the frame to carol");
        assert_eq!(frame::decode(&sent[0]).expect("a frame").dst, carol);
        assert_eq!(handle.stats().dropped_not_allowed, 1);

        handle.allow(bob, true);
        handle.shared.send_datagram(bob, &[1u8; 100]);
        assert_eq!(locked(&recorder.0).len(), 2, "allowed again");
    }

    /// A destination that was never named is allowed: its handshake must pass.
    #[test]
    fn a_destination_that_was_never_named_is_allowed() {
        let handle = GossipHandle::new(secret(1).public());
        let recorder = Arc::new(Recorder::default());
        handle.attach(recorder.clone());

        handle.shared.send_datagram(secret(9).public(), &[1u8; 100]);

        assert_eq!(locked(&recorder.0).len(), 1);
        assert_eq!(handle.stats().dropped_not_allowed, 0);
    }

    /// A dial by id alone reaches the peer: the lookup supplies the gossip address.
    #[tokio::test]
    async fn a_dial_by_id_alone_is_resolved_by_the_gossip_lookup() {
        let hub = MemoryHub::new();
        let (alice_handle, bob_handle) = (
            GossipHandle::new(secret(1).public()),
            GossipHandle::new(secret(2).public()),
        );
        hub.join(&alice_handle);
        hub.join(&bob_handle);
        let build = |key: SecretKey, handle: GossipHandle| async move {
            Endpoint::builder(presets::Minimal)
                .secret_key(key)
                .relay_mode(RelayMode::Disabled)
                .add_custom_transport(handle.custom_transport())
                .address_lookup(handle.address_lookup())
                .clear_ip_transports()
                .clear_relay_transports()
                .bind()
                .await
                .expect("bind")
        };
        let alice = build(secret(1), alice_handle).await;
        let bob = build(secret(2), bob_handle).await;
        let router = Router::builder(bob.clone()).accept(ECHO_ALPN, Echo).spawn();

        let connection =
            tokio::time::timeout(Duration::from_secs(10), alice.connect(bob.id(), ECHO_ALPN))
                .await
                .expect("connect timed out")
                .expect("connect by id");

        echo_once(&connection, b"found by id").await;
        connection.close(0u32.into(), b"done");
        router.shutdown().await.expect("shutdown");
    }

    /// A frame to a destination with an established connection is charged to the
    /// budget and dropped when the budget is out. A frame to any other destination
    /// is a handshake: it is sent, and counted as exempt.
    #[test]
    fn an_established_destination_is_charged_and_a_handshake_is_exempt() {
        let handle = GossipHandle::new(secret(1).public());
        let recorder = Arc::new(Recorder::default());
        handle.attach(recorder.clone());
        let (bob, carol) = (secret(2).public(), secret(3).public());
        handle.set_budget(Some(1000));
        handle.set_established(bob, true);

        // A 100-byte datagram is a 166-byte frame: six fit in 1000 bytes.
        for _ in 0..8 {
            handle.shared.send_datagram(bob, &[1u8; 100]);
        }
        assert_eq!(locked(&recorder.0).len(), 6, "six frames fit the burst");
        assert_eq!(handle.stats().dropped_budget, 2);

        // Carol has no connection: her handshake passes with the budget spent.
        handle.shared.send_datagram(carol, &[1u8; 100]);
        assert_eq!(locked(&recorder.0).len(), 7, "the handshake passed");
        assert_eq!(handle.stats().exempt_frames, 1);

        // Once she has a connection, her frames are charged and refused.
        handle.set_established(carol, true);
        handle.shared.send_datagram(carol, &[1u8; 100]);
        assert_eq!(locked(&recorder.0).len(), 7, "charged, and refused");
        assert_eq!(handle.stats().dropped_budget, 3);
    }

    #[test]
    fn without_a_budget_nothing_is_dropped_for_bytes() {
        let handle = GossipHandle::new(secret(1).public());
        let recorder = Arc::new(Recorder::default());
        handle.attach(recorder.clone());
        let bob = secret(2).public();
        handle.set_established(bob, true);

        for _ in 0..100 {
            handle.shared.send_datagram(bob, &[1u8; 1000]);
        }

        assert_eq!(locked(&recorder.0).len(), 100);
        assert_eq!(handle.stats().dropped_budget, 0);
    }

    /// A packet larger than the buffer iroh offers is dropped, counted, and does
    /// not stop the next one.
    #[test]
    fn an_oversized_packet_is_counted_and_the_next_one_is_read() {
        let me = secret(1).public();
        let handle = GossipHandle::new(me);
        let mut endpoint = handle.transport.bind().expect("bind");
        let waker = Arc::new(CountingWaker::default());
        let std_waker = std::task::Waker::from(Arc::clone(&waker));
        let mut cx = Context::from_waker(&std_waker);
        let mut storage = [0u8; 50];
        let mut bufs = [io::IoSliceMut::new(&mut storage)];
        let mut metas = [noq_udp::RecvMeta::default()];
        let mut infos = [RecvInfo::new(gossip_addr(me), None)];
        let big = frame::encode(me, secret(2).public(), &[5u8; 100]).expect("a frame");
        let small = frame::encode(me, secret(2).public(), &[5u8; 40]).expect("a frame");

        assert_eq!(handle.deliver(&big), Delivery::Queued);
        let first = endpoint.poll_recv(&mut cx, &mut bufs, &mut metas, &mut infos);
        assert!(
            first.is_pending(),
            "the only packet was too large: {first:?}"
        );
        assert_eq!(handle.stats().dropped_oversized_in, 1);

        assert_eq!(handle.deliver(&small), Delivery::Queued);
        let second = endpoint.poll_recv(&mut cx, &mut bufs, &mut metas, &mut infos);
        assert!(matches!(second, Poll::Ready(Ok(1))), "{second:?}");
        assert_eq!(handle.stats().dropped_oversized_in, 1);
    }
}
