//! A sink over a real gossip topic.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use iroh_gossip::api::{Event, GossipReceiver, GossipSender};
use n0_future::StreamExt as _;
use tokio::sync::mpsc;

use crate::{FrameSink, GossipHandle};

/// Frames waiting for the topic's sender. A full queue refuses the frame: QUIC
/// treats that as loss.
const QUEUE: usize = 256;

/// Hands frames to the topic's sender from a task of its own, because the
/// sender's `broadcast` is async and a sink must not block.
///
/// The task ends when the topic is closed or when the sink is dropped. When it
/// ends it clears the alive flag, and the handle then treats the path as not valid
/// and counts a datagram as `dropped_no_sink`.
#[derive(Debug)]
pub struct GossipSink {
    queue: mpsc::Sender<Bytes>,
    alive: Arc<AtomicBool>,
}

impl GossipSink {
    /// Start the task that sends on `sender`.
    #[must_use]
    pub fn spawn(sender: GossipSender) -> Self {
        let (queue, mut frames) = mpsc::channel::<Bytes>(QUEUE);
        let alive = Arc::new(AtomicBool::new(true));
        let task_alive = Arc::clone(&alive);
        n0_future::task::spawn(async move {
            while let Some(frame) = frames.recv().await {
                if sender.broadcast(frame).await.is_err() {
                    break;
                }
            }
            task_alive.store(false, Ordering::SeqCst);
        });
        Self { queue, alive }
    }
}

/// The task of [`spawn_receive_loop`]. `abort()` stops it.
pub type ReceiveLoop = n0_future::task::JoinHandle<()>;

/// Read a topic and hand every message to `handle`, until the topic ends.
///
/// For a topic that carries **only** transport frames, as a test or a benchmark does.
/// On the mesh topic the engine splits the frames from the mesh messages before
/// it hands anything to a handle (design doc, section 2.5): this loop does not.
#[must_use]
pub fn spawn_receive_loop(mut receiver: GossipReceiver, handle: GossipHandle) -> ReceiveLoop {
    n0_future::task::spawn(async move {
        while let Some(Ok(event)) = receiver.next().await {
            handle_event(&handle, event);
        }
    })
}

/// What the receive loop does with one topic event.
pub(crate) fn handle_event(handle: &GossipHandle, event: Event) {
    match event {
        Event::Received(message) => {
            let _ = handle.deliver(&message.content);
        }
        Event::Lagged => handle.note_lagged(),
        Event::NeighborUp(_) | Event::NeighborDown(_) => {}
    }
}

impl FrameSink for GossipSink {
    fn try_send(&self, frame: Bytes) -> bool {
        self.queue.try_send(frame).is_ok()
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::address_lookup::memory::MemoryLookup;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::{Endpoint, RelayMode, SecretKey};
    use iroh_gossip::api::Event;
    use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
    use iroh_gossip::proto::TopicId;

    use crate::{GossipHandle, frame};

    fn secret(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    async fn member(seed: u8, lookup: &MemoryLookup) -> (Endpoint, Gossip, Router) {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(secret(seed))
            .relay_mode(RelayMode::Disabled)
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .expect("loopback"),
            )
            .expect("bind address")
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind");
        lookup.add_endpoint_info(endpoint.addr());
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let router = Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .spawn();
        (endpoint, gossip, router)
    }

    async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..200 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for {what}");
    }

    /// A frame that a handle sends through a real topic arrives at the other
    /// member, whose receive loop hands it to its own handle.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_frame_sent_through_a_real_topic_reaches_the_other_member() {
        let lookup = MemoryLookup::new();
        let (alice_endpoint, alice_gossip, _alice_router) = member(1, &lookup).await;
        let (bob_endpoint, bob_gossip, _bob_router) = member(2, &lookup).await;
        let topic = TopicId::from_bytes([7u8; 32]);
        let alice_handle = GossipHandle::new(alice_endpoint.id());
        let bob_handle = GossipHandle::new(bob_endpoint.id());

        let bob_topic = bob_gossip
            .subscribe(topic, vec![])
            .await
            .expect("bob joins");
        let (_bob_sender, bob_receiver) = bob_topic.split();
        let alice_topic = alice_gossip
            .subscribe_and_join(topic, vec![bob_endpoint.id()])
            .await
            .expect("alice joins");
        let (alice_sender, _alice_receiver) = alice_topic.split();
        let reader = super::spawn_receive_loop(bob_receiver, bob_handle.clone());

        alice_handle.attach_gossip(alice_sender);
        alice_handle
            .shared
            .send_datagram(bob_endpoint.id(), &[7u8; 100]);

        wait_for("the frame at bob", || bob_handle.stats().queued == 1).await;
        let (alice_stats, bob_stats) = (alice_handle.stats(), bob_handle.stats());
        assert_eq!(alice_stats.frames_out, 1, "{alice_stats:?}");
        assert_eq!(bob_stats.frames_in, 1, "{bob_stats:?}");
        assert_eq!(bob_stats.bytes_in, (frame::HEADER_LEN + 100) as u64);
        reader.abort();
    }

    /// The ladder: IP first, then gossip.
    #[derive(Debug)]
    struct Ladder;

    impl iroh::endpoint::transports::PathSelector for Ladder {
        fn select(
            &self,
            ctx: &iroh::endpoint::transports::PathSelectionContext<'_>,
        ) -> iroh::endpoint::transports::PathSelection {
            use habilis_network_iroh_transport_util::{climb, custom_rung};
            let paths: Vec<_> = ctx.paths().collect();
            let mut selection = iroh::endpoint::transports::PathSelection::none();
            if let Some(path) = climb(&paths, custom_rung, |_, _| true) {
                selection.set(path);
            }
            selection
        }
    }

    const ECHO_ALPN: &[u8] = b"habilis-network-gossip/test-echo/0";

    #[derive(Debug, Clone)]
    struct Echo;

    impl iroh::protocol::ProtocolHandler for Echo {
        async fn accept(
            &self,
            connection: iroh::endpoint::Connection,
        ) -> Result<(), iroh::protocol::AcceptError> {
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                tokio::io::copy(&mut recv, &mut send).await?;
                send.finish()?;
            }
            Ok(())
        }
    }

    /// Whether the `IPv6` loopback (`::1`) can be bound on this machine.
    fn ipv6_loopback_available() -> bool {
        std::net::UdpSocket::bind("[::1]:0").is_ok()
    }

    /// Three members, A and C with no IP path to each other and B between them. The
    /// gossip links run over IP; a QUIC connection from A to C has only the gossip
    /// path, and an echo over it completes through the real flood.
    ///
    /// **Needs the `IPv6` loopback.** A binds `[::1]` only and C binds `127.0.0.1`
    /// only, which is what leaves them without an IP path to each other. On a
    /// machine that cannot bind `::1` the test logs that it was skipped and
    /// passes, so that a runner without `IPv6` does not go red.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_quic_echo_between_two_members_with_no_direct_path_completes_over_real_gossip() {
        if !ipv6_loopback_available() {
            eprintln!("SKIPPED: this machine cannot bind the IPv6 loopback [::1]");
            return;
        }
        let topic = TopicId::from_bytes([9u8; 32]);
        let lookups = [
            MemoryLookup::new(),
            MemoryLookup::new(),
            MemoryLookup::new(),
        ];
        let mut nodes = Vec::new();
        for (index, lookup) in lookups.iter().enumerate() {
            let key = secret(10 + u8::try_from(index).expect("small"));
            let handle = GossipHandle::new(key.public());
            // A has IPv6 loopback only, C has IPv4 only, and B has both: A and C have
            // no way to send each other an IP packet, whatever addresses they learn.
            let binds: &[&str] = match index {
                0 => &["[::1]:0"],
                1 => &["127.0.0.1:0", "[::1]:0"],
                _ => &["127.0.0.1:0"],
            };
            let mut builder = Endpoint::builder(presets::Minimal)
                .secret_key(key.clone())
                .relay_mode(RelayMode::Disabled)
                .clear_ip_transports()
                .add_custom_transport(handle.custom_transport())
                .path_selector(std::sync::Arc::new(Ladder))
                .address_lookup(lookup.clone());
            for bind in binds {
                builder = builder
                    .bind_addr(bind.parse::<std::net::SocketAddr>().expect("loopback"))
                    .expect("bind address");
            }
            let endpoint = builder.bind().await.expect("bind");
            nodes.push((endpoint, handle));
        }
        let (alice, bob, carol) = (&nodes[0], &nodes[1], &nodes[2]);
        // The gossip links: A and C each know B, and B knows both.
        lookups[0].add_endpoint_info(bob.0.addr());
        lookups[2].add_endpoint_info(bob.0.addr());
        lookups[1].add_endpoint_info(alice.0.addr());
        lookups[1].add_endpoint_info(carol.0.addr());
        let mut routers = Vec::new();
        let mut gossips = Vec::new();
        for (endpoint, _) in &nodes {
            let gossip = Gossip::builder().spawn(endpoint.clone());
            routers.push(
                Router::builder(endpoint.clone())
                    .accept(GOSSIP_ALPN, gossip.clone())
                    .accept(ECHO_ALPN, Echo)
                    .spawn(),
            );
            gossips.push(gossip);
        }
        let mut readers = Vec::new();
        // B joins first: A and C bootstrap on it, and wait for it to be there.
        for index in [1usize, 0, 2] {
            let (handle, gossip) = (&nodes[index].1, &gossips[index]);
            let topic_handle = if index == 1 {
                gossip.subscribe(topic, vec![]).await.expect("bob joins")
            } else {
                tokio::time::timeout(
                    Duration::from_secs(20),
                    gossip.subscribe_and_join(topic, vec![bob.0.id()]),
                )
                .await
                .expect("join timed out")
                .expect("join")
            };
            let (sender, receiver) = topic_handle.split();
            handle.attach_gossip(sender);
            readers.push(super::spawn_receive_loop(receiver, handle.clone()));
        }

        let to_carol = iroh::EndpointAddr::from_parts(
            carol.0.id(),
            [iroh::TransportAddr::Custom(crate::gossip_addr(
                carol.0.id(),
            ))],
        );
        let connection = tokio::time::timeout(
            Duration::from_secs(30),
            alice.0.connect(to_carol, ECHO_ALPN),
        )
        .await
        .expect("connect timed out")
        .expect("connect over real gossip");
        let (mut send, mut recv) = connection.open_bi().await.expect("stream");
        send.write_all(b"through the flood").await.expect("write");
        send.finish().expect("finish");
        let echoed = tokio::time::timeout(Duration::from_secs(30), recv.read_to_end(1024))
            .await
            .expect("the echo timed out")
            .expect("read");

        assert_eq!(echoed, b"through the flood");
        let selected_is_gossip = connection.paths().iter().any(|path| {
            path.is_selected()
                && matches!(path.remote_addr(), iroh::TransportAddr::Custom(addr) if addr.id() == crate::GOSSIP_TRANSPORT_ID)
        });
        let paths: Vec<String> = connection
            .paths()
            .iter()
            .map(|path| format!("{:?} selected={}", path.remote_addr(), path.is_selected()))
            .collect();
        assert!(
            selected_is_gossip,
            "the selected path is not gossip: {paths:?}"
        );
        assert!(bob.1.stats().frames_in > 0, "the flood did not pass bob");
        assert!(bob.1.stats().not_for_us > 0, "bob only reads the flood");
        connection.close(0u32.into(), b"done");
        for reader in readers {
            reader.abort();
        }
    }

    /// When the topic closes, the sink's task ends, and the path is not valid any
    /// more: a packet on it would go nowhere.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_closed_topic_makes_the_path_invalid() {
        let lookup = MemoryLookup::new();
        let (endpoint, gossip, _router) = member(5, &lookup).await;
        let handle = GossipHandle::new(endpoint.id());
        let topic = gossip
            .subscribe(TopicId::from_bytes([3u8; 32]), vec![])
            .await
            .expect("join");
        let (sender, _receiver) = topic.split();
        handle.attach_gossip(sender);
        assert!(
            handle.shared.path_is_valid(),
            "valid while the topic is open"
        );

        gossip.shutdown().await.expect("shutdown");
        let other = secret(6).public();
        for _ in 0..100 {
            handle.shared.send_datagram(other, &[1u8; 50]);
            if !handle.shared.path_is_valid() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert!(!handle.shared.path_is_valid(), "the topic is closed");
        let before = handle.stats().dropped_no_sink;
        handle.shared.send_datagram(other, &[1u8; 50]);
        assert_eq!(
            handle.stats().dropped_no_sink,
            before + 1,
            "counted as no sink"
        );
    }

    /// A `Lagged` event of the topic is counted, and the other events that carry no
    /// frame change nothing.
    #[test]
    fn a_lagged_event_is_counted_and_a_neighbor_event_is_not() {
        let handle = GossipHandle::new(secret(1).public());

        super::handle_event(&handle, Event::Lagged);
        super::handle_event(&handle, Event::Lagged);
        super::handle_event(&handle, Event::NeighborUp(secret(2).public()));

        assert_eq!(handle.stats().topic_lagged, 2);
        assert_eq!(handle.stats().frames_in, 0);
    }
}
