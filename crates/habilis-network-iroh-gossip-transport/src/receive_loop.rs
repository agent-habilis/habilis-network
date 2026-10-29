//! The task that reads a gossip topic into a handle.

use iroh_gossip::api::{Event, GossipReceiver};

use crate::GossipHandle;

/// The task of [`spawn_receive_loop`]. `abort()` stops it.
///
/// # Examples
///
/// The loop reads a live gossip receiver, so this is not compiled.
///
/// ```ignore
/// let task = spawn_receive_loop(receiver, handle);
/// task.abort();
/// ```
pub type ReceiveLoop = n0_future::task::JoinHandle<()>;

/// Read a topic and hand every message to `handle`, until the topic ends.
///
/// For a topic that carries **only** transport frames, as a test or a benchmark does.
/// On the mesh topic the engine splits the frames from the mesh messages before
/// it hands anything to a handle (design doc, section 2.5): this loop does not.
///
/// # Examples
///
/// It reads a live gossip receiver, so this is not compiled.
///
/// ```ignore
/// let task = spawn_receive_loop(receiver, handle);
/// task.abort();
/// ```
#[must_use]
pub fn spawn_receive_loop(mut receiver: GossipReceiver, handle: GossipHandle) -> ReceiveLoop {
    use n0_future::StreamExt as _;
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use iroh::address_lookup::memory::MemoryLookup;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::{Endpoint, RelayMode, SecretKey};
    use iroh_gossip::api::Event;
    use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
    use iroh_gossip::proto::TopicId;

    use crate::{GossipHandle, frame};

    use iroh::endpoint::transports;
    fn secret(seed: u8) -> SecretKey {
        SecretKey::from_bytes(&[seed; 32])
    }

    async fn member(seed: u8, lookup: &MemoryLookup) -> (Endpoint, Gossip, Router) {
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret(seed))
            .relay_mode(RelayMode::Disabled);
        let bound = builder
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("bind address");
        let endpoint: Endpoint = bound
            .address_lookup(lookup.clone())
            .bind()
            .await
            .expect("bind");
        lookup.add_endpoint_info(endpoint.addr());
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let accepting = Router::builder(endpoint.clone()).accept(GOSSIP_ALPN, gossip.clone());
        let router = accepting.spawn();
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
    #[test]
    fn a_frame_sent_through_a_real_topic_reaches_the_other_member() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let lookup = MemoryLookup::new();
                let (alice_endpoint, alice_gossip, alice_router) = member(1, &lookup).await;
                let (bob_endpoint, bob_gossip, bob_router) = member(2, &lookup).await;
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
                assert_eq!(
                    bob_stats.bytes_in,
                    (frame::HEADER_LEN + 100) as u64,
                    "a frame through a real topic reaches the other member's byte counter"
                );
                reader.abort();
                alice_router.shutdown().await.expect("shutdown");
                bob_router.shutdown().await.expect("shutdown");
            },
        );
    }

    /// The ladder: IP first, then gossip.
    #[derive(Debug)]
    struct Ladder;

    impl transports::PathSelector for Ladder {
        fn select(
            &self,
            context: &transports::PathSelectionContext<'_>,
        ) -> transports::PathSelection {
            use habilis_network_iroh_transport_util::{climb, custom_rung};
            let paths: Vec<_> = context.paths().collect();
            let mut selection = transports::PathSelection::none();
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
    #[test]
    fn a_quic_echo_between_two_members_with_no_direct_path_completes_over_real_gossip() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            4,
            async {
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
                    let mut builder: iroh::endpoint::Builder = Endpoint::builder(presets::Minimal);
                    builder = builder.secret_key(key.clone());
                    builder = builder.relay_mode(RelayMode::Disabled);
                    builder = builder.clear_ip_transports();
                    builder = builder.add_custom_transport(handle.custom_transport());
                    // trait object: the endpoint builder takes the selector by Arc
                    builder = builder.path_selector(std::sync::Arc::new(Ladder));
                    builder = builder.address_lookup(lookup.clone());
                    for bind in binds {
                        let bind: SocketAddr = bind.parse().expect("loopback");
                        builder = builder.bind_addr(bind).expect("bind address");
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
                    let router =
                        Router::builder(endpoint.clone()).accept(GOSSIP_ALPN, gossip.clone());
                    routers.push(router.accept(ECHO_ALPN, Echo).spawn());
                    gossips.push(gossip);
                }
                let mut readers = Vec::new();
                // B joins first: A and C bootstrap on it, and wait for it to be there.
                for index in [1usize, 0, 2] {
                    let (handle, gossip) = (&nodes[index].1, &gossips[index]);
                    let topic_handle: iroh_gossip::api::GossipTopic = if index == 1 {
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

                assert_eq!(
                    echoed, b"through the flood",
                    "a quic echo between members with no direct path completes over gossip"
                );
                let selected_is_gossip: bool = connection.paths().iter().any(|path| {
                path.is_selected()
                    && matches!(path.remote_addr(), iroh::TransportAddr::Custom(address) if address.id() == crate::GOSSIP_TRANSPORT_ID)
            });
                let mut paths: Vec<String> = Vec::new();
                for path in connection.paths().iter() {
                    paths.push(format!(
                        "{:?} selected={}",
                        path.remote_addr(),
                        path.is_selected()
                    ));
                }
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
                for router in routers {
                    router.shutdown().await.expect("shutdown");
                }
            },
        );
    }

    /// When the topic closes, the sink's task ends, and the path is not valid any
    /// more: a packet on it would go nowhere.
    #[test]
    fn a_closed_topic_makes_the_path_invalid() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let lookup = MemoryLookup::new();
                let (endpoint, gossip, router) = member(5, &lookup).await;
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
                // The gossip is shut down already, and a shutdown of the router would shut it down
                // again and warn. The router goes first, so that it does not run its shutdown when
                // the endpoint closes.
                drop(router);
                endpoint.close().await;
            },
        );
    }

    /// A `Lagged` event of the topic is counted, and the other events that carry no
    /// frame change nothing.
    #[test]
    fn a_lagged_event_is_counted_and_a_neighbor_event_is_not() {
        let _guard = ::habilis_network_test_tracing::init();
        let handle = GossipHandle::new(secret(1).public());

        super::handle_event(&handle, Event::Lagged);
        super::handle_event(&handle, Event::Lagged);
        super::handle_event(&handle, Event::NeighborUp(secret(2).public()));

        assert_eq!(handle.stats().topic_lagged, 2, "a lagged event is counted");
        assert_eq!(
            handle.stats().frames_in,
            0,
            "a lagged event does not count the frames in"
        );
    }
}
