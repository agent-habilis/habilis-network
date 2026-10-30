use super::{TransportOpts, build_peer_endpoint};
use crate::protocol::meshes::{LookupOpts, RelayChoice, TransportPolicy};
use crate::transport::PayloadPath;
use std::collections::HashSet;

#[cfg(feature = "host")]
use crate::transport;
#[cfg(feature = "host")]
use crate::transport::payload_path;
use crate::transport::webrtc;
#[cfg(feature = "host")]
use habilis_network_iroh_gossip_transport::hub;
use iroh::address_lookup::memory;
#[cfg(feature = "host")]
use iroh::endpoint;
#[cfg(feature = "host")]
use iroh::endpoint::presets;
#[cfg(all(feature = "host", feature = "mdns"))]
use iroh::endpoint_info;
#[cfg(feature = "host")]
use iroh::protocol;
#[cfg(all(feature = "host", feature = "mdns"))]
use iroh_gossip::api;
#[cfg(all(feature = "host", feature = "mdns"))]
use iroh_gossip::proto;
use n0_future::{task, time};
#[cfg(all(feature = "host", feature = "mdns"))]
use std::io;
use std::net;
use std::time::Duration as std_Duration;
#[cfg(all(feature = "host", feature = "mdns"))]
use tokio::sync::mpsc;
use tokio::time as tokio_time;
use tokio::time::Instant as tokio_Instant;
/// R1: the tag of a mesh is the same for one topic, differs between topics (the topic id
/// folds in the password: two rooms of one name with two passwords are two topics) and fits the
/// user data of an endpoint.
#[cfg(all(feature = "host", feature = "mdns"))]
#[test]
fn the_lan_tag_follows_the_topic() {
    let _guard = ::habilis_network_test_tracing::init();
    let one = proto::TopicId::from_bytes([1u8; 32]);
    let other = proto::TopicId::from_bytes([2u8; 32]);

    assert_eq!(
        super::lan::lan_member_tag(&one),
        super::lan::lan_member_tag(&one),
        "the lan tag is the same for the same topic"
    );
    assert_ne!(
        super::lan::lan_member_tag(&one),
        super::lan::lan_member_tag(&other),
        "the lan tag differs between topics"
    );
    let user_data: Result<endpoint_info::UserData, _> = super::lan::lan_member_tag(&one).parse();
    assert!(user_data.is_ok(), "the tag must fit the user data");
}

/// R1: our tag in, a foreign tag out, no user data out.
#[cfg(all(feature = "host", feature = "mdns"))]
#[test]
fn only_our_tag_is_a_member_of_our_mesh() {
    let _guard = ::habilis_network_test_tracing::init();
    let ours = super::lan::lan_member_tag(&proto::TopicId::from_bytes([1u8; 32]));
    let foreign = super::lan::lan_member_tag(&proto::TopicId::from_bytes([2u8; 32]));
    let user = |text: &str| -> endpoint_info::UserData { text.parse().expect("fits") };

    assert!(
        super::mdns::is_member_tag(Some(&user(&ours)), &ours),
        "only our tag counts as a member of our mesh"
    );
    assert!(
        !super::mdns::is_member_tag(Some(&user(&foreign)), &ours),
        "a foreign tag is not a member of our mesh"
    );
    assert!(
        !super::mdns::is_member_tag(Some(&user("hello")), &ours),
        "a tag that is not a mesh tag is not a member of our mesh"
    );
    assert!(
        !super::mdns::is_member_tag(None, &ours),
        "a missing tag is not a member of our mesh"
    );
}

/// R2 (the forwarder's filter): a new id passes, the same record again does not, a changed record
/// does, and a `Gone` passes only for an id that was passed before.
#[cfg(all(feature = "host", feature = "mdns"))]
#[test]
fn the_forwarder_passes_news_only() {
    use std::collections::HashMap;

    use super::{LanEvent, mdns};

    let _guard = ::habilis_network_test_tracing::init();
    let id = iroh::SecretKey::generate().public();
    let stranger = iroh::SecretKey::generate().public();
    let at = |port: u16| {
        iroh::EndpointAddr::new(id)
            .with_ip_addr(net::SocketAddr::from((net::Ipv4Addr::LOCALHOST, port)))
    };
    let mut known = HashMap::new();

    assert_eq!(
        mdns::news_only(LanEvent::Gone(stranger), &mut known),
        None,
        "a Gone for an id never passed ends here"
    );
    assert!(
        mdns::news_only(LanEvent::Seen(at(1)), &mut known).is_some(),
        "the forwarder passes a newly seen peer"
    );
    assert_eq!(
        mdns::news_only(LanEvent::Seen(at(1)), &mut known),
        None,
        "the same record again is the refresh, not news"
    );
    assert!(
        mdns::news_only(LanEvent::Seen(at(2)), &mut known).is_some(),
        "a changed record is news"
    );
    assert_eq!(
        mdns::news_only(LanEvent::Gone(id), &mut known),
        Some(LanEvent::Gone(id)),
        "the forwarder passes a peer that is gone"
    );
    assert_eq!(
        mdns::news_only(LanEvent::Gone(id), &mut known),
        None,
        "the forwarder drops a repeated gone event"
    );
}

/// R3: two members of one mesh and a stranger of another, all on the LAN with mDNS and no
/// beacon at all. The members hear each other through the mDNS stream, graft each other, and
/// become gossip neighbors; the stranger is never reported. The test runs on a host that sends
/// multicast; where it cannot, nothing is discovered and the test fails on the deadline, which
/// the slot reports as VOID for fix C, never as green.
#[cfg(all(feature = "host", feature = "mdns"))]
#[test]
#[ignore = "needs a host that sends mDNS multicast: run with --ignored --nocapture"]
fn two_members_on_the_lan_link_with_no_beacon() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            use std::io::Write as _;
            use std::time::{Duration, Instant};

            use futures_util::StreamExt as _;
            use iroh_gossip::api::Event;

            use iroh::Endpoint;
            use iroh::address_lookup::memory::MemoryLookup;
            use iroh::protocol::Router;
            use iroh_gossip::net::{GOSSIP_ALPN, Gossip};

            use super::{LanEvent, TransportHandles, address_book};

            struct Member {
                endpoint: Endpoint,
                book: MemoryLookup,
                sender: api::GossipSender,
                receiver: api::GossipReceiver,
                events: mpsc::Receiver<LanEvent>,
                _router: Router,
            }

            async fn member(topic: proto::TopicId) -> Member {
                let lan = LookupOpts::new(RelayChoice::Disabled).mdns(true);
                let (endpoint, handle) = super::build_endpoint_keeping_mdns(
                    &lan,
                    None,
                    None,
                    Vec::new(),
                    TransportHandles::default(),
                )
                .await
                .expect("a LAN endpoint");
                super::lan::tag_as_member(&endpoint, &topic).expect("the tag fits");
                let gossip = Gossip::builder().spawn(endpoint.clone());
                let router_builder =
                    Router::builder(endpoint.clone()).accept(GOSSIP_ALPN, gossip.clone());
                let router = router_builder.spawn();
                let (sender, receiver) = gossip
                    .subscribe(topic, Vec::new())
                    .await
                    .expect("subscribe without a bootstrap")
                    .split();
                let events = super::mdns::spawn_lan_contacts(
                    &handle.expect("mDNS is wired on a LAN endpoint"),
                    super::lan::lan_member_tag(&topic),
                    endpoint.id(),
                )
                .await;
                Member {
                    book: address_book(&endpoint),
                    endpoint,
                    sender,
                    receiver,
                    events,
                    _router: router,
                }
            }

            let topic = proto::TopicId::from_bytes([3u8; 32]);
            let other_topic = proto::TopicId::from_bytes([4u8; 32]);
            let started = Instant::now();
            let mut first = member(topic).await;
            let mut second = member(topic).await;
            let stranger = member(other_topic).await;
            let ids = (first.endpoint.id(), second.endpoint.id());
            let mut stderr = io::stderr();
            let mut seen_first = HashSet::new();
            let mut seen_second = HashSet::new();
            let mut neighbors = (false, false);

            let deadline = tokio_time::sleep(Duration::from_secs(30));
            tokio::pin!(deadline);
            while !(neighbors.0 && neighbors.1) {
                tokio::select! {
                    () = &mut deadline => break,
                    Some(event) = first.events.recv() => {
                        if let LanEvent::Seen(address) = event {
                            let _ = writeln!(stderr, "lan: first saw {} at {:?}", address.id.fmt_short(), started.elapsed());
                            seen_first.insert(address.id);
                            first.book.add_endpoint_info(address.clone());
                            first.sender.neighbor_peers(vec![address.id]).await.expect("graft request");
                        }
                    }
                    Some(event) = second.events.recv() => {
                        if let LanEvent::Seen(address) = event {
                            let _ = writeln!(stderr, "lan: second saw {} at {:?}", address.id.fmt_short(), started.elapsed());
                            seen_second.insert(address.id);
                            second.book.add_endpoint_info(address.clone());
                            second.sender.neighbor_peers(vec![address.id]).await.expect("graft request");
                        }
                    }
                    Some(Ok(Event::NeighborUp(id))) = first.receiver.next() => {
                        if id == ids.1 {
                            let _ = writeln!(stderr, "lan: first has the second as neighbor at {:?}", started.elapsed());
                            neighbors.0 = true;
                        }
                    }
                    Some(Ok(Event::NeighborUp(id))) = second.receiver.next() => {
                        if id == ids.0 {
                            let _ = writeln!(stderr, "lan: second has the first as neighbor at {:?}", started.elapsed());
                            neighbors.1 = true;
                        }
                    }
                }
            }

            assert!(
                neighbors.0 && neighbors.1,
                "the two members did not become gossip neighbors through the LAN within 30 s: first saw {seen_first:?}, second saw {seen_second:?}, neighbors {neighbors:?}"
            );
            assert!(
                !seen_first.contains(&stranger.endpoint.id())
                    && !seen_second.contains(&stranger.endpoint.id()),
                "a member of another mesh was reported"
            );
            first.endpoint.close().await;
            second.endpoint.close().await;
            stranger.endpoint.close().await;
        },
    );
}

/// A merge kept the address of every beacon that this process held under the rendezvous id.
#[test]
fn replacing_a_peer_address_leaves_exactly_the_new_one() {
    use super::{add_peer_addr, replace_peer_addr};

    let _guard = ::habilis_network_test_tracing::init();
    let book = memory::MemoryLookup::new();
    let id = iroh::SecretKey::generate().public();
    let at = |port: u16| {
        iroh::EndpointAddr::new(id)
            .with_ip_addr(net::SocketAddr::from((net::Ipv4Addr::LOCALHOST, port)))
    };
    add_peer_addr(&book, at(4000));

    replace_peer_addr(&book, at(5000));

    let entry = book
        .get_endpoint_info(id)
        .expect("an entry")
        .into_endpoint_addr();
    let ip_addrs: Vec<_> = entry.ip_addrs().copied().collect();
    assert_eq!(
        ip_addrs,
        vec![net::SocketAddr::from((net::Ipv4Addr::LOCALHOST, 5000))],
        "the book keeps the address of a beacon that is gone"
    );
}

#[test]
fn the_mesh_policy_turns_off_the_paths_it_leaves_out() {
    let _guard = ::habilis_network_test_tracing::init();
    let webrtc_only = TransportPolicy::default().udp(false);
    let on_webrtc = TransportOpts::default().within(&webrtc_only);
    assert!(
        !on_webrtc.udp && on_webrtc.webrtc && on_webrtc.relay,
        "the webrtc policy turns off the paths it leaves out"
    );

    let udp_only = TransportPolicy::default().webrtc(false);
    let on_udp = TransportOpts::default().within(&udp_only);
    assert!(
        on_udp.udp && !on_udp.webrtc && on_udp.relay,
        "the udp policy keeps udp and relay and turns off webrtc"
    );

    let narrow_node = TransportOpts::webrtc_only().within(&TransportPolicy::default());
    assert!(
        !narrow_node.udp && narrow_node.webrtc,
        "a mesh never turns on a path the node lacks"
    );
}

// Binds the `Minimal`-based reachable branch (the default relay
// ladder, no lookup wired) and the loopback all-off branch. mDNS
// multicast / mainline-DHT socket setup is environment-dependent, so
// it is not exercised here; presence-allowlist resolution is
// unit-tested in `protocol::meshes`, and the relay ladder logic in
// [`super::relay`].

/// **A receiver that never reads grants the whole window to one stream.** Every endpoint of the
/// engine sets the QUIC windows of decision D11: 16 `MiB` for a stream and for a connection, far
/// above the iroh default of about 1.2 `MiB`, so that one blob stream can use the whole window, and
/// still a bound for a peer that sends faster than the node reads. The test pins the value, so
/// that a change of the constant is a change of the test.
///
/// The sender is a plain iroh endpoint whose own buffer is capped at 64 `KiB`. It cannot get
/// more than that ahead of what the receiver has taken in, so the bytes that its writes
/// accept, less its own buffer, are what the receiver granted. Nobody reads at the receiver.
#[cfg(feature = "host")]
#[test]
fn a_receiver_that_never_reads_grants_the_whole_window_to_one_stream() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            use std::sync::Arc;
            use std::sync::atomic::{AtomicUsize, Ordering};
            use std::time::Duration;

            const ALPN: &[u8] = b"habilis-test/flood/0";
            const WINDOW: usize = 16 * 1024 * 1024;
            const SENDER_BUFFER: usize = 64 * 1024;
            let receiver = super::build_endpoint(
                &LookupOpts::loopback(),
                None,
                None,
                vec![ALPN.to_vec()],
                super::TransportHandles::default(),
            )
            .await
            .expect("bind the receiver");
            let transport = endpoint::QuicTransportConfig::builder()
                .send_window(SENDER_BUFFER as u64)
                .build();
            let sender: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .transport_config(transport)
                .bind()
                .await
                .expect("bind the sender");

            let receiving = tokio::spawn({
                let receiver = receiver.clone();
                async move {
                    let incoming = receiver.accept().await.expect("an incoming connection");
                    let connection = incoming.await.expect("the handshake");
                    let stream = connection.accept_uni().await.expect("a stream");
                    // Nothing is read: the connection and the stream stay open and unread.
                    tokio_time::sleep(Duration::from_secs(10)).await;
                    drop((connection, stream));
                }
            });
            let connection = sender
                .connect(receiver.addr(), ALPN)
                .await
                .expect("connect to the receiver");
            let mut stream = connection.open_uni().await.expect("open a stream");
            // the writers and the test share the accepted count
            let accepted = Arc::new(AtomicUsize::new(0));
            let writing = tokio::spawn({
                let accepted = Arc::clone(&accepted);
                async move {
                    let chunk = vec![0u8; 16 * 1024];
                    while stream.write_all(&chunk).await.is_ok() {
                        accepted.fetch_add(chunk.len(), Ordering::Relaxed);
                    }
                }
            });

            tokio_time::sleep(Duration::from_secs(2)).await;
            let taken_in = accepted
                .load(Ordering::Relaxed)
                .saturating_sub(SENDER_BUFFER);
            writing.abort();
            receiving.abort();

            assert!(
                taken_in > WINDOW - 4 * 1024 * 1024 && taken_in <= WINDOW + 64 * 1024,
                "the receiver took in {taken_in} bytes of a stream nobody read; the window is {WINDOW}"
            );
            sender.close().await;
            receiver.close().await;
        },
    );
}

/// **Many streams that nobody reads still fit in the connection window.** Forty streams
/// at 16 `MiB` each could hold 640 `MiB`; the window of the connection (decision D11) holds the
/// receiver to 16 `MiB` for all of them together, where the iroh defaults let it take in about
/// 47 `MiB`. The test pins the value, and also that the receiver does take in the window. Counted
/// at the sender, as in
/// `a_receiver_that_never_reads_grants_the_whole_window_to_one_stream`.
#[cfg(feature = "host")]
#[test]
fn streams_that_nobody_reads_fit_in_the_connection_window() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            use std::sync::Arc;
            use std::sync::atomic::{AtomicUsize, Ordering};
            use std::time::Duration;

            const ALPN: &[u8] = b"habilis-test/flood/1";
            const WINDOW: usize = 16 * 1024 * 1024;
            const SENDER_BUFFER: usize = 64 * 1024;
            const STREAMS: usize = 40;
            let receiver = super::build_endpoint(
                &LookupOpts::loopback(),
                None,
                None,
                vec![ALPN.to_vec()],
                super::TransportHandles::default(),
            )
            .await
            .expect("bind the receiver");
            let transport = endpoint::QuicTransportConfig::builder()
                .send_window(SENDER_BUFFER as u64)
                .build();
            let sender: iroh::Endpoint = iroh::Endpoint::builder(presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .transport_config(transport)
                .bind()
                .await
                .expect("bind the sender");

            let receiving = tokio::spawn({
                let receiver = receiver.clone();
                async move {
                    let incoming = receiver.accept().await.expect("an incoming connection");
                    let connection = incoming.await.expect("the handshake");
                    let mut streams = Vec::new();
                    while let Ok(stream) = connection.accept_uni().await {
                        streams.push(stream);
                    }
                }
            });
            let connection = sender
                .connect(receiver.addr(), ALPN)
                .await
                .expect("connect to the receiver");
            // the writers and the test share the accepted count
            let accepted = Arc::new(AtomicUsize::new(0));
            let mut writers = Vec::new();
            for _ in 0..STREAMS {
                let mut stream = connection.open_uni().await.expect("open a stream");
                let accepted = Arc::clone(&accepted);
                writers.push(tokio::spawn(async move {
                    let chunk = vec![0u8; 16 * 1024];
                    while stream.write_all(&chunk).await.is_ok() {
                        accepted.fetch_add(chunk.len(), Ordering::Relaxed);
                    }
                }));
            }

            tokio_time::sleep(Duration::from_secs(6)).await;
            let taken_in = accepted
                .load(Ordering::Relaxed)
                .saturating_sub(SENDER_BUFFER);
            for writer in writers {
                writer.abort();
            }
            receiving.abort();

            assert!(
                taken_in > WINDOW - 4 * 1024 * 1024 && taken_in <= WINDOW + 64 * 1024,
                "the receiver took in {taken_in} bytes of {STREAMS} streams nobody read; the connection window is {WINDOW}"
            );
            sender.close().await;
            receiver.close().await;
        },
    );
}

// An address that changes is told again, so addresses are registered again and again for one
// endpoint. The endpoint has one lookup service for them, made once by `address_book`, not one
// per registration.
#[test]
fn the_addresses_of_one_endpoint_go_to_one_lookup_service() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        let peer = iroh::SecretKey::generate().public();
        let at =
            |ip: &str| iroh::EndpointAddr::new(peer).with_ip_addr(ip.parse().expect("an address"));
        let first = build_peer_endpoint(&LookupOpts::loopback())
            .await
            .expect("loopback endpoint must bind");
        let second = build_peer_endpoint(&LookupOpts::loopback())
            .await
            .expect("loopback endpoint must bind");
        let services =
            |endpoint: &iroh::Endpoint| endpoint.address_lookup().expect("lookup services").len();
        let (first_before, second_before) = (services(&first), services(&second));

        let first_book = super::address_book(&first);
        super::add_peer_addr(&first_book, at("192.0.2.1:4000"));
        super::add_peer_addr(&first_book, at("192.0.2.2:4000"));
        let second_book = super::address_book(&second);
        super::add_peer_addr(&second_book, at("192.0.2.3:4000"));

        assert_eq!(
            services(&first),
            first_before + 1,
            "two registrations for one endpoint add one lookup service"
        );
        assert_eq!(
            services(&second),
            second_before + 1,
            "another endpoint has a book of its own"
        );
        first.close().await;
        second.close().await;
    });
}

#[test]
fn loopback_all_off_binds() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        let endpoint = build_peer_endpoint(&LookupOpts::loopback())
            .await
            .expect("loopback endpoint must bind");
        endpoint.close().await;
    });
}

// A handles value with only gossip is a member endpoint: it must not read as a beacon.
#[test]
fn a_handles_value_with_only_gossip_is_not_empty() {
    let _guard = ::habilis_network_test_tracing::init();
    let handle = habilis_network_iroh_gossip_transport::GossipHandle::new(
        iroh::SecretKey::from_bytes(&[51; 32]).public(),
    );
    assert!(
        super::TransportHandles::default().is_empty(),
        "a default handles value is empty"
    );
    let only_gossip = super::TransportHandles {
        gossip: Some(handle),
        ..super::TransportHandles::default()
    };
    assert!(
        !only_gossip.is_empty(),
        "a handles value with only gossip is not empty"
    );
}

// Gossip is a choice of the mesh: the opts follow the policy, and it needs a direct path.
#[test]
fn the_mesh_policy_decides_gossip_for_the_opts() {
    let _guard = ::habilis_network_test_tracing::init();
    let policy = |gossip: bool, udp: bool, webrtc: bool| {
        TransportPolicy::default()
            .gossip(gossip)
            .udp(udp)
            .webrtc(webrtc)
    };
    let within = |mesh: TransportPolicy| TransportOpts::default().within(&mesh).gossip.is_on();
    assert!(
        !TransportOpts::default().gossip.is_on(),
        "off until the mesh asks"
    );
    assert!(
        within(policy(true, true, true)),
        "the mesh policy decides gossip when it is within reach"
    );
    assert!(within(policy(true, false, true)), "webrtc is a direct path");
    assert!(
        !within(policy(false, true, true)),
        "the mesh policy does not decide gossip outside reach"
    );
    assert!(
        !within(policy(true, false, false)),
        "no direct path to ride"
    );
}

// The gossip transport is on the member endpoint and nowhere else: not on the multihop
// underlay. iroh does not list the address of a custom transport in `Endpoint::addr` (the
// `WebRTC` one is not there either), so the reading is the admission table, which keeps the
// handle that the member endpoint was built with: the member's table has it, and the
// underlay's does not. The member of a mesh without gossip has none. A beacon is built from
// `TransportHandles::default()`, which has no gossip, and from opts that never name it.
#[cfg(feature = "host")]
#[test]
fn only_the_member_endpoint_has_the_gossip_handle() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        let build = |gossip: bool| async move {
            let options = TransportOpts {
                gossip: gossip.into(),
                ..TransportOpts::default()
            };
            let table = transport::SignalAdmission::new(8);
            let (endpoint, handle, _webrtc, leg, _mdns) = super::build_peer_multihop_with(
                &LookupOpts::loopback(),
                options,
                Some(&table),
                super::multihop_handle_config(PayloadPath::DirectOnly),
                Some(5),
            )
            .await
            .expect("a multihop peer binds");
            handle.close().await;
            endpoint.close().await;
            (table, leg.expect("a leg when a cap is given"))
        };

        let (member_table, leg) = build(true).await;
        assert!(
            member_table.gossip_handle().is_some(),
            "the member endpoint has the handle"
        );
        assert!(
            leg.admission.gossip_handle().is_none(),
            "the multihop underlay does not"
        );
        let (table_without, _leg) = build(false).await;
        assert!(
            table_without.gossip_handle().is_none(),
            "a mesh without gossip has none"
        );
        assert!(
            super::TransportHandles::default().gossip.is_none(),
            "a default handles value has no gossip handle"
        );
    });
}

// The list `udp,gossip` has no WebRTC and no multihop, so no other selector is installed: the
// member still gets the gossip handle (the admission table keeps it), the gossip address,
// and the ladder of the gossip handle, which keeps IP above gossip.
#[cfg(feature = "host")]
#[test]
fn the_member_of_a_udp_and_gossip_list_keeps_ip_above_gossip() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        use habilis_network_iroh_gossip_transport;
        use std::time::Duration;

        use iroh::protocol::{AcceptError, ProtocolHandler};

        const ALPN: &[u8] = b"habilis-network/test-udp-gossip-list/0";
        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, connection: endpoint::Connection) -> Result<(), AcceptError> {
                connection.closed().await;
                Ok(())
            }
        }
        let options = TransportOpts {
            webrtc: false,
            gossip: true.into(),
            ..TransportOpts::default()
        };
        let hub = hub::Hub::new();
        let mut members = Vec::new();
        for _ in 0..2 {
            let table = transport::SignalAdmission::new(8);
            let (endpoint, _webrtc, _mdns) =
                super::build_peer_webrtc_with(&LookupOpts::loopback(), options, Some(&table))
                    .await
                    .expect("a member binds");
            let handle = table
                .gossip_handle()
                .expect("the table keeps the gossip handle");
            hub.join(&handle);
            members.push(endpoint);
        }
        let (alice, bob) = (members.remove(0), members.remove(0));
        let router = protocol::Router::builder(bob.clone())
            .accept(ALPN, Hold)
            .spawn();
        let bob_addr = bob.addr();
        let both = bob_addr
            .addrs
            .into_iter()
            .chain([iroh::TransportAddr::Custom(
                habilis_network_iroh_gossip_transport::gossip_addr(bob.id()),
            )]);
        let connection = alice
            .connect(iroh::EndpointAddr::from_parts(bob.id(), both), ALPN)
            .await
            .expect("connect");

        let paths_deadline = tokio_Instant::now() + Duration::from_secs(5);
        while connection.paths().len() < 2 && tokio_Instant::now() < paths_deadline {
            tokio_time::sleep(Duration::from_millis(50)).await;
        }
        assert!(connection.paths().len() >= 2, "IP and gossip are both open");
        let selected_deadline = tokio_Instant::now() + Duration::from_secs(5);
        while connection
            .paths()
            .iter()
            .find(endpoint::Path::is_selected)
            .is_none()
            && tokio_Instant::now() < selected_deadline
        {
            tokio_time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            payload_path::selected_is_ip(&connection),
            "IP is above gossip: the ladder of the gossip handle is the selector"
        );
        router.shutdown().await.expect("shutdown");
        alice.close().await;
    });
}

// The underlay gets a `WebRTC` leg only when it is asked for, and only when
// this instance has `WebRTC` on. Its table takes the cap it is given (G).
// A browser advertises its links at ten times the cost; every other number is the engine's.
#[cfg(feature = "multihop")]
#[test]
fn the_handle_config_of_a_browser_differs_from_the_engine_s_in_the_link_cost_only() {
    let _guard = ::habilis_network_test_tracing::init();
    let native = super::multihop_handle_config(PayloadPath::RelayAllowed);
    let browser = super::peer::browser_handle_config(PayloadPath::RelayAllowed);
    assert_eq!(native.link_cost, 10, "the native link cost is the engine's");
    assert_eq!(
        browser.link_cost, 100,
        "the browser link cost differs from the engine's"
    );
    assert_eq!(
        browser.link_cost(native.link_cost),
        native,
        "apart from the link cost the browser config matches the engine"
    );
}

#[cfg(feature = "host")]
#[test]
fn the_underlay_leg_takes_the_cap_it_is_given_and_needs_webrtc_on() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        let build = |options: TransportOpts, cap: Option<usize>| async move {
            super::build_peer_multihop_with(
                &LookupOpts::loopback(),
                options,
                None,
                super::multihop_handle_config(PayloadPath::DirectOnly),
                cap,
            )
            .await
            .expect("a multihop peer binds")
        };

        let (endpoint, handle, _webrtc, leg, _mdns) =
            build(TransportOpts::default(), Some(5)).await;
        let leg = leg.expect("a leg when a cap is given");
        assert_eq!(leg.admission.cap(), 5, "the table has the cap of G");
        assert_eq!(
            leg.endpoint.id(),
            handle.underlay_id().get(),
            "the leg is on the underlay"
        );
        assert_eq!(
            leg.handle.session_count(),
            0,
            "the underlay leg starts with no sessions"
        );
        handle.close().await;
        endpoint.close().await;

        let (capless_endpoint, capless_handle, _, without_cap, _) =
            build(TransportOpts::default(), None).await;
        capless_handle.close().await;
        capless_endpoint.close().await;
        assert!(without_cap.is_none(), "no cap, no leg");
        let off = TransportOpts {
            webrtc: false,
            ..TransportOpts::default()
        };
        let (off_endpoint, off_handle, _, webrtc_off, _) = build(off, Some(5)).await;
        off_handle.close().await;
        off_endpoint.close().await;
        assert!(webrtc_off.is_none(), "WebRTC off, no leg");
    });
}

// A test can switch the leg of the underlay off for the whole process, which
// is the control cell of a measurement.
#[cfg(all(feature = "host", feature = "iroh-test-utils"))]
#[test]
fn a_test_can_switch_the_underlay_leg_off() {
    let _guard = ::habilis_network_test_tracing::init();
    assert_eq!(super::underlay_cap(7), Some(7), "on by default");
    super::set_underlay_leg_off(true);
    assert_eq!(super::underlay_cap(7), None, "switched off");
    super::set_underlay_leg_off(false);
    assert_eq!(super::underlay_cap(7), Some(7), "switched on again");
}

// One identity per peer: the application endpoint (UDP and relay), the
// WebRTC address and the multihop hop identity share one key. The underlay
// has a key of its own (see `build_peer_multihop`).
#[cfg(feature = "host")]
#[test]
fn one_key_serves_udp_webrtc_and_multihop() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        let (endpoint, handle, webrtc) = super::build_peer_multihop(
            &LookupOpts::loopback(),
            TransportOpts::default(),
            None,
            PayloadPath::DirectOnly,
        )
        .await
        .expect("a multihop peer binds");
        assert_eq!(handle.app_id().get(), endpoint.id(), "hop identity");
        assert_eq!(
            webrtc.transport().local_id(),
            endpoint.id(),
            "WebRTC address"
        );
        assert_ne!(
            handle.underlay_addr().id,
            endpoint.id(),
            "a relay hands an id's packets to one endpoint only"
        );
        handle.close().await;
        endpoint.close().await;
    });
}

// An injected endpoint's multihop handle must obey the mesh's relay rule. Its
// keys are checked when it is bound: see `InjectedEndpoint::bind`.
#[test]
fn an_injected_multihop_handle_must_obey_the_mesh_relay_rule() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        let lookups = LookupOpts::loopback();
        let (endpoint, _webrtc) = super::build_peer_webrtc(&lookups, TransportOpts::default())
            .await
            .expect("a peer binds");
        super::check_injected_against_mesh(&endpoint, false, &lookups, false)
            .expect("a handle that does not carry cells is allowed");
        let relay_error = super::check_injected_against_mesh(&endpoint, true, &lookups, false)
            .expect_err("relay cells on a lookup-only mesh");
        assert!(relay_error.to_string().contains("relay"), "{relay_error}");
        super::check_injected_against_mesh(&endpoint, true, &lookups, true)
            .expect("the mesh lets the relay carry cells");
        endpoint.close().await;
    });
}

/// The window of a starting holder: the rung is bound with an empty ALPN list and its router
/// has not set `GOSSIP_ALPN` yet (`build_endpoint` gives a rung exactly this before
/// `Router::spawn`). A dial on `GOSSIP_ALPN` then fails on the ALPN, which a listener sends
/// before any certificate: it proves nothing about the identity, so the probe must not
/// answer `Foreign`, which makes a walk bind a second rung.
#[test]
fn a_holder_of_our_identity_that_serves_no_alpn_yet_is_not_a_foreign_mesh() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        use std::net::SocketAddr;

        use iroh::{EndpointAddr, SecretKey};

        use super::{ProbeAnswer, TransportHandles, build_endpoint, probe_answer};

        let secret = SecretKey::generate();
        let id = secret.public();
        let bound = net::UdpSocket::bind((net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr());
        let port = bound.expect("a free loopback port").port();
        let holder = build_endpoint(
            &LookupOpts::loopback(),
            Some(secret),
            Some(port),
            Vec::new(),
            TransportHandles::default(),
        )
        .await
        .expect("a bound rung without a router");
        let driving = holder.clone();
        let task = task::spawn(async move {
            while let Some(incoming) = driving.accept().await {
                if let Ok(accepting) = incoming.accept() {
                    let _ = accepting.await;
                }
            }
        });
        let prober = build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            TransportHandles::default(),
        )
        .await
        .expect("a prober");
        let address =
            EndpointAddr::new(id).with_ip_addr(SocketAddr::from((net::Ipv4Addr::LOCALHOST, port)));

        let answer = probe_answer(&prober, address, std_Duration::from_secs(2)).await;

        prober.close().await;
        holder.close().await;
        task.abort();
        assert_ne!(
            answer,
            ProbeAnswer::Foreign,
            "a holder of our mesh that has no ALPN yet is not another mesh"
        );
        assert_ne!(
            answer,
            ProbeAnswer::Ours,
            "a dial that failed on the ALPN did not open"
        );
    });
}

/// A listener of the identity that was asked for, which refuses every connection (a beacon that
/// is saturated or going down does the same), is not another mesh: its refusal proves nothing
/// about the identity, so the probe must not answer `Foreign`, which makes a walk bind a rung.
#[test]
fn a_refusal_from_a_listener_of_our_identity_is_not_a_foreign_mesh() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        use std::net::SocketAddr;

        use iroh::{EndpointAddr, SecretKey};
        use iroh_gossip::net::GOSSIP_ALPN;

        use super::{ProbeAnswer, TransportHandles, build_endpoint, probe_answer};

        let secret = SecretKey::generate();
        let id = secret.public();
        let bound = net::UdpSocket::bind((net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr());
        let port = bound.expect("a free loopback port").port();
        let listener = build_endpoint(
            &LookupOpts::loopback(),
            Some(secret),
            Some(port),
            vec![GOSSIP_ALPN.to_vec()],
            TransportHandles::default(),
        )
        .await
        .expect("a listener of our identity");
        let refusing = listener.clone();
        let task = task::spawn(async move {
            while let Some(incoming) = refusing.accept().await {
                incoming.refuse();
            }
        });
        let prober = build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            TransportHandles::default(),
        )
        .await
        .expect("a prober");
        let address =
            EndpointAddr::new(id).with_ip_addr(SocketAddr::from((net::Ipv4Addr::LOCALHOST, port)));

        let answer = probe_answer(&prober, address, std_Duration::from_secs(2)).await;

        prober.close().await;
        listener.close().await;
        task.abort();
        assert_ne!(
            answer,
            ProbeAnswer::Foreign,
            "a listener that refused is not another mesh: it proved no identity"
        );
        assert_ne!(answer, ProbeAnswer::Ours, "a refused dial did not open");
    });
}

/// A session that attaches to the rendezvous is followed by a nudge: a dial on the nudge ALPN
/// that does its work only when it completes. The router of the beacon is built with no
/// unicast acceptor, so it has to serve the nudge ALPN all the same, or the handshake fails
/// with `no_application_protocol` and the nudge does nothing.
#[test]
fn a_router_that_carries_no_unicast_completes_a_nudge() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        use std::net::SocketAddr;

        use iroh::{EndpointAddr, SecretKey};
        use iroh_gossip::net::GOSSIP_ALPN;

        use super::{TransportHandles, build_endpoint, build_mesh};

        let secret = SecretKey::generate();
        let id = secret.public();
        let bound = net::UdpSocket::bind((net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.local_addr());
        let port = bound.expect("a free loopback port").port();
        let beacon = build_endpoint(
            &LookupOpts::loopback(),
            Some(secret),
            Some(port),
            vec![GOSSIP_ALPN.to_vec()],
            TransportHandles::default(),
        )
        .await
        .expect("a beacon endpoint");
        let (_gossip, router, _book) = build_mesh(
            beacon,
            5,
            None,
            None,
            habilis_network_iroh_transport_util::ProtocolSet::default(),
            true,
            false,
        );
        let dialer = build_endpoint(
            &LookupOpts::loopback(),
            None,
            None,
            Vec::new(),
            TransportHandles::default(),
        )
        .await
        .expect("a dialer");
        let address =
            EndpointAddr::new(id).with_ip_addr(SocketAddr::from((net::Ipv4Addr::LOCALHOST, port)));

        let nudge = time::timeout(
            std_Duration::from_secs(5),
            dialer.connect(address, webrtc::NUDGE_ALPN),
        )
        .await
        .map(|dialed| dialed.map(|_| ()));

        dialer.close().await;
        let _ = router.shutdown().await;
        assert!(
            matches!(nudge, Ok(Ok(()))),
            "the nudge did not complete: {nudge:?}"
        );
    });
}

/// What each way a dial can end proves: only the verdict of our verifier on the key is another
/// mesh. An alert that is sent before a certificate (`no_application_protocol`, from a holder
/// of our own mesh whose router has not set its ALPN yet), a close, a reset and a version
/// mismatch say nothing of the identity; a local failure says nothing.
#[test]
fn every_way_a_dial_ends_is_read_by_what_it_proves() {
    use iroh::endpoint::{ConnectionError, TransportError, TransportErrorCode};

    use super::probe_answer::{ProbeAnswer, answer_of_connection_error};

    let _guard = ::habilis_network_test_tracing::init();
    let alert = |code: u8| {
        ConnectionError::TransportError(TransportError::new(
            TransportErrorCode::crypto(code),
            String::new(),
        ))
    };
    let unknown_ca = alert(48);
    let no_application_protocol = alert(120);
    let handshake_failure = alert(40);
    assert_eq!(
        answer_of_connection_error(&unknown_ca),
        ProbeAnswer::Foreign,
        "the verifier rejected the key"
    );
    for refused in [
        no_application_protocol,
        handshake_failure,
        ConnectionError::Reset,
        ConnectionError::VersionMismatch,
    ] {
        assert_eq!(
            answer_of_connection_error(&refused),
            ProbeAnswer::Refused,
            "{refused:?}"
        );
    }
    for silent in [
        ConnectionError::TimedOut,
        ConnectionError::LocallyClosed,
        ConnectionError::CidsExhausted,
    ] {
        assert_eq!(
            answer_of_connection_error(&silent),
            ProbeAnswer::NoAnswer,
            "{silent:?}"
        );
    }
}

#[test]
#[ignore = "needs the public relay ladder; run with --ignored"]
fn public_default_relay_binds() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        // No lookup wired: exercises the `Minimal` + pinned-ladder
        // composition. `bind()` is non-blocking wrt the relay, so this
        // is offline-safe even with the relay ladder configured.
        let endpoint = build_peer_endpoint(&LookupOpts::public_preset())
            .await
            .expect("endpoint with pinned relay ladder must bind");
        endpoint.close().await;
    });
}
