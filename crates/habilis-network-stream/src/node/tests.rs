//! The stream node's tests: a loopback producer and consumer.

use habilis_network::runtime;

use habilis_network::net::TransportOpts;
use habilis_network::protocol::{Lookup, MeshConfig, Transport};

use super::{StreamNode, StreamOpts};
// A stream is one direct lane: a list that names `multihop` is refused
// before anything binds.
#[test]
fn a_stream_node_refuses_multihop() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        let options = StreamOpts {
            transport: vec![Transport::Udp, Transport::Multihop],
            ..StreamOpts::default()
        };
        let refused = StreamNode::bind(&options)
            .await
            .expect_err("multihop is refused");
        assert!(
            refused.to_string().contains("no multihop"),
            "the error names the reason: {refused}"
        );
    });
}

// A stream node never joins a gossip mesh: a list that names `gossip` is refused too.
#[test]
fn a_stream_node_refuses_gossip() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        let options = StreamOpts {
            transport: vec![Transport::Udp, Transport::Gossip],
            ..StreamOpts::default()
        };
        let refused = StreamNode::bind(&options)
            .await
            .expect_err("gossip is refused");
        assert!(
            refused.to_string().contains("no gossip"),
            "the error names the reason: {refused}"
        );
    });
}

// The mesh default has `multihop`. An empty list for a stream must not take it.
#[test]
fn an_empty_list_is_udp_and_webrtc_for_a_stream() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        let node = StreamNode::bind(&StreamOpts::default())
            .await
            .expect("bind a loopback node");
        let policy = node.transport;
        assert!(policy.udp && policy.webrtc, "udp and webrtc are on");
        assert!(!policy.multihop, "multihop is off");
        node.endpoint.close().await;
    });
}

// A browser has no UDP, so a list without `webrtc` leaves relay payload as
// its only path: without `relay` in the list, nothing carries its bytes.
#[test]
fn a_browser_refuses_a_list_with_no_path_it_can_run() {
    let _guard = ::habilis_network_test_tracing::init();
    let refused = |transport: &[Transport]| {
        let config = MeshConfig::resolve(&[Lookup::Relay], None, transport).expect("valid");
        let transports = TransportOpts::default().within(&config.transport);
        runtime::refuse_in_browser(&config.lookups, config.transport, transports).is_err()
    };
    assert!(refused(&[Transport::Udp]), "udp only");
    assert!(
        !refused(&[Transport::Udp, Transport::Relay]),
        "relay payload"
    );
    assert!(!refused(&[Transport::WebRtc]), "a data channel");
}

// A data channel's handshake crosses the relay, and a browser has no
// other way to reach a producer.
#[test]
fn a_browser_refuses_a_stream_with_no_relay_lookup() {
    let _guard = ::habilis_network_test_tracing::init();
    let config = MeshConfig::resolve(&[Lookup::Dht], None, &[Transport::Udp, Transport::WebRtc])
        .expect("valid");
    let transports = TransportOpts::default().within(&config.transport);
    let error = runtime::refuse_in_browser(&config.lookups, config.transport, transports)
        .expect_err("no path to signal on");
    assert_eq!(
        error.to_string(),
        runtime::BROWSER_NEEDS_RELAY_LOOKUP,
        "a browser refuses a stream with no relay lookup with the browser message"
    );
}

// A reader runs only the paths the producer runs: an offer to a producer
// with no data channel would fail only after its whole JSEP round.
#[test]
fn a_reader_takes_the_producers_transport_list() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            let producer_node = StreamNode::bind(&StreamOpts {
                transport: vec![Transport::Udp],
                ..StreamOpts::default()
            })
            .await
            .expect("bind");
            let hash = producer_node.create().await.hash().clone();
            let reader_node = StreamNode::bind_for(&hash).await.expect("bind for");
            assert!(
                reader_node.transports.udp,
                "a reader takes the producer's udp transport"
            );
            assert!(
                !reader_node.transports.webrtc,
                "no data channel to offer to"
            );
            producer_node.close().await;
            reader_node.close().await;
        },
    );
}

#[test]
fn opening_many_streams_adds_one_address_lookup() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            let producer_node = StreamNode::bind(&StreamOpts::default())
                .await
                .expect("bind");
            let consumer_node = StreamNode::bind(&StreamOpts::default())
                .await
                .expect("bind");
            let lookups = || {
                consumer_node
                    .endpoint
                    .address_lookup()
                    .expect("an address book")
                    .len()
            };
            let before = lookups();
            for _ in 0..5 {
                let producer = producer_node.create().await;
                consumer_node.open(producer.hash()).await.expect("open");
            }
            let after = lookups();
            assert!(after <= before + 1, "{before} lookups grew to {after}");
            producer_node.close().await;
            consumer_node.close().await;
        },
    );
}
