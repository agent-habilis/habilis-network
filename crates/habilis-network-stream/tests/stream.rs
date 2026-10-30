//! End to end over real endpoints: loopback, and an in-process relay where the
//! path matters.

#![cfg(not(target_arch = "wasm32"))]

use std::time::{Duration, Instant};

use habilis_network::net::test_relay;
use habilis_network::protocol::{Lookup, Transport};
use habilis_network_stream::{
    Producer, Reader, Refused, StreamError, StreamHash, StreamNode, StreamOpts, StreamSecret,
};

use habilis_network::iroh;
use habilis_network::iroh::endpoint::presets;
use habilis_network::net::direct;
use tokio::time;
/// Generous: a relay dial, a JSEP round and a hole punch all fit inside it.
const BUDGET: Duration = Duration::from_mins(1);

async fn loopback() -> StreamNode {
    StreamNode::bind(&StreamOpts::default())
        .await
        .expect("bind a loopback node")
}

/// Read to the end, or fail with whatever ended the stream.
async fn read_all(reader: &mut Reader) -> Result<Vec<u8>, StreamError> {
    let mut out = Vec::new();
    while let Some(chunk) = reader.read().await? {
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn refusal(error: &StreamError) -> Option<Refused> {
    match error {
        StreamError::Refused(refused) => Some(*refused),
        StreamError::Options(_)
        | StreamError::Bind { .. }
        | StreamError::Open { .. }
        | StreamError::NodeClosed
        | StreamError::Closed
        | StreamError::ConsumerGone(_)
        | StreamError::Lost(_)
        | _ => None,
    }
}

/// Write `payload` in `chunk`-sized pieces and close.
async fn produce(mut producer: Producer, payload: Vec<u8>, chunk: usize) {
    for piece in payload.chunks(chunk) {
        producer.write(piece).await.expect("write");
    }
    producer.close().await.expect("close");
}

fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index * 31 % 251).expect("below 251"))
        .collect()
}

#[test]
fn ten_megabytes_arrive_complete_and_in_order() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let sent = payload(10 * 1024 * 1024);
        let writer = tokio::spawn(produce(producer, sent.clone(), 64 * 1024));

        let mut reader = consumer_node.open(&hash).await.expect("open");
        let started = Instant::now();
        let got = time::timeout(BUDGET, read_all(&mut reader))
            .await
            .expect("within budget")
            .expect("read");
        let elapsed = started.elapsed();
        writer.await.expect("writer");
        println!("10 MB over loopback in {elapsed:?} (gossip pipe baseline: 0.63 s)");
        assert_eq!(
            got.len(),
            sent.len(),
            "ten megabytes arrive complete and in order"
        );
        assert!(got == sent, "bytes differ");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn an_empty_stream_reaches_the_end() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let closer = tokio::spawn(producer.close());
        let mut reader = consumer_node.open(&hash).await.expect("open");
        assert!(
            read_all(&mut reader).await.expect("read").is_empty(),
            "an empty stream reaches the end"
        );
        closer.await.expect("closer").expect("close");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn a_read_after_the_end_is_the_end_again() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let writer = tokio::spawn(produce(producer, b"once".to_vec(), 64));
        let mut reader = consumer_node.open(&hash).await.expect("open");
        assert_eq!(
            read_all(&mut reader).await.expect("read"),
            b"once",
            "a read after the end is the end again"
        );
        writer.await.expect("writer");
        // Past the reader's own `DONE` close, which the first end triggered.
        time::sleep(Duration::from_millis(500)).await;
        assert!(
            reader.read().await.expect("a read after the end").is_none(),
            "the end of stream must repeat"
        );
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn a_second_consumer_is_refused_as_taken() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let mut producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let _first = consumer_node.open(&hash).await.expect("first open");
        producer
            .attached()
            .await
            .expect("the first consumer attaches");

        let mut second = consumer_node.open(&hash).await.expect("second open");
        let error = read_all(&mut second).await.expect_err("second consumer");
        assert_eq!(refusal(&error), Some(Refused::Taken), "{error:#}");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn two_racing_consumers_admit_exactly_one() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let mut producer = producer_node.create().await;
        let hash = producer.hash().clone();

        let (left, right) = tokio::join!(consumer_node.open(&hash), consumer_node.open(&hash));
        let (mut left, mut right) = (left.expect("open"), right.expect("open"));
        // Held open until both have their first answer: once the stream closes the
        // hash is spent, and a late loser would read "unknown" instead of "taken".
        producer.write(b"only one").await.expect("write");
        let (first_left, first_right) = tokio::join!(left.read(), right.read());
        let (won, lost) = match (first_left, first_right) {
            (Ok(Some(bytes)), Err(error)) | (Err(error), Ok(Some(bytes))) => (bytes, error),
            other => panic!("exactly one consumer must win: {other:?}"),
        };
        assert_eq!(
            &won[..],
            b"only one",
            "only one of two racing consumers is admitted"
        );
        assert_eq!(refusal(&lost), Some(Refused::Taken), "{lost:#}");
        producer.close().await.expect("close");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn a_wrong_secret_reads_nothing() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let producer = producer_node.create().await;
        let mut forged: StreamHash = producer.hash().clone();
        let mut wrong = *forged.secret.as_bytes();
        wrong[0] ^= 1;
        forged.secret = StreamSecret::from(wrong);
        let mut reader = consumer_node.open(&forged).await.expect("open");
        let error = read_all(&mut reader).await.expect_err("forged hash");
        assert_eq!(refusal(&error), Some(Refused::Unknown), "{error:#}");
        drop(producer);
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn a_closed_stream_is_spent() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let writer = tokio::spawn(produce(producer, b"once".to_vec(), 64));
        let mut reader = consumer_node.open(&hash).await.expect("open");
        assert_eq!(
            read_all(&mut reader).await.expect("read"),
            b"once",
            "a closed stream is spent and reads once"
        );
        writer.await.expect("writer");

        let mut again = consumer_node.open(&hash).await.expect("open again");
        let error = read_all(&mut again).await.expect_err("spent hash");
        assert_eq!(refusal(&error), Some(Refused::Unknown), "{error:#}");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn close_or_abandon_with_no_consumer_abandons_at_once() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let producer = producer_node.create().await;
        let hash = producer.hash().clone();
        time::timeout(Duration::from_secs(1), producer.close_or_abandon())
            .await
            .expect("no wait for a consumer")
            .expect("abandoned");
        let mut reader = consumer_node.open(&hash).await.expect("open");
        let error = read_all(&mut reader).await.expect_err("abandoned stream");
        assert_eq!(refusal(&error), Some(Refused::Unknown), "{error:#}");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn close_or_abandon_with_a_consumer_ends_the_stream() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let mut producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let mut reader = consumer_node.open(&hash).await.expect("open");
        producer.write(b"kept").await.expect("write");
        producer.close_or_abandon().await.expect("closed");
        assert_eq!(
            read_all(&mut reader).await.expect("read"),
            b"kept",
            "closing or abandoning with a consumer ends the stream"
        );
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn a_dropped_producer_refuses_later_consumers() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let producer = producer_node.create().await;
        let hash = producer.hash().clone();
        drop(producer);
        let mut reader = consumer_node.open(&hash).await.expect("open");
        let error = read_all(&mut reader).await.expect_err("abandoned stream");
        assert_eq!(refusal(&error), Some(Refused::Unknown), "{error:#}");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn a_producer_dropped_mid_stream_is_an_error_not_an_end() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let mut producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let mut reader = consumer_node.open(&hash).await.expect("open");
        producer.write(b"half").await.expect("write");
        drop(producer);
        let error = read_all(&mut reader)
            .await
            .expect_err("abandoned mid-stream");
        assert_eq!(refusal(&error), Some(Refused::Abandoned), "{error:#}");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

/// The consumer's link can reach the producer before anything polls
/// `attached()`, and then waits in the hand-off. A producer dropped then has
/// abandoned the stream as surely as one dropped mid-write.
#[test]
fn a_producer_dropped_with_its_link_unclaimed_abandons_the_stream() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let mut reader = consumer_node.open(&hash).await.expect("open");
        // Past the acceptor's hand-off, without ever calling `attached()`.
        time::sleep(Duration::from_millis(500)).await;
        drop(producer);
        let outcome = time::timeout(BUDGET, read_all(&mut reader))
            .await
            .expect("within budget");
        let error = outcome.expect_err("an abandoned stream must not read as ended");
        assert_eq!(refusal(&error), Some(Refused::Abandoned), "{error:#}");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn a_consumer_that_leaves_fails_the_write_and_spends_the_hash() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let mut producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let reader = consumer_node.open(&hash).await.expect("open");
        producer.attached().await.expect("attached");
        drop(reader);

        let chunk = vec![0; 64 * 1024];
        let failed = time::timeout(BUDGET, async {
            loop {
                if producer.write(&chunk).await.is_err() {
                    return;
                }
            }
        })
        .await;
        assert!(
            failed.is_ok(),
            "a write must fail once the consumer is gone"
        );

        let mut again = consumer_node.open(&hash).await.expect("open again");
        let error = read_all(&mut again).await.expect_err("spent hash");
        assert_eq!(refusal(&error), Some(Refused::Taken), "{error:#}");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

#[test]
fn two_streams_on_one_node_stay_apart() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (producer_node, consumer_node) = (loopback().await, loopback().await);
        let (first, second) = (producer_node.create().await, producer_node.create().await);
        let (first_hash, second_hash) = (first.hash().clone(), second.hash().clone());
        let writers = (
            tokio::spawn(produce(first, payload(300_000), 4096)),
            tokio::spawn(produce(second, b"second".repeat(50_000), 1000)),
        );
        let (mut first_reader, mut second_reader) = (
            consumer_node.open(&first_hash).await.expect("open first"),
            consumer_node.open(&second_hash).await.expect("open second"),
        );
        let (first_got, second_got) =
            tokio::join!(read_all(&mut first_reader), read_all(&mut second_reader));
        assert_eq!(
            first_got.expect("first"),
            payload(300_000),
            "the first reader gets the whole first payload"
        );
        assert_eq!(
            second_got.expect("second"),
            b"second".repeat(50_000),
            "the second reader gets the whole second payload"
        );
        writers.0.await.expect("first writer");
        writers.1.await.expect("second writer");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

/// A node on the local relay, with `transport` as given.
async fn on_relay(url: &str, transport: Vec<Transport>) -> StreamNode {
    let base = StreamOpts::default();
    let relay_urls = vec![url.to_owned()];
    let options = base
        .lookup(vec![Lookup::Relay])
        .transport(transport)
        .relay_urls(relay_urls);
    StreamNode::bind(&options).await.expect("bind a relay node")
}

/// The relay logs a client that resets while the relay is still accepting its upgrade. These tests
/// close their two nodes while that upgrade may still run, so the line can come; it is the relay's
/// own log, not an error of ours, so the guard must not fail on it.
fn allow_relay_upgrade_reset() {
    habilis_network_test_tracing::allow_warn(
        "iroh_relay::server::http_server",
        "error accepting upgraded connection",
    );
}

#[test]
fn a_relay_transport_stream_admits_a_consumer_with_no_direct_path() {
    let guard = habilis_network_test_tracing::init();
    allow_relay_upgrade_reset();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (url, _relay) = test_relay::spawn_plain().await.expect("relay");
        let url = url.to_string();
        // The producer has no data channel and the consumer has no UDP, so no
        // direct path can exist between them.
        let producer_node = on_relay(&url, vec![Transport::Udp, Transport::Relay]).await;
        let consumer_node = on_relay(&url, vec![Transport::WebRtc, Transport::Relay]).await;
        let producer = producer_node.create().await;
        assert!(
            producer.hash().transport.allows(Transport::Relay),
            "the producer hash carries the relay transport"
        );
        let hash = producer.hash().clone();
        let writer = tokio::spawn(produce(producer, b"over the relay".to_vec(), 64));
        let mut reader = time::timeout(BUDGET, consumer_node.open(&hash))
            .await
            .expect("within budget")
            .expect("open");
        assert_eq!(
            read_all(&mut reader).await.expect("read"),
            b"over the relay",
            "a relay transport stream admits a consumer with no direct path"
        );
        writer.await.expect("writer");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

/// The consumer has no IP path and the relay may not carry the bytes, so the
/// only way they arrive is the `WebRTC` data channel.
#[test]
fn a_webrtc_only_consumer_reads_over_the_data_channel() {
    let guard = habilis_network_test_tracing::init();
    allow_relay_upgrade_reset();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (url, _relay) = test_relay::spawn_plain().await.expect("relay");
        let url = url.to_string();
        let producer_node = on_relay(&url, vec![Transport::Udp, Transport::WebRtc]).await;
        let consumer_node = on_relay(&url, vec![Transport::WebRtc]).await;
        let producer = producer_node.create().await;
        assert!(
            !producer.hash().transport.allows(Transport::Relay),
            "the webrtc-only producer hash has no relay transport"
        );
        let hash = producer.hash().clone();
        let sent = payload(1024 * 1024);
        let writer = tokio::spawn(produce(producer, sent.clone(), 16 * 1024));
        let mut reader = time::timeout(BUDGET, consumer_node.open(&hash))
            .await
            .expect("within budget")
            .expect("open");
        let got = time::timeout(BUDGET, read_all(&mut reader))
            .await
            .expect("within budget")
            .expect("read");
        assert!(got == sent, "bytes differ");
        writer.await.expect("writer");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

/// The producer has no IP path, the relay may not carry the bytes, and the
/// consumer has `WebRTC` off: no lane can exist, so the open fails at once
/// rather than after the direct-path probe.
#[test]
fn a_consumer_with_no_lane_to_a_webrtc_only_producer_fails_fast() {
    let guard = habilis_network_test_tracing::init();
    allow_relay_upgrade_reset();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (url, _relay) = test_relay::spawn_plain().await.expect("relay");
        let url = url.to_string();
        let producer_node = on_relay(&url, vec![Transport::WebRtc]).await;
        let consumer_node = on_relay(&url, vec![Transport::Udp]).await;
        let producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let started = Instant::now();
        let error = consumer_node.open(&hash).await.expect_err("no lane");
        let elapsed = started.elapsed();
        assert_eq!(refusal(&error), Some(Refused::RelayRefused), "{error:#}");
        assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

/// A `WebRTC` session that attaches makes its answerer dial the offerer on the nudge ALPN, to move
/// the connections of the pair onto the session. A stream node with `WebRTC` must serve that ALPN,
/// or the dial fails with a TLS alert 120 and the node logs a warning for it.
#[test]
fn a_stream_node_with_webrtc_serves_the_nudge_of_a_peer() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let node = loopback().await;
        let producer = node.create().await;
        let address = producer.hash().address.clone();
        let dialer = iroh::Endpoint::bind(presets::Minimal)
            .await
            .expect("bind a dialer");
        let nudge = dialer.connect(address, direct::NUDGE_ALPN).await;
        assert!(nudge.is_ok(), "the nudge was refused: {:?}", nudge.err());
        dialer.close().await;
        node.close().await;
    });
}

/// The mirror case: the reader has only a data channel, and the producer
/// runs none. The hash says so, so the open fails at once instead of offering
/// a round the producer cannot answer.
#[test]
fn a_webrtc_only_consumer_of_a_producer_without_webrtc_fails_fast() {
    let guard = habilis_network_test_tracing::init();
    allow_relay_upgrade_reset();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (url, _relay) = test_relay::spawn_plain().await.expect("relay");
        let url = url.to_string();
        let producer_node = on_relay(&url, vec![Transport::Udp]).await;
        let consumer_node = on_relay(&url, vec![Transport::WebRtc]).await;
        let producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let started = Instant::now();
        let error = consumer_node.open(&hash).await.expect_err("no lane");
        let elapsed = started.elapsed();
        assert_eq!(refusal(&error), Some(Refused::RelayRefused), "{error:#}");
        assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

/// The consumer's list refuses relay payload even when the producer's allows
/// it. A producer with no UDP and a consumer with no data channel share only
/// the relay, so the open fails at once instead of streaming over it.
#[test]
fn a_consumer_without_relay_payload_refuses_a_relay_only_pair() {
    let guard = habilis_network_test_tracing::init();
    allow_relay_upgrade_reset();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (url, _relay) = test_relay::spawn_plain().await.expect("relay");
        let url = url.to_string();
        let producer_node = on_relay(&url, vec![Transport::WebRtc, Transport::Relay]).await;
        let consumer_node = on_relay(&url, vec![Transport::Udp]).await;
        let producer = producer_node.create().await;
        let hash = producer.hash().clone();
        let started = Instant::now();
        let error = consumer_node.open(&hash).await.expect_err("relay only");
        let elapsed = started.elapsed();
        assert_eq!(refusal(&error), Some(Refused::RelayRefused), "{error:#}");
        assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
        producer_node.close().await;
        consumer_node.close().await;
    });
}

/// A node made to read a hash can produce as well, and the hash it mints must
/// carry its home relay like one from `bind` does.
#[test]
fn a_hash_minted_by_a_bind_for_node_carries_its_relay() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        let (url, _relay) = test_relay::spawn_plain().await.expect("relay");
        let url = url.to_string();
        let first = on_relay(&url, vec![Transport::Udp]).await;
        let given = first.create().await.hash().clone();
        let node = StreamNode::bind_for(&given).await.expect("bind for");
        let minted = node.create().await.hash().clone();
        assert!(
            minted.address.relay_urls().next().is_some(),
            "no relay in {:?}",
            minted.address
        );
        node.close().await;
        first.close().await;
    });
}

/// Gossip-only mesh: a stream is one direct lane between two endpoints that never join a mesh,
/// so it cannot ride the gossip rung. A node that asks for `gossip` or `multihop` is refused
/// at bind, with the reason.
#[test]
fn a_stream_node_refuses_the_gossip_and_multihop_transports() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(guard, 2, async {
        for (transport, reason) in [
            (Transport::Gossip, "a stream has no gossip"),
            (Transport::Multihop, "a stream has no multihop"),
        ] {
            let options = StreamOpts::default().transport(vec![Transport::Udp, transport]);
            let error = StreamNode::bind(&options)
                .await
                .expect_err("the transport must be refused");
            assert!(
                format!("{error:#}").contains(reason),
                "{transport:?}: {error:#}"
            );
        }
    });
}
