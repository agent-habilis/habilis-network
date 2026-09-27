//! End to end over real endpoints: loopback, and an in-process relay where the
//! path matters.

#![cfg(not(target_arch = "wasm32"))]

use std::time::{Duration, Instant};

use fofoca::net::PathFlags;
use fofoca::net::test_relay;
use fofoca::protocol::{Lookup, Transport};
use fofoca_stream::{Producer, Reader, Refused, StreamHash, StreamNode, StreamOpts};

/// Generous: a relay dial, a JSEP round and a hole punch all fit inside it.
const BUDGET: Duration = Duration::from_mins(1);

async fn loopback() -> StreamNode {
    StreamNode::bind(&StreamOpts::default())
        .await
        .expect("bind a loopback node")
}

/// Read to the end, or fail with whatever ended the stream.
async fn read_all(reader: &mut Reader) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = reader.read().await? {
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn refusal(error: &anyhow::Error) -> Option<Refused> {
    error.downcast_ref::<Refused>().copied()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ten_megabytes_arrive_complete_and_in_order() {
    let (producer_node, consumer_node) = (loopback().await, loopback().await);
    let producer = producer_node.create().await;
    let hash = producer.hash().clone();
    let sent = payload(10 * 1024 * 1024);
    let writer = tokio::spawn(produce(producer, sent.clone(), 64 * 1024));

    let mut reader = consumer_node.open(&hash).await.expect("open");
    let started = Instant::now();
    let got = tokio::time::timeout(BUDGET, read_all(&mut reader))
        .await
        .expect("within budget")
        .expect("read");
    let elapsed = started.elapsed();
    writer.await.expect("writer");
    println!("10 MB over loopback in {elapsed:?} (gossip pipe baseline: 0.63 s)");
    assert_eq!(got.len(), sent.len());
    assert!(got == sent, "bytes differ");
    producer_node.close().await;
    consumer_node.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_stream_reaches_the_end() {
    let (producer_node, consumer_node) = (loopback().await, loopback().await);
    let producer = producer_node.create().await;
    let hash = producer.hash().clone();
    let closer = tokio::spawn(producer.close());
    let mut reader = consumer_node.open(&hash).await.expect("open");
    assert!(read_all(&mut reader).await.expect("read").is_empty());
    closer.await.expect("closer").expect("close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_after_the_end_is_the_end_again() {
    let (producer_node, consumer_node) = (loopback().await, loopback().await);
    let producer = producer_node.create().await;
    let hash = producer.hash().clone();
    let writer = tokio::spawn(produce(producer, b"once".to_vec(), 64));
    let mut reader = consumer_node.open(&hash).await.expect("open");
    assert_eq!(read_all(&mut reader).await.expect("read"), b"once");
    writer.await.expect("writer");
    // Past the reader's own `DONE` close, which the first end triggered.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        reader.read().await.expect("a read after the end").is_none(),
        "the end of stream must repeat"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_consumer_is_refused_as_taken() {
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_racing_consumers_admit_exactly_one() {
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
    assert_eq!(&won[..], b"only one");
    assert_eq!(refusal(&lost), Some(Refused::Taken), "{lost:#}");
    producer.close().await.expect("close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_secret_reads_nothing() {
    let (producer_node, consumer_node) = (loopback().await, loopback().await);
    let producer = producer_node.create().await;
    let mut forged: StreamHash = producer.hash().clone();
    forged.secret[0] ^= 1;
    let mut reader = consumer_node.open(&forged).await.expect("open");
    let error = read_all(&mut reader).await.expect_err("forged hash");
    assert_eq!(refusal(&error), Some(Refused::Unknown), "{error:#}");
    drop(producer);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_stream_is_spent() {
    let (producer_node, consumer_node) = (loopback().await, loopback().await);
    let producer = producer_node.create().await;
    let hash = producer.hash().clone();
    let writer = tokio::spawn(produce(producer, b"once".to_vec(), 64));
    let mut reader = consumer_node.open(&hash).await.expect("open");
    assert_eq!(read_all(&mut reader).await.expect("read"), b"once");
    writer.await.expect("writer");

    let mut again = consumer_node.open(&hash).await.expect("open again");
    let error = read_all(&mut again).await.expect_err("spent hash");
    assert_eq!(refusal(&error), Some(Refused::Unknown), "{error:#}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_or_abandon_with_no_consumer_abandons_at_once() {
    let (producer_node, consumer_node) = (loopback().await, loopback().await);
    let producer = producer_node.create().await;
    let hash = producer.hash().clone();
    tokio::time::timeout(Duration::from_secs(1), producer.close_or_abandon())
        .await
        .expect("no wait for a consumer")
        .expect("abandoned");
    let mut reader = consumer_node.open(&hash).await.expect("open");
    let error = read_all(&mut reader).await.expect_err("abandoned stream");
    assert_eq!(refusal(&error), Some(Refused::Unknown), "{error:#}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_or_abandon_with_a_consumer_ends_the_stream() {
    let (producer_node, consumer_node) = (loopback().await, loopback().await);
    let mut producer = producer_node.create().await;
    let hash = producer.hash().clone();
    let mut reader = consumer_node.open(&hash).await.expect("open");
    producer.write(b"kept").await.expect("write");
    producer.close_or_abandon().await.expect("closed");
    assert_eq!(read_all(&mut reader).await.expect("read"), b"kept");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_producer_refuses_later_consumers() {
    let (producer_node, consumer_node) = (loopback().await, loopback().await);
    let producer = producer_node.create().await;
    let hash = producer.hash().clone();
    drop(producer);
    let mut reader = consumer_node.open(&hash).await.expect("open");
    let error = read_all(&mut reader).await.expect_err("abandoned stream");
    assert_eq!(refusal(&error), Some(Refused::Unknown), "{error:#}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_producer_dropped_mid_stream_is_an_error_not_an_end() {
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
}

/// The consumer's link can reach the producer before anything polls
/// `attached()`, and then waits in the hand-off. A producer dropped then has
/// abandoned the stream as surely as one dropped mid-write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_producer_dropped_with_its_link_unclaimed_abandons_the_stream() {
    let (producer_node, consumer_node) = (loopback().await, loopback().await);
    let producer = producer_node.create().await;
    let hash = producer.hash().clone();
    let mut reader = consumer_node.open(&hash).await.expect("open");
    // Past the acceptor's hand-off, without ever calling `attached()`.
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(producer);
    let outcome = tokio::time::timeout(BUDGET, read_all(&mut reader))
        .await
        .expect("within budget");
    let error = outcome.expect_err("an abandoned stream must not read as ended");
    assert_eq!(refusal(&error), Some(Refused::Abandoned), "{error:#}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_consumer_that_leaves_fails_the_write_and_spends_the_hash() {
    let (producer_node, consumer_node) = (loopback().await, loopback().await);
    let mut producer = producer_node.create().await;
    let hash = producer.hash().clone();
    let reader = consumer_node.open(&hash).await.expect("open");
    producer.attached().await.expect("attached");
    drop(reader);

    let chunk = vec![0; 64 * 1024];
    let failed = tokio::time::timeout(BUDGET, async {
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_streams_on_one_node_stay_apart() {
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
    assert!(first_got.expect("first") == payload(300_000));
    assert!(second_got.expect("second") == b"second".repeat(50_000));
    writers.0.await.expect("first writer");
    writers.1.await.expect("second writer");
}

/// A node on the local relay, with `transport` and `paths` as given.
async fn on_relay(url: &str, transport: Vec<Transport>, paths: PathFlags) -> StreamNode {
    StreamNode::bind(&StreamOpts {
        lookup: vec![Lookup::Relay],
        transport,
        relay_urls: vec![url.to_owned()],
        paths,
    })
    .await
    .expect("bind a relay node")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_transport_stream_admits_a_relay_only_consumer() {
    let (url, _relay) = test_relay::spawn_plain().await.expect("relay");
    let url = url.to_string();
    let both = vec![Transport::P2p, Transport::Relay];
    let producer_node = on_relay(&url, both.clone(), PathFlags::default()).await;
    let relay_only = PathFlags {
        ip: false,
        webrtc: false,
    };
    let consumer_node = on_relay(&url, both, relay_only).await;
    let producer = producer_node.create().await;
    assert!(producer.hash().relay_transport);
    let hash = producer.hash().clone();
    let writer = tokio::spawn(produce(producer, b"over the relay".to_vec(), 64));
    let mut reader = tokio::time::timeout(BUDGET, consumer_node.open(&hash))
        .await
        .expect("within budget")
        .expect("open");
    assert_eq!(
        read_all(&mut reader).await.expect("read"),
        b"over the relay"
    );
    writer.await.expect("writer");
}

/// The consumer has no IP path and the relay may not carry the bytes, so the
/// only way they arrive is the WebRTC data channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_webrtc_only_consumer_reads_over_the_data_channel() {
    let (url, _relay) = test_relay::spawn_plain().await.expect("relay");
    let url = url.to_string();
    let producer_node = on_relay(&url, vec![Transport::P2p], PathFlags::default()).await;
    let webrtc_only = PathFlags {
        ip: false,
        webrtc: true,
    };
    let consumer_node = on_relay(&url, vec![Transport::P2p], webrtc_only).await;
    let producer = producer_node.create().await;
    assert!(!producer.hash().relay_transport);
    let hash = producer.hash().clone();
    let sent = payload(1024 * 1024);
    let writer = tokio::spawn(produce(producer, sent.clone(), 16 * 1024));
    let mut reader = tokio::time::timeout(BUDGET, consumer_node.open(&hash))
        .await
        .expect("within budget")
        .expect("open");
    let got = tokio::time::timeout(BUDGET, read_all(&mut reader))
        .await
        .expect("within budget")
        .expect("read");
    assert!(got == sent, "bytes differ");
    writer.await.expect("writer");
}

/// The producer has no IP path, the relay may not carry the bytes, and the
/// consumer has WebRTC off: no lane can exist, so the open fails at once
/// rather than after the direct-path probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_consumer_with_no_lane_to_a_webrtc_only_producer_fails_fast() {
    let (url, _relay) = test_relay::spawn_plain().await.expect("relay");
    let url = url.to_string();
    let webrtc_only = PathFlags {
        ip: false,
        webrtc: true,
    };
    let producer_node = on_relay(&url, vec![Transport::P2p], webrtc_only).await;
    let no_webrtc = PathFlags {
        ip: true,
        webrtc: false,
    };
    let consumer_node = on_relay(&url, vec![Transport::P2p], no_webrtc).await;
    let producer = producer_node.create().await;
    let hash = producer.hash().clone();
    let started = Instant::now();
    let error = consumer_node.open(&hash).await.expect_err("no lane");
    let elapsed = started.elapsed();
    assert_eq!(refusal(&error), Some(Refused::RelayRefused), "{error:#}");
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
}

/// A node made to read a hash can produce as well, and the hash it mints must
/// carry its home relay like one from `bind` does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hash_minted_by_a_bind_for_node_carries_its_relay() {
    let (url, _relay) = test_relay::spawn_plain().await.expect("relay");
    let url = url.to_string();
    let first = on_relay(&url, vec![Transport::P2p], PathFlags::default()).await;
    let given = first.create().await.hash().clone();
    let node = StreamNode::bind_for(&given).await.expect("bind for");
    let minted = node.create().await.hash().clone();
    assert!(
        minted.addr.relay_urls().next().is_some(),
        "no relay in {:?}",
        minted.addr
    );
}
