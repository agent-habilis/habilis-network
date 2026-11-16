//! The data lane against in-process relays: delivery in order, the one relay both ends pick, the
//! budgets of the socket, and the bound on the receive side.

use std::time::{Duration, Instant};

use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;
use habilis_network_iroh_nostr_address_lookup::{DataPool, Datagram, RECEIVE_CAPACITY};
use tokio::sync::mpsc::Receiver;
use tokio::time;
use url::Url;

const ALICE: [u8; 32] = [1u8; 32];
const BOB: [u8; 32] = [2u8; 32];
const ALICE_TAG: [u8; 32] = [0xa1; 32];
const BOB_TAG: [u8; 32] = [0xb2; 32];

async fn relays(count: usize) -> Vec<TestRelay> {
    let mut relays = Vec::new();
    for _ in 0..count {
        relays.push(TestRelay::spawn().await.expect("spawn test relay"));
    }
    relays
}

fn urls(relays: &[TestRelay]) -> Vec<Url> {
    relays.iter().map(TestRelay::url).collect()
}

/// Poll `check` until it holds or 15 s pass.
async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..300 {
        if check() {
            return;
        }
        time::sleep(Duration::from_millis(50)).await;
    }
    assert!(check(), "timed out waiting for: {what}");
}

struct Node {
    pool: DataPool,
    datagrams: Receiver<Datagram>,
}

fn node(ranking: Vec<Url>, me: [u8; 32], tag: [u8; 32]) -> Node {
    let (pool, datagrams) = DataPool::open(ranking, me, tag);
    Node { pool, datagrams }
}

/// Send `payload` until the other end has it: a subscription can land a moment after
/// `connected()` says so.
async fn warm_up(from: &Node, to_tag: &[u8; 32], to: &mut Node) {
    for _ in 0..50 {
        from.pool.send(to_tag, b"warm".to_vec());
        if let Ok(Some(datagram)) =
            time::timeout(Duration::from_millis(300), to.datagrams.recv()).await
            && datagram.bytes == b"warm"
        {
            return;
        }
    }
    panic!("no delivery after 50 tries");
}

#[tokio::test]
async fn datagrams_cross_a_relay_in_order_with_the_sender_id() {
    let relays = relays(1).await;
    let alice = node(urls(&relays), ALICE, ALICE_TAG);
    let mut bob = node(urls(&relays), BOB, BOB_TAG);
    warm_up(&alice, &BOB_TAG, &mut bob).await;
    // The tail of the warm-up copies: a retry can leave extras behind.
    time::sleep(Duration::from_millis(400)).await;
    while bob.datagrams.try_recv().is_ok() {}

    for number in 0..20u8 {
        alice.pool.send(&BOB_TAG, vec![number; 100]);
    }
    for number in 0..20u8 {
        let datagram = time::timeout(Duration::from_secs(5), bob.datagrams.recv())
            .await
            .expect("a datagram in time")
            .expect("the channel is open");
        assert_eq!(
            datagram.bytes,
            vec![number; 100],
            "datagram {number} in order"
        );
        assert_eq!(datagram.from, ALICE, "the sender id");
    }
}

#[tokio::test]
async fn both_ends_use_the_first_relay_of_the_ranking() {
    let relays = relays(3).await;
    let alice = node(urls(&relays), ALICE, ALICE_TAG);
    let mut bob = node(urls(&relays), BOB, BOB_TAG);
    warm_up(&alice, &BOB_TAG, &mut bob).await;
    warm_up(&bob, &ALICE_TAG, &mut { alice }).await;
    assert!(relays[0].events() > 0, "the first relay carried the data");
    assert_eq!(relays[1].events(), 0, "the second relay carried none");
    assert_eq!(relays[2].events(), 0, "the third relay carried none");
}

#[tokio::test]
async fn a_dead_first_relay_moves_the_data_to_the_next() {
    let mut relays = relays(2).await;
    let ranking = urls(&relays);
    let alice = node(ranking.clone(), ALICE, ALICE_TAG);
    let mut bob = node(ranking, BOB, BOB_TAG);
    warm_up(&alice, &BOB_TAG, &mut bob).await;
    drop(relays.remove(0));
    warm_up(&alice, &BOB_TAG, &mut bob).await;
    assert!(relays[0].events() > 0, "the next relay carried the data");
}

#[tokio::test]
async fn no_data_goes_to_a_relay_outside_the_list() {
    let relays = relays(2).await;
    let alice = node(vec![relays[0].url()], ALICE, ALICE_TAG);
    let mut bob = node(vec![relays[0].url()], BOB, BOB_TAG);
    warm_up(&alice, &BOB_TAG, &mut bob).await;
    assert_eq!(
        relays[1].accepted(),
        0,
        "the relay outside the list was never dialed"
    );
    assert_eq!(relays[1].events(), 0, "and carried no event");
}

/// Two meshes of one process send flat out to one relay. The relay sees one socket, so it sees
/// the budget of a node, not twice that.
#[tokio::test]
async fn two_pools_of_one_process_stay_under_the_relay_budgets() {
    let relays = relays(1).await;
    let ranking = urls(&relays);
    let first = node(ranking.clone(), ALICE, ALICE_TAG);
    let mut first_peer = node(ranking.clone(), BOB, BOB_TAG);
    let second = node(ranking.clone(), [3u8; 32], [0xc3; 32]);
    let mut second_peer = node(ranking, [4u8; 32], [0xd4; 32]);
    warm_up(&first, &BOB_TAG, &mut first_peer).await;
    warm_up(&second, &[0xd4; 32], &mut second_peer).await;
    let (events_before, bytes_before) = (relays[0].events(), relays[0].event_bytes());

    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        for _ in 0..8 {
            first.pool.send(&BOB_TAG, vec![7u8; 1200]);
            second.pool.send(&[0xd4; 32], vec![8u8; 1200]);
        }
        time::sleep(Duration::from_millis(1)).await;
    }
    let seconds = started.elapsed().as_secs_f64();
    let frames = f64::from(u32::try_from(relays[0].events() - events_before).unwrap_or(u32::MAX));
    let bytes =
        f64::from(u32::try_from(relays[0].event_bytes() - bytes_before).unwrap_or(u32::MAX));
    assert!(
        frames <= 20.0 + 200.0 * seconds + 5.0,
        "{frames} frames in {seconds} s"
    );
    assert!(
        bytes <= 65_536.0 + 1_048_576.0 * seconds + 65_536.0,
        "{bytes} bytes in {seconds} s"
    );
    assert!(bytes > 262_144.0, "the data flowed: {bytes} bytes");
}

/// A consumer that never drains: the channel holds its capacity, and the rest is dropped and
/// counted. Memory does not grow with what the relay delivers.
#[tokio::test]
async fn a_consumer_that_does_not_drain_loses_datagrams_and_counts_them() {
    let relays = relays(1).await;
    let alice = node(urls(&relays), ALICE, ALICE_TAG);
    let mut bob = node(urls(&relays), BOB, BOB_TAG);
    warm_up(&alice, &BOB_TAG, &mut bob).await;
    time::sleep(Duration::from_millis(400)).await;
    while bob.datagrams.try_recv().is_ok() {}

    let total = RECEIVE_CAPACITY * 3;
    for index in 0..total {
        alice
            .pool
            .send(&BOB_TAG, vec![u8::try_from(index % 251).unwrap_or(0); 40]);
        if index % 100 == 0 {
            time::sleep(Duration::from_millis(20)).await;
        }
    }
    eventually("datagrams are dropped", || bob.pool.dropped() > 0).await;
    let mut held = 0;
    while bob.datagrams.try_recv().is_ok() {
        held += 1;
    }
    assert!(held <= RECEIVE_CAPACITY, "the channel held {held}");
}

#[tokio::test]
async fn the_first_datagram_after_idle_arrives_before_a_tick_would_matter() {
    let relays = relays(1).await;
    let alice = node(urls(&relays), ALICE, ALICE_TAG);
    let mut bob = node(urls(&relays), BOB, BOB_TAG);
    warm_up(&alice, &BOB_TAG, &mut bob).await;
    time::sleep(Duration::from_millis(500)).await;
    while bob.datagrams.try_recv().is_ok() {}

    let sent = Instant::now();
    alice.pool.send(&BOB_TAG, b"after idle".to_vec());
    let datagram = time::timeout(Duration::from_secs(2), bob.datagrams.recv())
        .await
        .expect("a datagram in time")
        .expect("the channel is open");
    assert_eq!(datagram.bytes, b"after idle", "the datagram");
    assert!(
        sent.elapsed() < Duration::from_millis(250),
        "the first datagram took {:?}",
        sent.elapsed()
    );
}
