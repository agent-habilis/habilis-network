//! The data lane against in-process relays: delivery in order, the one relay both ends pick, the
//! budgets of the socket, and the bound on the receive side.

use std::time::{Duration, Instant};

use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;
use habilis_network_iroh_nostr_address_lookup::{
    DataPool, Datagram, MAX_DATA_RELAYS, RECEIVE_CAPACITY,
};
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

/// Wait until everything `from` sent before this call has come out of `to`: send a marker and read
/// up to it. The copies of the warm-up that a retry left behind come first, in order, because one
/// sender and one relay keep the order. A fixed sleep would only guess how long they take.
async fn settle(from: &Node, to_tag: &[u8; 32], to: &mut Node) {
    from.pool.send(to_tag, b"marker".to_vec());
    loop {
        let datagram = time::timeout(Duration::from_secs(5), to.datagrams.recv())
            .await
            .expect("the marker in time")
            .expect("the channel is open");
        if datagram.bytes == b"marker" {
            return;
        }
    }
}

#[tokio::test]
async fn datagrams_cross_a_relay_in_order_with_the_sender_id() {
    let relays = relays(1).await;
    let alice = node(urls(&relays), ALICE, ALICE_TAG);
    let mut bob = node(urls(&relays), BOB, BOB_TAG);
    warm_up(&alice, &BOB_TAG, &mut bob).await;
    settle(&alice, &BOB_TAG, &mut bob).await;

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

/// A rate limit is per sender, so two ends can see different relays as healthy, and a sender can
/// fall to a relay far down the list. The receiver hears it only if it listens there: on every
/// relay of the list, not on the first two.
#[tokio::test]
async fn a_node_listens_on_every_relay_of_the_list() {
    let relays = relays(3).await;
    let bob = node(urls(&relays), BOB, BOB_TAG);
    eventually("bob holds all three relays", || {
        bob.pool.connected().count() == 3
    })
    .await;
    for relay in &relays {
        assert_eq!(relay.connections(), 1, "one data socket on each relay");
    }
}

/// The list is capped, and both ends cap it the same way: a relay past the cap carries no data.
#[tokio::test]
async fn a_relay_past_the_listen_cap_carries_no_data() {
    let relays = relays(MAX_DATA_RELAYS + 1).await;
    let alice = node(urls(&relays), ALICE, ALICE_TAG);
    let mut bob = node(urls(&relays), BOB, BOB_TAG);
    warm_up(&alice, &BOB_TAG, &mut bob).await;
    let last = relays.last().expect("a last relay");
    assert_eq!(
        last.accepted(),
        0,
        "the relay past the cap was never dialed"
    );
}

/// One data relay answers "rate-limited:" once. While the wait runs the lane takes nothing; when
/// it ends the lane takes a frame again, and that frame is the probe that earns the relay `Up`.
/// A transport that sends only while the lane is sendable must see that moment, or no frame ever
/// goes and the lane stays shut.
#[tokio::test]
async fn a_lane_with_one_relay_recovers_from_one_rate_limit() {
    let relays = relays(1).await;
    relays[0].refuse_events(Some("rate-limited: slow down"));
    let alice = node(urls(&relays), ALICE, ALICE_TAG);
    let mut bob = node(urls(&relays), BOB, BOB_TAG);
    eventually("the lane takes a frame", || alice.pool.sendable()).await;
    alice.pool.send(&BOB_TAG, b"refused".to_vec());
    eventually("the relay limits the lane", || !alice.pool.sendable()).await;
    relays[0].refuse_events(None);
    // The first wait is 1 s. The pool must say so when it ends, not at its next slow check.
    let mut sendable_again = false;
    for _ in 0..60 {
        if alice.pool.sendable() {
            sendable_again = true;
            break;
        }
        time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        sendable_again,
        "the lane took no frame 3 s after a 1 s wait"
    );
    warm_up(&alice, &BOB_TAG, &mut bob).await;
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
    assert_eq!(
        relays[0].accepted(),
        1,
        "both pools of the process share one socket to the relay"
    );
}

/// A consumer that never drains: the channel holds its capacity, and the rest is dropped and
/// counted. Memory does not grow with what the relay delivers.
#[tokio::test]
async fn a_consumer_that_does_not_drain_loses_datagrams_and_counts_them() {
    let relays = relays(1).await;
    let alice = node(urls(&relays), ALICE, ALICE_TAG);
    let mut bob = node(urls(&relays), BOB, BOB_TAG);
    warm_up(&alice, &BOB_TAG, &mut bob).await;
    settle(&alice, &BOB_TAG, &mut bob).await;

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
    assert_eq!(
        held, RECEIVE_CAPACITY,
        "the channel was full when the first datagram was dropped, and nobody drained it"
    );
}

/// That the first datagram after an idle spell goes out at once, with no wait for a tick, is
/// shown in virtual time by the tests of the queue and of the socket. This one shows that it
/// arrives.
#[tokio::test]
async fn the_first_datagram_after_idle_arrives() {
    let relays = relays(1).await;
    let alice = node(urls(&relays), ALICE, ALICE_TAG);
    let mut bob = node(urls(&relays), BOB, BOB_TAG);
    warm_up(&alice, &BOB_TAG, &mut bob).await;
    settle(&alice, &BOB_TAG, &mut bob).await;

    alice.pool.send(&BOB_TAG, b"after idle".to_vec());
    let datagram = time::timeout(Duration::from_secs(5), bob.datagrams.recv())
        .await
        .expect("a datagram in time")
        .expect("the channel is open");
    assert_eq!(datagram.bytes, b"after idle", "the datagram");
}
