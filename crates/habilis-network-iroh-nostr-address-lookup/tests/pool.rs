//! The pool against in-process relays: delivery, relay health, and how many
//! sockets it holds.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;
use habilis_network_iroh_nostr_address_lookup::{Event, Keys, Pool};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::{runtime, time};
use url::Url;

const TAG: [u8; 32] = [7u8; 32];

async fn relays(count: usize) -> Vec<TestRelay> {
    let mut relays = Vec::new();
    for _ in 0..count {
        relays.push(TestRelay::spawn().await.expect("spawn test relay"));
    }
    relays
}

/// The relays the pool holds now, in rank order.
fn connected_set(pool: &Pool) -> Vec<Url> {
    let held: Vec<Url> = pool.connected().collect();
    held
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

/// Publish until the receiver sees our event: a subscription can land a moment
/// after `connected()` says so, and the engine re-announces for the same reason.
async fn deliver(from: &Pool, to: &mut UnboundedReceiver<Event>, content: &str) -> Event {
    for _ in 0..50 {
        from.publish(&TAG, content.to_owned());
        if let Ok(Some(got)) = time::timeout(Duration::from_millis(300), to.recv()).await {
            assert_eq!(got.content, content, "the delivered content");
            assert_eq!(
                got.pubkey,
                from.pubkey(),
                "the event came from the publisher"
            );
            return got;
        }
    }
    panic!("no delivery of {content:?}");
}

#[tokio::test]
async fn two_pools_deliver_to_each_other() {
    let relays = relays(1).await;
    let (alice, mut alice_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    let (bob, mut bob_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    eventually("both connected", || {
        connected_set(&alice).len() == 1 && connected_set(&bob).len() == 1
    })
    .await;

    deliver(&alice, &mut bob_rx, "hi bob").await;
    deliver(&bob, &mut alice_rx, "hi alice").await;
}

#[tokio::test]
async fn an_event_carried_by_two_relays_arrives_once() {
    let relays = relays(2).await;
    let (alice, _alice_rx) = Pool::open(urls(&relays), 2, &[TAG]);
    let (bob, mut bob_rx) = Pool::open(urls(&relays), 2, &[TAG]);
    eventually("both on two relays", || {
        connected_set(&alice).len() == 2 && connected_set(&bob).len() == 2
    })
    .await;

    deliver(&alice, &mut bob_rx, "once").await;
    time::sleep(Duration::from_millis(300)).await;
    assert!(
        bob_rx.try_recv().is_err(),
        "the second relay's copy was dropped"
    );
}

#[tokio::test]
async fn a_rate_limited_relay_is_passed_over_and_delivery_still_happens() {
    let relays = relays(3).await;
    relays[0].refuse_events(Some("rate-limited: slow down"));
    let (alice, _alice_rx) = Pool::open(urls(&relays), 2, &[TAG]);
    let (bob, mut bob_rx) = Pool::open(urls(&relays), 2, &[TAG]);
    eventually("both connected", || {
        connected_set(&alice).len() == 2 && connected_set(&bob).len() == 2
    })
    .await;

    // Relay 0 refuses, relay 1 forwards.
    deliver(&alice, &mut bob_rx, "through the healthy one").await;
    // Relay 0 is now limited for alice, so she holds relay 2 to keep two
    // usable relays.
    eventually("alice refills to relay 2", || {
        connected_set(&alice).contains(&relays[2].url())
    })
    .await;
}

#[tokio::test]
async fn a_retired_relay_is_never_dialed_again() {
    let relays = relays(2).await;
    relays[0].refuse_subs(Some("blocked: not welcome"));
    let (first, _first_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    eventually("first pool moves to relay 1", || {
        connected_set(&first) == vec![relays[1].url()]
    })
    .await;
    let dialed = relays[0].accepted();
    // With the first pool gone, nothing holds the old connection: only the
    // hub's memory of the retirement can stop a fresh dial.
    drop(first);
    time::sleep(Duration::from_millis(100)).await;

    let (second, _second_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    eventually("second pool on relay 1", || {
        connected_set(&second) == vec![relays[1].url()]
    })
    .await;
    time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        relays[0].accepted(),
        dialed,
        "no new dial to a retired relay"
    );
}

#[tokio::test]
async fn a_dropped_connection_reconnects_and_resubscribes() {
    let relays = relays(1).await;
    let (alice, _alice_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    let (bob, mut bob_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    eventually("both connected", || {
        connected_set(&alice).len() == 1 && connected_set(&bob).len() == 1
    })
    .await;
    deliver(&alice, &mut bob_rx, "before").await;

    let before = relays[0].accepted();
    relays[0].drop_connections();
    eventually("the shared socket is dialed again", || {
        relays[0].accepted() > before && relays[0].connections() == 1
    })
    .await;
    deliver(&alice, &mut bob_rx, "after").await;
}

#[tokio::test]
async fn two_retired_relays_of_three_are_replaced_by_the_next_in_rank() {
    let relays = relays(5).await;
    relays[0].refuse_subs(Some("auth-required: NIP-42"));
    relays[1].refuse_subs(Some("pow: difficulty 20"));
    let (pool, _rx) = Pool::open(urls(&relays), 3, &[TAG]);
    eventually("ranks 3, 4 and 5 held", || {
        connected_set(&pool) == vec![relays[2].url(), relays[3].url(), relays[4].url()]
    })
    .await;
}

#[tokio::test]
async fn width_opens_and_closes_sockets_in_rank_order() {
    let relays = relays(3).await;
    let (pool, _rx) = Pool::open(urls(&relays), 3, &[TAG]);
    eventually("three connected", || connected_set(&pool).len() == 3).await;

    pool.set_width(1);
    eventually("only the first relay stays open", || {
        connected_set(&pool) == vec![relays[0].url()]
            && relays[1].connections() == 0
            && relays[2].connections() == 0
    })
    .await;
    assert_eq!(relays[0].connections(), 1, "one socket serves the pool");

    pool.set_width(3);
    eventually("the next two reopen", || connected_set(&pool).len() == 3).await;
}

#[tokio::test]
async fn two_pools_in_one_process_share_one_socket_per_relay() {
    let relays = relays(1).await;
    let (alice, _a) = Pool::open(urls(&relays), 1, &[TAG]);
    let (bob, _b) = Pool::open(urls(&relays), 1, &[[8u8; 32]]);
    eventually("both connected", || {
        connected_set(&alice).len() == 1 && connected_set(&bob).len() == 1
    })
    .await;
    assert_eq!(relays[0].connections(), 1, "one socket serves the pool");
    assert_eq!(relays[0].accepted(), 1, "dialed once");

    drop(alice);
    time::sleep(Duration::from_millis(200)).await;
    assert_eq!(relays[0].connections(), 1, "bob still holds the socket");
    drop(bob);
    eventually("the last pool closes the socket", || {
        relays[0].connections() == 0
    })
    .await;
}

/// Like `deliver`, but for up to `secs` seconds.
async fn deliver_within(secs: u64, from: &Pool, to: &mut UnboundedReceiver<Event>, content: &str) {
    let deadline = time::Instant::now() + Duration::from_secs(secs);
    while time::Instant::now() < deadline {
        from.publish(&TAG, content.to_owned());
        if let Ok(Some(got)) = time::timeout(Duration::from_millis(500), to.recv()).await {
            assert_eq!(got.content, content, "the delivered content");
            return;
        }
    }
    panic!("no delivery of {content:?} within {secs} s");
}

/// A connection task runs on the runtime of the first pool that dialed it.
/// When that runtime goes away, the next pool must dial again rather than
/// inherit a connection nobody drives.
#[test]
fn a_pool_survives_the_runtime_that_first_dialed_its_relay() {
    let relay_runtime = runtime::Runtime::new().expect("a tokio runtime");
    let relay = relay_runtime
        .block_on(TestRelay::spawn())
        .expect("spawn test relay");
    let ranking = vec![relay.url()];

    let first_runtime = runtime::Runtime::new().expect("a tokio runtime");
    let second_runtime = runtime::Runtime::new().expect("a tokio runtime");
    let (first, _first_rx) =
        first_runtime.block_on(async { Pool::open(ranking.clone(), 1, &[TAG]) });
    first_runtime.block_on(eventually("first connected", || {
        connected_set(&first).len() == 1
    }));
    let (bob, mut bob_rx) =
        second_runtime.block_on(async { Pool::open(ranking.clone(), 1, &[TAG]) });
    second_runtime.block_on(eventually("bob connected", || {
        connected_set(&bob).len() == 1
    }));

    drop(first);
    drop(first_runtime);

    second_runtime.block_on(async {
        let (alice, _alice_rx) = Pool::open(ranking, 1, &[TAG]);
        deliver_within(10, &alice, &mut bob_rx, "after the first runtime").await;
    });
}

/// A relay that accepts events and forwards none looks healthy by every
/// socket-level sign. Our own echo is the only proof it forwards.
#[tokio::test]
async fn a_relay_that_swallows_events_is_passed_over() {
    let relays = relays(2).await;
    relays[0].swallow_events(true);
    let (alice, _alice_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    let (bob, mut bob_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    eventually("both connected", || {
        connected_set(&alice).len() == 1 && connected_set(&bob).len() == 1
    })
    .await;
    // Both publish, as every member announces: each learns from its own
    // missing echo that relay 0 swallows, and both move on to relay 1.
    let deadline = time::Instant::now() + Duration::from_secs(30);
    while time::Instant::now() < deadline {
        alice.publish(&TAG, "past the swallower".to_owned());
        bob.publish(&TAG, "bob announces".to_owned());
        if let Ok(Some(got)) = time::timeout(Duration::from_millis(500), bob_rx.recv()).await {
            assert_eq!(got.content, "past the swallower", "the content arrives");
            assert!(
                connected_set(&bob).contains(&relays[1].url()),
                "bob holds the second relay"
            );
            return;
        }
    }
    panic!("no delivery past a relay that swallows events");
}

/// A relay may forward a copy with the content changed and the id kept. The
/// pool must not deliver it, and must not let it shadow a good copy.
#[tokio::test]
async fn a_tampered_copy_is_dropped() {
    let relays = relays(1).await;
    relays[0].tamper_events(true);
    let (alice, _alice_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    let (bob, mut bob_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    eventually("both connected", || {
        connected_set(&alice).len() == 1 && connected_set(&bob).len() == 1
    })
    .await;
    for _ in 0..5 {
        alice.publish(&TAG, "genuine".to_owned());
        time::sleep(Duration::from_millis(100)).await;
    }
    time::sleep(Duration::from_millis(300)).await;
    if let Ok(event) = bob_rx.try_recv() {
        panic!("a tampered event was delivered: {:?}", event.content);
    }
}

/// The pool checks the id of an event it receives, not its Schnorr signature:
/// the Nostr key is random and proves nothing, and the content authenticates
/// itself. An event with a valid id and a bad signature is delivered.
#[tokio::test]
async fn an_event_with_a_valid_id_and_a_bad_signature_is_delivered() {
    let relays = relays(1).await;
    let (bob, mut bob_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    eventually("bob connected", || connected_set(&bob).len() == 1).await;
    time::sleep(Duration::from_millis(200)).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs();
    let mut event = Event::sign(&Keys::generate(), now, &TAG, "unsigned".to_owned());
    event.signature = "00".repeat(64);
    relays[0].inject(&event);
    let got = time::timeout(Duration::from_secs(2), bob_rx.recv())
        .await
        .expect("an event with a valid id must arrive")
        .expect("the pool channel is open");
    assert_eq!(got.content, "unsigned", "the delivered content");
}

/// A relay that finishes the handshake and hangs up must be dialed with a
/// growing delay, or we hammer it once a second until it bans us.
#[tokio::test]
async fn a_relay_that_hangs_up_is_not_hammered() {
    let relays = relays(1).await;
    relays[0].hang_up_on_accept(true);
    let (_pool, _rx) = Pool::open(urls(&relays), 1, &[TAG]);
    time::sleep(Duration::from_secs(8)).await;
    // Delays of 1, 2 and 4 s put dials at about 0, 1, 3 and 7 s.
    let dials = relays[0].accepted();
    assert!(dials <= 4, "{dials} dials in 8 s");
}

/// A peer's clock can be a few seconds behind ours. Its events carry its
/// clock, so a subscription that starts at our "now" drops them.
#[tokio::test]
async fn a_peer_whose_clock_is_behind_still_reaches_us() {
    let relays = relays(1).await;
    let (bob, mut bob_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    eventually("bob connected", || connected_set(&bob).len() == 1).await;
    time::sleep(Duration::from_millis(200)).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs();
    let late = Event::sign(&Keys::generate(), now - 5, &TAG, "late".to_owned());
    relays[0].inject(&late);
    let got = time::timeout(Duration::from_secs(2), bob_rx.recv())
        .await
        .expect("an event 5 s behind must arrive")
        .expect("the pool channel is open");
    assert_eq!(got.content, "late", "the late event arrives");
}

/// A signalling event is a few kilobytes. A relay that sends a much larger frame is
/// broken or hostile; the socket is dropped rather than the frame buffered.
#[tokio::test]
async fn an_oversized_frame_drops_the_socket() {
    let relays = relays(1).await;
    let (pool, _rx) = Pool::open(urls(&relays), 1, &[TAG]);
    eventually("connected", || connected_set(&pool).len() == 1).await;
    let before = relays[0].accepted();
    relays[0].send_raw(&format!("[\"NOTICE\",\"{}\"]", "x".repeat(200 * 1024)));
    eventually("the socket is dialed again", || {
        relays[0].accepted() > before
    })
    .await;
}

/// A relay that closes a REQ for no stated reason gets it again with a growing
/// delay, not every 5 s.
#[tokio::test]
async fn an_unexplained_closed_backs_off() {
    let relays = relays(1).await;
    relays[0].refuse_subs(Some("error: too many subscriptions"));
    let (_pool, _rx) = Pool::open(urls(&relays), 1, &[TAG]);
    time::sleep(Duration::from_secs(17)).await;
    // The first REQ, then retries 5 and 10 s apart (at 5 and 15 s).
    let reqs = relays[0].reqs();
    assert!(reqs <= 3, "{reqs} REQs in 17 s");
}

/// A pool publishes as soon as it opens, while its sockets are still dialing:
/// the first announces land there. One publish, no retry, must arrive.
#[tokio::test]
async fn a_publish_made_while_dialing_is_sent() {
    let relays = relays(1).await;
    let (_bob, mut bob_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    let (alice, _alice_rx) = Pool::open(urls(&relays), 1, &[TAG]);
    alice.publish(&TAG, "early".to_owned());
    let got = time::timeout(Duration::from_secs(3), bob_rx.recv())
        .await
        .expect("a publish made while dialing must be sent")
        .expect("the pool channel is open");
    assert_eq!(got.content, "early", "the early event arrives");
}
