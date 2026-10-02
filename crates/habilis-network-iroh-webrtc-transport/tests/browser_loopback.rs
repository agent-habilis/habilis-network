//! The browser backend against a real browser — the wasm mirror of
//! `loopback.rs`.
//!
//! The fast suite: four tests, a few seconds, green or red. The harness it
//! runs on (and how to invoke it) is documented in `browser_harness/mod.rs`;
//! the slow configuration sweep is `browser_matrix.rs`.
//!
//! ## Why this file exists
//!
//! Browser↔**browser** bulk transfer had never been exercised. Browser↔native
//! is what `docs/perf/` benchmarked (4–19 MB/s), and it exercises exactly one
//! of these pumps — the other end is `native::`, which is a different
//! implementation with different queues. A consumer driving two Chrome
//! instances found the pairing that had no coverage: small traffic and a ~9 KB
//! request/response round pass, then the first bulk read never answers and the
//! wire counters stay flat.
//!
//! So the tests below are deliberately staged — a small round first, then a
//! bulk one — because "small passes, bulk stalls" is the whole signature, and a
//! suite that only proved bytes can move at all would have gone on passing
//! throughout.
//!
//! Not in CI: it needs a browser and a way to drive one, like
//! `habilis-network-chunks/tests/idb_browser.rs`.

#![cfg(target_arch = "wasm32")]

mod browser_harness;

use browser_harness::{BULK_BYTES, Pair};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn a_small_request_round_trips() {
    let pair = Pair::negotiate().await.expect("negotiate");
    // The case that already worked, asserted first so a bulk failure below is
    // unambiguously about size and not about the pair being broken.
    pair.request(32).await.expect("small request");
    pair.shutdown().await;
}

#[wasm_bindgen_test]
async fn a_bulk_request_completes() {
    let pair = Pair::negotiate().await.expect("negotiate");
    pair.request(32).await.expect("small request");

    // `channel_bytes_settled`, not `channel_bytes`: the browser publishes these
    // counters on its own cadence, and a read taken the instant the last byte
    // is delivered can still describe the state before it. This assertion was
    // written against the raw read and duly failed on a verified 1 MiB transfer
    // — `received 4116 -> 4116`, on a machine that was busy — which is the
    // hunted signature produced by nothing but sampling.
    let (sent_before, received_before) = pair
        .channel_bytes_settled()
        .await
        .expect("a completed small request leaves a readable counter");
    let outcome = pair.request(BULK_BYTES).await;
    let settled = pair.channel_bytes_settled().await;

    // Counters read before the unwrap: on a stall they are the difference
    // between "the pump discarded everything and nothing was ever sent" and
    // "bytes went out and the far end never answered". A consumer reported the
    // first, from counters that turned out not to measure this channel; these
    // do, so the distinction is finally available.
    let outcome = outcome.map_err(|error| {
        format!(
            "{error}\ndata-channel bytes before: sent {sent_before}, received {received_before}"
        )
    });
    outcome.expect("bulk request");

    let (_, received_after) = settled.expect("a completed bulk transfer leaves a readable counter");
    // `f64` because that is what `getStats` reports; the comparison is against
    // a byte count that is nowhere near the mantissa's limit.
    assert!(
        received_after - received_before >= f64::from(u32::try_from(BULK_BYTES).expect("u32")),
        "the reply did not cross the channel: received {received_before} -> {received_after}\n\
         raw stats:\n{}",
        pair.dump_stats().await
    );
    pair.shutdown().await;
}

/// Four bulk transfers in flight at once, over four separate pairs.
///
/// The one resource every session on a hub shares is the inbound fan-in
/// channel (`IN_QUEUE`, 512 datagrams for the whole transport), and the
/// outbound side has no backpressure at all — `poll_send` drops on a full
/// queue and tells QUIC it succeeded. Transfers taken one at a time never
/// press on either. This is the cheapest shape that does, and "some channels
/// carried the share at speed while another stalled" is what a shared queue
/// under contention looks like from the outside.
#[wasm_bindgen_test]
async fn concurrent_bulk_transfers_all_complete() {
    let mut pairs = Vec::new();
    for _ in 0..4 {
        pairs.push(Pair::negotiate().await.expect("negotiate"));
    }

    let outcomes: Vec<_> =
        futures::future::join_all(pairs.iter().map(|pair| pair.request(BULK_BYTES))).await;

    // Every failure, not just the first: which subset stalled is the finding.
    let failures: Vec<String> = outcomes
        .iter()
        .enumerate()
        .filter_map(|(index, outcome)| {
            outcome
                .as_ref()
                .err()
                .map(|error| format!("pair {index}: {error}"))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of 4 concurrent bulk transfers stalled:\n{}",
        failures.len(),
        failures.join("\n")
    );

    // Contention is the point of this test, so the drop counters are the
    // result worth asserting on, not just the completion. Four bulk transfers
    // sharing one 512-datagram fan-in and four 256-datagram outbound queues is
    // exactly where a lane that silently discards would start doing so — and
    // QUIC would paper over it with retransmits, so the transfers could all
    // pass while the lane was in fact dropping steadily.
    for (index, pair) in pairs.iter().enumerate() {
        let counters = pair
            .client_hub
            .session_counters(&pair.server_id)
            .expect("a live session has counters");
        assert_eq!(
            counters.dropped(),
            0,
            "pair {index} dropped datagrams under contention: {counters:?}"
        );
    }

    for pair in pairs {
        pair.shutdown().await;
    }
}

/// Ten fresh channels in a row, each carrying a bulk transfer.
///
/// The consumer's finding was *intermittent per channel*: some channels between
/// the same two builds carried a 600 KB share at speed, and once a channel
/// stalled it stalled consistently. A single-channel test therefore passes
/// roughly as often as the bug allows, which is worse than no test — so the
/// acceptance criterion is a run of channels, not one.
#[wasm_bindgen_test]
async fn ten_fresh_channels_each_carry_a_bulk_transfer() {
    for round in 0..10 {
        let pair = Pair::negotiate().await.expect("negotiate");
        if let Err(error) = pair.request(BULK_BYTES).await {
            panic!("channel {round} of 10 failed its bulk transfer: {error}");
        }
        pair.shutdown().await;
    }
}
