//! The data lane in a browser: two `DataPool`s on a relay that runs outside the page, and a
//! datagram that goes from one to the other through the browser's own `WebSocket`. This is the
//! only run of the browser writer, with its check of `bufferedAmount`.
//!
//! A page cannot run a relay, so the test reads the address of one at build time. Start the
//! relay, then build with the address:
//!
//! ```text
//! cargo run -p habilis-network-iroh-nostr-address-lookup --example serve_relay -- 127.0.0.1:7447 &
//! NOSTR_TEST_RELAY_URL=ws://127.0.0.1:7447 WASM_BINDGEN_USE_BROWSER=1 \
//!     cargo test --target wasm32-unknown-unknown -p habilis-network-iroh-nostr-address-lookup \
//!     --test data_browser
//! ```
//!
//! Without the address the test says so and passes. The two pools share one page, so they share
//! one socket per relay, as two pools of one process do on a host.
//!
//! The module is gated, not the crate root: a root gated by `target_arch` drops the crate
//! attribute that the `Omitted patterns` step of the CI injects, and the step fails on a host.

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::time::Duration;

    use habilis_network_iroh_nostr_address_lookup::DataPool;
    use n0_future::time::{sleep, timeout};
    use tokio::sync::mpsc::Receiver;
    use url::Url;
    use wasm_bindgen_test::{console_log, wasm_bindgen_test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    /// The relay of the run, fixed when the test is built.
    const RELAY: Option<&str> = option_env!("NOSTR_TEST_RELAY_URL");

    const ALICE: [u8; 32] = [1u8; 32];
    const BOB: [u8; 32] = [2u8; 32];
    const ALICE_TAG: [u8; 32] = [0xa1; 32];
    const BOB_TAG: [u8; 32] = [0xb2; 32];

    /// The next datagram `bob` reads, or `None` after `wait`.
    async fn next(
        bob: &mut Receiver<habilis_network_iroh_nostr_address_lookup::Datagram>,
        wait: Duration,
    ) -> Option<Vec<u8>> {
        timeout(wait, bob.recv())
            .await
            .ok()
            .flatten()
            .map(|datagram| datagram.bytes)
    }

    #[wasm_bindgen_test]
    async fn a_datagram_goes_from_one_browser_pool_to_another() {
        let Some(relay) = RELAY else {
            console_log!("skipped: NOSTR_TEST_RELAY_URL was not set when the test was built");
            return;
        };
        let relay: Url = relay.parse().expect("NOSTR_TEST_RELAY_URL is a URL");
        let (alice, _alice_datagrams) = DataPool::open(vec![relay.clone()], ALICE, ALICE_TAG);
        let (_bob, mut bob_datagrams) = DataPool::open(vec![relay], BOB, BOB_TAG);

        // A subscription can land a moment after the socket is up: send until the first one arrives.
        let mut warmed = false;
        for _ in 0..50 {
            alice.send(&BOB_TAG, b"warm".to_vec());
            if next(&mut bob_datagrams, Duration::from_millis(300))
                .await
                .as_deref()
                == Some(&b"warm"[..])
            {
                warmed = true;
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert!(warmed, "no datagram reached the other pool in 50 tries");

        // The copies of the warm-up that the retries left come first; a marker ends them.
        alice.send(&BOB_TAG, b"marker".to_vec());
        while next(&mut bob_datagrams, Duration::from_secs(5))
            .await
            .expect("the marker in time")
            != b"marker"
        {}

        let payload: Vec<u8> = (0..1200u32)
            .map(|index| u8::try_from(index % 251).unwrap_or(0))
            .collect();
        alice.send(&BOB_TAG, payload.clone());
        assert_eq!(
            next(&mut bob_datagrams, Duration::from_secs(5)).await,
            Some(payload),
            "the datagram arrives whole"
        );
    }
}
