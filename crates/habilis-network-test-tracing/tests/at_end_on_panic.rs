//! A test whose body panics still closes what it registered with `at_end`, before its guard
//! drops. A handle that stays in the registration would drop at the end of the thread, after the
//! guard left the live list, and its log would fail every test that runs beside it.

use std::rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::{task, time};
static FIRST_IN: AtomicBool = AtomicBool::new(false);
static SECOND_IN: AtomicBool = AtomicBool::new(false);
static CLOSED: AtomicBool = AtomicBool::new(false);

struct Endpoint;

impl Endpoint {
    async fn close(&self) {
        task::yield_now().await;
        CLOSED.store(true, Ordering::SeqCst);
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if !CLOSED.load(Ordering::SeqCst) {
            tracing::error!("endpoint dropped without close");
        }
    }
}

/// Returns once the other test is inside its body too, so that both are live.
async fn meet(mine: &AtomicBool, other: &AtomicBool) {
    mine.store(true, Ordering::SeqCst);
    let started = Instant::now();
    while !other.load(Ordering::SeqCst) {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the other test never started beside this one"
        );
        time::sleep(Duration::from_millis(10)).await;
    }
}

#[test]
#[should_panic(expected = "the body of the first test fails")]
fn a_test_that_panics_with_a_registered_endpoint_fails_with_its_own_panic() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            let endpoint = rc::Rc::new(Endpoint);
            let closer = rc::Rc::clone(&endpoint);
            ::habilis_network_test_tracing::at_end(async move { closer.close().await });
            meet(&FIRST_IN, &SECOND_IN).await;
            panic!("the body of the first test fails");
        },
    );
}

#[test]
fn the_test_beside_a_test_that_panicked_with_an_endpoint_passes() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            meet(&SECOND_IN, &FIRST_IN).await;
            time::sleep(Duration::from_secs(1)).await;
        },
    );
}
