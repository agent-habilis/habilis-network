//! Two async tests run side by side, and a WARN of the runtime of one fails only
//! that test: the worker threads of a runtime of this crate carry the name of
//! their test.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static FIRST_IN: AtomicBool = AtomicBool::new(false);
static SECOND_IN: AtomicBool = AtomicBool::new(false);

/// Returns once the other test is inside its body too, so that both are live.
async fn meet(mine: &AtomicBool, other: &AtomicBool) {
    mine.store(true, Ordering::SeqCst);
    let started = Instant::now();
    while !other.load(Ordering::SeqCst) {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the other test never started beside this one"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[test]
#[should_panic(expected = "unexpected WARN")]
fn a_warn_of_a_task_fails_the_test_that_spawned_it() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            meet(&FIRST_IN, &SECOND_IN).await;
            tokio::spawn(async { tracing::warn!("relay actor errored") })
                .await
                .expect("task");
            tokio::time::sleep(Duration::from_millis(300)).await;
        },
    );
}

#[test]
fn the_test_beside_it_passes() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            meet(&SECOND_IN, &FIRST_IN).await;
            tokio::time::sleep(Duration::from_millis(600)).await;
        },
    );
}
