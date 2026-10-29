//! A WARN from a spawned task of a multi-thread runtime fails the test that
//! owns the guard. Alone in its binary: the event comes from a worker thread,
//! so it reaches every live guard of the binary.

use std::panic::AssertUnwindSafe;

use tokio::runtime;
#[test]
fn a_warn_from_a_spawned_task_fails() {
    let runtime = runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let err = habilis_network_test_tracing::catch_panic(AssertUnwindSafe(|| {
        let _log = habilis_network_test_tracing::init();
        runtime.block_on(async {
            tokio::spawn(async { tracing::warn!("relay actor errored") })
                .await
                .expect("task");
        });
    }))
    .expect_err("the guard must panic");
    let text = err.downcast_ref::<String>().expect("panic text");
    assert!(text.contains("unexpected WARN"), "{text}");
    assert!(text.contains("relay actor errored"), "{text}");
    assert!(text.contains("tokio-rt-worker"), "{text}");
    assert!(text.contains("from a worker thread"), "{text}");
}
