//! `run` and `run_multi_thread` drop the runtime before the guard, so an event
//! that the runtime logs while it drops its tasks belongs to the test.

use habilis_network_test_tracing::catch_panic;
use std::panic::AssertUnwindSafe;

use habilis_network_test_tracing::{init, run, run_multi_thread};

struct LogsOnDrop;

impl Drop for LogsOnDrop {
    fn drop(&mut self) {
        tracing::error!("endpoint dropped by the runtime");
    }
}

fn panic_text(body: impl FnOnce()) -> String {
    let err = catch_panic(AssertUnwindSafe(body)).expect_err("the guard must panic");
    err.downcast_ref::<String>().cloned().expect("panic text")
}

#[test]
fn run_returns_the_output_of_the_future() {
    assert_eq!(
        run(init(), async { 7 }),
        7,
        "run returns the output of the future"
    );
}

#[test]
fn an_event_of_the_runtime_drop_fails_a_current_thread_test() {
    let text = panic_text(|| {
        run(init(), async {
            tokio::spawn(async {
                let _logs = LogsOnDrop;
                std::future::pending::<()>().await;
            });
            tokio::task::yield_now().await;
        });
    });
    assert!(text.contains("unexpected ERROR"), "{text}");
    assert!(text.contains("endpoint dropped by the runtime"), "{text}");
}

#[test]
fn an_event_of_the_runtime_drop_fails_a_multi_thread_test() {
    let text = panic_text(|| {
        run_multi_thread(init(), 2, async {
            tokio::spawn(async {
                let _logs = LogsOnDrop;
                std::future::pending::<()>().await;
            });
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });
    });
    assert!(text.contains("unexpected ERROR"), "{text}");
    assert!(text.contains("endpoint dropped by the runtime"), "{text}");
}
