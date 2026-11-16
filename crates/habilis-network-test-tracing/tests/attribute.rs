//! `#[test]` of this crate, imported by name, replaces the builtin attribute. A
//! sync test gets a guard, an async test runs on a runtime that drops before
//! its guard.

use std::future;
use std::time::Duration;
use tokio::{task, time};
struct LogsOnDrop;

impl Drop for LogsOnDrop {
    fn drop(&mut self) {
        tracing::error!("endpoint dropped by the runtime");
    }
}

#[test]
fn a_clean_sync_test_passes() {
    let _guard = ::habilis_network_test_tracing::init();
    tracing::info!("nothing to report");
}

#[test]
#[should_panic(expected = "unexpected ERROR")]
fn a_sync_test_that_logs_an_error_fails() {
    let _guard = ::habilis_network_test_tracing::init();
    tracing::error!("endpoint dropped");
}

#[test]
fn a_clean_async_test_passes() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        task::yield_now().await;
    });
}

#[test]
#[should_panic(expected = "unexpected WARN")]
fn an_async_test_whose_task_logs_a_warn_fails() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        tokio::spawn(async { tracing::warn!("relay actor errored") })
            .await
            .expect("task");
    });
}

#[test]
#[should_panic(expected = "endpoint dropped by the runtime")]
fn an_event_of_the_runtime_drop_fails_a_multi_thread_test() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            tokio::spawn(async {
                let _logs = LogsOnDrop;
                let forever: future::Pending<()> = future::pending();
                forever.await;
            });
            time::sleep(Duration::from_millis(50)).await;
        },
    );
}

#[test]
fn an_async_test_can_return_a_result() -> Result<(), String> {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async { Ok(()) })
}
