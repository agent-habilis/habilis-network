//! `#[test]` of this crate, imported by name, replaces the builtin attribute. A
//! sync test gets a guard, an async test runs on a runtime that drops before
//! its guard.

use habilis_network_test_tracing::test;

struct LogsOnDrop;

impl Drop for LogsOnDrop {
    fn drop(&mut self) {
        tracing::error!("endpoint dropped by the runtime");
    }
}

#[test]
fn a_clean_sync_test_passes() {
    tracing::info!("nothing to report");
}

#[test]
#[should_panic(expected = "unexpected ERROR")]
fn a_sync_test_that_logs_an_error_fails() {
    tracing::error!("endpoint dropped");
}

#[test]
async fn a_clean_async_test_passes() {
    tokio::task::yield_now().await;
}

#[test]
#[should_panic(expected = "unexpected WARN")]
async fn an_async_test_whose_task_logs_a_warn_fails() {
    tokio::spawn(async { tracing::warn!("relay actor errored") })
        .await
        .expect("task");
}

#[test(flavor = "multi_thread", worker_threads = 2)]
#[should_panic(expected = "endpoint dropped by the runtime")]
async fn an_event_of_the_runtime_drop_fails_a_multi_thread_test() {
    tokio::spawn(async {
        let _logs = LogsOnDrop;
        std::future::pending::<()>().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

#[test]
async fn an_async_test_can_return_a_result() -> Result<(), String> {
    Ok(())
}
