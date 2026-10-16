//! `init_capturing` keeps a log line that a test asserts on, and still fails
//! the test on a WARN or ERROR event that its own filter hides.

use std::panic::{AssertUnwindSafe, catch_unwind};

use habilis_network_test_tracing::init_capturing;

#[test]
fn the_log_text_holds_the_lines_that_the_filter_admits() {
    let log = init_capturing("capturing=info");
    tracing::info!("beacon role active");
    tracing::debug!("filtered out");
    let logs = log.logs();
    assert!(logs.contains("beacon role active"), "{logs}");
    assert!(!logs.contains("filtered out"), "{logs}");
}

#[test]
fn a_warn_that_the_filter_hides_still_fails() {
    let err = catch_unwind(AssertUnwindSafe(|| {
        let log = init_capturing("capturing=info");
        tracing::warn!(target: "elsewhere", "link lost");
        assert!(!log.logs().contains("link lost"));
    }))
    .expect_err("the guard must panic");
    let text = err.downcast_ref::<String>().expect("panic text");
    assert!(
        text.contains("unexpected WARN elsewhere: link lost"),
        "{text}"
    );
}
