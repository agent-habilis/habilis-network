//! `init_capturing` keeps a log line that a test asserts on, and still fails
//! the test on a WARN or ERROR event that its own filter hides.

use std::panic::AssertUnwindSafe;

use habilis_network_test_tracing::{captured_logs, init_capturing};

mod support;

#[test]
fn the_log_text_holds_the_lines_that_the_filter_admits() {
    support::without_rust_log(
        "the_log_text_holds_the_lines_that_the_filter_admits",
        || {
            let _log = init_capturing("capturing=info");
            tracing::info!("beacon role active");
            tracing::debug!("filtered out");
            let logs = captured_logs();
            assert!(logs.contains("beacon role active"), "{logs}");
            assert!(!logs.contains("filtered out"), "{logs}");
        },
    );
}

#[test]
fn a_warn_that_the_filter_hides_still_fails() {
    support::without_rust_log("a_warn_that_the_filter_hides_still_fails", || {
        let err = habilis_network_test_tracing::catch_panic(AssertUnwindSafe(|| {
            let _log = init_capturing("capturing=info");
            tracing::warn!(target: "elsewhere", "link lost");
            assert!(
                !captured_logs().contains("link lost"),
                "a warn that the filter hides still fails"
            );
        }))
        .expect_err("the guard must panic");
        let text: &String = err.downcast_ref().expect("panic text");
        assert!(
            text.contains("unexpected WARN elsewhere: link lost"),
            "{text}"
        );
    });
}
