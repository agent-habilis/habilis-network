//! An ERROR that a test allows excuses that ERROR only: any other ERROR, and a WARN of the same
//! text, still fail the test. These cases build their own guard, so they use the plain test
//! attribute.

use std::panic::AssertUnwindSafe;

fn panic_text(body: impl FnOnce() + Send) -> Option<String> {
    let err = habilis_network_test_tracing::catch_panic(AssertUnwindSafe(body)).err()?;
    let text: Option<&String> = err.downcast_ref();
    text.cloned()
}

#[test]
fn an_allowed_error_that_occurs_passes() {
    let log = habilis_network_test_tracing::init();
    log.allow_error(module_path!(), "connection reset");
    tracing::error!("failed: connection reset by the client");
}

#[test]
fn an_allowed_error_that_does_not_occur_passes() {
    let _log = habilis_network_test_tracing::init();
    habilis_network_test_tracing::allow_error(module_path!(), "connection reset");
}

#[test]
fn an_error_that_is_not_allowed_still_fails() {
    let text = panic_text(|| {
        let log = habilis_network_test_tracing::init();
        log.allow_error(module_path!(), "connection reset");
        tracing::error!("disk full");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected ERROR"), "{text}");
    assert!(text.contains("disk full"), "{text}");
}

#[test]
fn an_allowed_error_does_not_excuse_a_warn() {
    let text = panic_text(|| {
        let log = habilis_network_test_tracing::init();
        log.allow_error(module_path!(), "connection reset");
        tracing::warn!("connection reset");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected WARN"), "{text}");
}
