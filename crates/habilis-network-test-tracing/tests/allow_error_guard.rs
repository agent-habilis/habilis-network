//! An ERROR that a test allows excuses that ERROR only: any other ERROR, and any WARN, still fails
//! the test. These cases build their own guard, so they use the plain test attribute.

use std::panic::AssertUnwindSafe;

fn panic_text(body: impl FnOnce() + Send) -> Option<String> {
    let err = habilis_network_test_tracing::catch_panic(AssertUnwindSafe(body)).err()?;
    let text: Option<&String> = err.downcast_ref();
    text.cloned()
}

#[test]
fn an_allowed_error_that_occurs_passes() {
    let log = habilis_network_test_tracing::init();
    log.allow_error(module_path!(), "dropped transmit");
    tracing::error!("unknown address, dropped transmit");
}

#[test]
fn an_allowed_error_that_does_not_occur_passes() {
    let log = habilis_network_test_tracing::init();
    log.allow_error(module_path!(), "dropped transmit");
}

#[test]
fn an_error_that_is_not_allowed_still_fails() {
    let text = panic_text(|| {
        let log = habilis_network_test_tracing::init();
        log.allow_error(module_path!(), "dropped transmit");
        tracing::error!("socket closed");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected ERROR"), "{text}");
    assert!(text.contains("socket closed"), "{text}");
}

#[test]
fn an_allowed_error_does_not_excuse_a_warn_of_the_same_text() {
    let text = panic_text(|| {
        let log = habilis_network_test_tracing::init();
        log.allow_error(module_path!(), "dropped transmit");
        tracing::warn!("dropped transmit");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected WARN"), "{text}");
}

#[test]
fn an_allowed_warn_does_not_excuse_an_error_of_the_same_text() {
    let text = panic_text(|| {
        let log = habilis_network_test_tracing::init();
        log.allow_warn(module_path!(), "dropped transmit");
        tracing::error!("dropped transmit");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected ERROR"), "{text}");
}
