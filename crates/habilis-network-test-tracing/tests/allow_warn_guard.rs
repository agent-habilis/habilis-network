//! A WARN that a test allows excuses that WARN only: any other WARN, and any ERROR, still fails
//! the test. These cases build their own guard, so they use the plain test attribute.

use std::panic::AssertUnwindSafe;

fn panic_text(body: impl FnOnce()) -> Option<String> {
    let err = habilis_network_test_tracing::catch_panic(AssertUnwindSafe(body)).err()?;
    err.downcast_ref::<String>().cloned()
}

#[test]
fn a_warn_that_is_not_allowed_still_fails() {
    let text = panic_text(|| {
        let log = habilis_network_test_tracing::init();
        log.allow_warn(module_path!(), "link replaced");
        tracing::warn!("link lost");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected WARN"), "{text}");
    assert!(text.contains("link lost"), "{text}");
}

#[test]
fn an_allowed_warn_does_not_excuse_an_error() {
    let text = panic_text(|| {
        let log = habilis_network_test_tracing::init();
        log.allow_warn(module_path!(), "link replaced");
        tracing::error!("link replaced");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected ERROR"), "{text}");
}

#[test]
fn an_allowed_warn_that_occurs_or_not_passes_on_a_guard() {
    let log = habilis_network_test_tracing::init();
    log.allow_warn(module_path!(), "link replaced");
    tracing::warn!("link replaced by a rival");
}
