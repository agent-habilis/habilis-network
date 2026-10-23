//! The guard fails a test on a WARN or ERROR event from the test thread, and
//! passes a clean test. A spawned task is in `spawned_task.rs`, because an
//! event from a worker thread reaches every live guard of its binary.

use habilis_network_test_tracing::catch_panic;
use std::panic::AssertUnwindSafe;

use habilis_network_test_tracing::init;

fn panic_text(body: impl FnOnce()) -> Option<String> {
    let err = catch_panic(AssertUnwindSafe(body)).err()?;
    err.downcast_ref::<String>().cloned()
}

#[test]
fn a_clean_test_passes() {
    let _log = init();
    tracing::info!("nothing to report");
}

#[test]
fn an_error_from_the_test_thread_fails() {
    let text = panic_text(|| {
        let _log = init();
        tracing::error!("endpoint dropped");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected ERROR"), "{text}");
    assert!(text.contains("endpoint dropped"), "{text}");
}

#[test]
fn a_warn_from_the_test_thread_fails() {
    let text = panic_text(|| {
        let _log = init();
        tracing::warn!(peer = 7, "link lost");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected WARN"), "{text}");
    assert!(text.contains("link lost peer=7"), "{text}");
}

#[test]
fn an_expected_warn_that_occurs_passes() {
    let log = init();
    log.expect_warn(module_path!(), "link lost");
    tracing::warn!("link lost for peer 7");
}

#[test]
fn an_expected_warn_that_does_not_occur_fails() {
    let text = panic_text(|| {
        let log = init();
        log.expect_warn(module_path!(), "link lost");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("expected WARN"), "{text}");
    assert!(text.contains("it was not logged"), "{text}");
}

#[test]
fn an_expected_warn_that_occurs_twice_passes() {
    let log = init();
    log.expect_warn(module_path!(), "link lost");
    tracing::warn!("link lost for peer 7");
    tracing::warn!("link lost for peer 7");
}

#[test]
fn an_event_from_the_test_thread_is_not_marked_as_from_a_worker() {
    let text = panic_text(|| {
        let _log = init();
        tracing::warn!("link lost");
    });
    let text = text.expect("the guard must panic");
    assert!(!text.contains("from a worker thread"), "{text}");
}

#[test]
fn an_unexpected_warn_beside_an_expected_one_fails() {
    let text = panic_text(|| {
        let log = init();
        log.expect_warn(module_path!(), "link lost");
        tracing::warn!("link lost");
        tracing::warn!("something else");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("something else"), "{text}");
    assert!(!text.contains("it was not logged"), "{text}");
}

#[test]
fn an_expected_warn_does_not_excuse_an_error() {
    let text = panic_text(|| {
        let log = init();
        log.expect_warn(module_path!(), "link lost");
        tracing::warn!("link lost");
        tracing::error!("link lost");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected ERROR"), "{text}");
}

#[test]
fn an_expected_warn_does_not_cover_a_target_with_a_longer_name() {
    let text = panic_text(|| {
        let log = init();
        log.expect_warn("net::peer", "link lost");
        tracing::warn!(target: "net::peer_extra", "link lost");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected WARN net::peer_extra"), "{text}");
}
