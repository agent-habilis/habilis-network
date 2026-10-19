//! A test waits for a WARN that it expects, and `saw_warn` tells it when the
//! WARN came.

use habilis_network_test_tracing::{init, saw_warn};

#[test]
fn saw_warn_is_false_until_the_warn_is_logged() {
    let log = init();
    assert!(!saw_warn(module_path!(), "link lost"));
    tracing::warn!("link lost for peer 7");
    assert!(saw_warn(module_path!(), "link lost"));
    assert!(!saw_warn(module_path!(), "link restored"));
    assert!(!saw_warn("another::module", "link lost"));
    log.expect_warn(module_path!(), "link lost");
}

#[test]
fn saw_warn_ignores_an_error_with_the_same_text() {
    let result = std::panic::catch_unwind(|| {
        let _log = init();
        tracing::error!("link lost");
        assert!(!saw_warn(module_path!(), "link lost"));
    });
    assert!(result.is_err(), "the ERROR must still fail the test");
}

#[test]
fn saw_warn_matches_the_target_or_a_child_module_not_a_longer_name() {
    let log = init();
    tracing::warn!(target: "net::peer_extra", "link lost");
    assert!(!saw_warn("net::peer", "link lost"));
    assert!(saw_warn("net::peer_extra", "link lost"));
    tracing::warn!(target: "net::peer::dial", "link lost");
    assert!(saw_warn("net::peer", "link lost"));
    log.expect_warn("net::peer_extra", "link lost");
    log.expect_warn("net::peer", "link lost");
}
