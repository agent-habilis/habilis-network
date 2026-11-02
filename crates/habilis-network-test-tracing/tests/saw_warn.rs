//! A test waits for a WARN that it expects, and `saw_warn` tells it when the
//! WARN came.

use habilis_network_test_tracing::{catch_panic, init, saw_warn};
use std::panic::AssertUnwindSafe;

#[test]
fn saw_warn_is_false_until_the_warn_is_logged() {
    let log = init();
    assert!(
        !saw_warn(module_path!(), "link lost"),
        "saw warn is false until the warn is logged"
    );
    tracing::warn!("link lost for peer 7");
    assert!(
        saw_warn(module_path!(), "link lost"),
        "saw warn is true once the warn is logged"
    );
    assert!(
        !saw_warn(module_path!(), "link restored"),
        "saw warn is false for another message"
    );
    assert!(
        !saw_warn("another::module", "link lost"),
        "saw warn is false for another module"
    );
    log.expect_warn(module_path!(), "link lost");
}

#[test]
fn saw_warn_ignores_an_error_with_the_same_text() {
    let result = catch_panic(AssertUnwindSafe(|| {
        let _log = init();
        tracing::error!("link lost");
        assert!(
            !saw_warn(module_path!(), "link lost"),
            "an error with the same text does not count as a warn"
        );
    }));
    assert!(result.is_err(), "the ERROR must still fail the test");
}

#[test]
fn saw_warn_matches_the_target_or_a_child_module_not_a_longer_name() {
    let log = init();
    tracing::warn!(target: "net::peer_extra", "link lost");
    assert!(
        !saw_warn("net::peer", "link lost"),
        "a longer module name is not the target"
    );
    assert!(
        saw_warn("net::peer_extra", "link lost"),
        "a child module of the target counts"
    );
    tracing::warn!(target: "net::peer::dial", "link lost");
    assert!(
        saw_warn("net::peer", "link lost"),
        "the target module counts its own warn"
    );
    log.expect_warn("net::peer_extra", "link lost");
    log.expect_warn("net::peer", "link lost");
}
