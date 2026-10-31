//! A WARN that a test allows may come, or not, and never fails the test. The scenario of the
//! test decides, such as a handover that two members can race. A test that the `test` attribute
//! guards allows its WARN with the free function. The cases that need a guard of their own are in
//! `allow_warn_guard.rs`.

#[test]
fn an_allowed_warn_that_occurs_passes() {
    let _guard = ::habilis_network_test_tracing::init();
    ::habilis_network_test_tracing::allow_warn(module_path!(), "link replaced");
    tracing::warn!("link replaced by a rival");
}

#[test]
fn an_allowed_warn_that_does_not_occur_passes() {
    let _guard = ::habilis_network_test_tracing::init();
    ::habilis_network_test_tracing::allow_warn(module_path!(), "link replaced");
}
