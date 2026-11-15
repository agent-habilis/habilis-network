//! A test that the `test` attribute guards expects its WARN with the free
//! function `expect_warn`, since the guard is out of its reach.

#[test]
fn an_expected_warn_that_occurs_passes() {
    let _guard = ::habilis_network_test_tracing::init();
    ::habilis_network_test_tracing::expect_warn(module_path!(), "link lost");
    tracing::warn!("link lost for peer 7");
}

#[test]
#[should_panic(expected = "it was not logged")]
fn an_expected_warn_that_does_not_occur_fails() {
    let _guard = ::habilis_network_test_tracing::init();
    ::habilis_network_test_tracing::expect_warn(module_path!(), "link lost");
}

#[test]
fn an_async_test_expects_a_warn_of_its_task() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        ::habilis_network_test_tracing::expect_warn(module_path!(), "relay actor errored");
        tokio::spawn(async { tracing::warn!("relay actor errored") })
            .await
            .expect("task");
    });
}
