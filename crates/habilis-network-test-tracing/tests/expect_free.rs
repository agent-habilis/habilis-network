//! A test that the `test` attribute guards expects its WARN with the free
//! function `expect_warn`, since the guard is out of its reach.

use habilis_network_test_tracing::{expect_warn, test};

#[test]
fn an_expected_warn_that_occurs_passes() {
    expect_warn(module_path!(), "link lost");
    tracing::warn!("link lost for peer 7");
}

#[test]
#[should_panic(expected = "it was not logged")]
fn an_expected_warn_that_does_not_occur_fails() {
    expect_warn(module_path!(), "link lost");
}

#[test]
async fn an_async_test_expects_a_warn_of_its_task() {
    expect_warn(module_path!(), "relay actor errored");
    tokio::spawn(async { tracing::warn!("relay actor errored") })
        .await
        .expect("task");
}
