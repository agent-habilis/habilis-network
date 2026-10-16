//! A test that starts a guard again on its own thread, as a test with several
//! rounds does, does not wait for the lock that its own thread holds.

use habilis_network_test_tracing::init;

#[test]
fn a_second_guard_on_the_same_thread_does_not_wait_for_the_first() {
    drop(init());
    drop(init());
}
