//! An event that arrives after the guard of a test dropped, for example from a
//! runtime that drops its endpoints after the test body, fails the next test
//! and names the test that ended.

use std::panic::AssertUnwindSafe;
use std::thread;

fn named<T: Send + 'static>(name: &str, body: impl FnOnce() -> T + Send + 'static) -> T {
    let builder = thread::Builder::new().name(name.to_owned());
    let handle = builder.spawn(body).expect("spawn");
    handle.join().expect("join")
}

#[test]
fn an_event_after_the_guard_dropped_fails_the_next_test() {
    named("late_first", || {
        drop(habilis_network_test_tracing::init());
        tracing::error!("endpoint dropped by the runtime");
    });
    let err = named("late_second", || {
        habilis_network_test_tracing::catch_panic(AssertUnwindSafe(|| {
            drop(habilis_network_test_tracing::init());
        }))
        .expect_err("the guard must panic")
    });
    let text: &String = err.downcast_ref().expect("panic text");
    assert!(
        text.contains("logged after test late_first ended"),
        "{text}"
    );
    assert!(text.contains("endpoint dropped by the runtime"), "{text}");
}
