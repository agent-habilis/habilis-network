//! An event that arrives after the guard of a test dropped, for example from a
//! runtime that drops its endpoints after the test body, fails the next test
//! and names the test that ended.

use habilis_network_test_tracing::catch_panic;
use std::panic::AssertUnwindSafe;
use std::thread;

use habilis_network_test_tracing::init;

fn named<T: Send + 'static>(name: &str, body: impl FnOnce() -> T + Send + 'static) -> T {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(body)
        .expect("spawn")
        .join()
        .expect("join")
}

#[test]
fn an_event_after_the_guard_dropped_fails_the_next_test() {
    named("late_first", || {
        drop(init());
        tracing::error!("endpoint dropped by the runtime");
    });
    let err = named("late_second", || {
        catch_panic(AssertUnwindSafe(|| drop(init()))).expect_err("the guard must panic")
    });
    let text = err.downcast_ref::<String>().expect("panic text");
    assert!(
        text.contains("logged after test late_first ended"),
        "{text}"
    );
    assert!(text.contains("endpoint dropped by the runtime"), "{text}");
}
