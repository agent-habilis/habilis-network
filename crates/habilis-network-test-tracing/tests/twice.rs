//! A second live guard on one thread would wait for the lock of the first for
//! ever, so it panics and says why.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use habilis_network_test_tracing::init;

#[test]
fn a_second_live_guard_on_one_thread_panics_instead_of_waiting() {
    let (done, wait) = mpsc::channel();
    thread::Builder::new()
        .name("twice_probe".to_owned())
        .spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let _first = init();
                let _second = init();
            }));
            let _ = done.send(
                outcome
                    .err()
                    .and_then(|err| err.downcast_ref::<String>().cloned()),
            );
        })
        .expect("spawn");
    let text = wait
        .recv_timeout(Duration::from_secs(5))
        .expect("the second init waits for ever")
        .expect("the second init must panic");
    assert!(text.contains("init() twice in one test"), "{text}");
}
