//! A second live guard on one thread would count every event twice, so it panics
//! and says why.

use habilis_network_test_tracing::catch_panic;
use std::panic::AssertUnwindSafe;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use habilis_network_test_tracing::init;

#[test]
fn a_second_live_guard_on_one_thread_panics() {
    let (done, wait) = mpsc::channel();
    thread::Builder::new()
        .name("twice_probe".to_owned())
        .spawn(move || {
            let outcome = catch_panic(AssertUnwindSafe(|| {
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
        .expect("the second init never returns")
        .expect("the second init must panic");
    assert!(text.contains("init() twice in one test"), "{text}");
}
