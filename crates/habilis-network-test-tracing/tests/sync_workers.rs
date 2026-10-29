//! An event of a thread that no test owns goes to every live test, and the failure
//! text names them all.

use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Barrier};
use std::thread;

fn named<T: Send + 'static>(
    name: &str,
    body: impl FnOnce() -> T + Send + 'static,
) -> thread::JoinHandle<T> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(body)
        .expect("spawn")
}

#[test]
fn an_event_of_a_worker_thread_names_every_live_sync_test() {
    // the barrier is shared by the three threads
    let live = Arc::new(Barrier::new(3));
    // the second barrier is shared by the three threads
    let emitted = Arc::new(Barrier::new(3));
    let tests: Vec<_> = ["sync_a", "sync_b"]
        .into_iter()
        .map(|name| {
            let (live, emitted) = (Arc::clone(&live), Arc::clone(&emitted));
            named(name, move || {
                habilis_network_test_tracing::catch_panic(AssertUnwindSafe(|| {
                    let _guard = habilis_network_test_tracing::init();
                    live.wait();
                    emitted.wait();
                }))
                .err()
                .and_then(|err| err.downcast_ref::<String>().cloned())
            })
        })
        .collect();
    live.wait();
    named("a_worker", || tracing::warn!("link lost"))
        .join()
        .expect("worker");
    emitted.wait();
    for test in tests {
        let text = test.join().expect("test").expect("the guard must panic");
        assert!(
            text.contains("from a worker thread, while these tests ran: sync_a, sync_b"),
            "{text}"
        );
    }
}
