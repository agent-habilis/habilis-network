//! A sync test holds no lock, so it starts while another guard holds the lock.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use habilis_network_test_tracing::{__sync_guard, init};

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
fn a_sync_guard_does_not_wait_for_a_guard_that_holds_the_lock() {
    let (held, wait_held) = mpsc::channel();
    let (release, wait_release) = mpsc::channel::<()>();
    let holder = named("sync_holder", move || {
        let _serial = init();
        held.send(()).expect("held");
        wait_release.recv().expect("release");
    });
    wait_held.recv().expect("the holder holds the lock");
    let (done, finished) = mpsc::channel();
    named("sync_free", move || {
        drop(__sync_guard());
        done.send(()).expect("done");
    });
    finished
        .recv_timeout(Duration::from_secs(5))
        .expect("the sync guard waits for the lock");
    release.send(()).expect("release");
    holder.join().expect("holder");
}
