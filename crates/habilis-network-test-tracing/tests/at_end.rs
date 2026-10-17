//! A test registers what it must close with `at_end`, and the runtime of
//! `run` and `run_multi_thread` awaits it before it drops.

use std::sync::atomic::{AtomicBool, Ordering};

use habilis_network_test_tracing::{at_end, test};

static CLOSED: AtomicBool = AtomicBool::new(false);

struct Endpoint;

impl Endpoint {
    async fn close(&self) {
        tokio::task::yield_now().await;
        CLOSED.store(true, Ordering::SeqCst);
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if !CLOSED.load(Ordering::SeqCst) {
            tracing::error!("endpoint dropped without close");
        }
    }
}

#[test]
async fn what_a_test_registers_is_closed_before_the_runtime_drops() {
    let endpoint = std::rc::Rc::new(Endpoint);
    let closer = std::rc::Rc::clone(&endpoint);
    at_end(async move { closer.close().await });
    tokio::spawn(async { tokio::task::yield_now().await });
    drop(endpoint);
}

#[test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cleanup_runs_even_when_the_registrations_are_many() {
    for _ in 0..5 {
        at_end(async { tokio::task::yield_now().await });
    }
}
