//! A test registers what it must close with `at_end`, and the runtime of
//! `run` and `run_multi_thread` awaits it before it drops.

use std::sync::atomic::{AtomicBool, Ordering};

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
fn what_a_test_registers_is_closed_before_the_runtime_drops() {
    ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
        let endpoint = std::rc::Rc::new(Endpoint);
        let closer = std::rc::Rc::clone(&endpoint);
        ::habilis_network_test_tracing::at_end(async move { closer.close().await });
        tokio::spawn(async { tokio::task::yield_now().await });
        drop(endpoint);
    });
}

#[test]
fn a_cleanup_runs_even_when_the_registrations_are_many() {
    ::habilis_network_test_tracing::run_multi_thread(
        ::habilis_network_test_tracing::init(),
        2,
        async {
            for _ in 0..5 {
                ::habilis_network_test_tracing::at_end(async { tokio::task::yield_now().await });
            }
        },
    );
}
