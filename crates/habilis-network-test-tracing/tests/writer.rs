//! `init_with_writer` sends the events to the writer of the test and still
//! fails the test on a WARN or ERROR event.

use habilis_network_test_tracing::catch_panic;
use std::io;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};

use habilis_network_test_tracing::init_with_writer;

mod support;
use support::without_rust_log;

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<String>>);

impl io::Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("no poison")
            .push_str(&String::from_utf8_lossy(bytes));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_writer_gets_the_events_and_the_guard_fails_on_an_error() {
    without_rust_log(
        "the_writer_gets_the_events_and_the_guard_fails_on_an_error",
        || {
            let sink = Sink::default();
            let seen = Arc::clone(&sink.0);
            let err = catch_panic(AssertUnwindSafe(|| {
                let _log = init_with_writer("writer=info", {
                    let sink = sink.clone();
                    move || sink.clone()
                });
                tracing::info!("round started");
                assert!(seen.lock().expect("no poison").contains("round started"));
                tracing::error!("round failed");
            }))
            .expect_err("the guard must panic");
            let text = err.downcast_ref::<String>().expect("panic text");
            assert!(
                text.contains("unexpected ERROR writer: round failed"),
                "{text}"
            );
        },
    );
}
