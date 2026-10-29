//! A tracing subscriber for tests that fails the test when a WARN or ERROR
//! event is logged.
//!
//! Start each test with `let _log = habilis_network_test_tracing::init();`.
//! The guard must be the first local of the test, so that it drops last and
//! sees the events of every value that the test drops before it.
//!
//! Tests run side by side. An event belongs to the test whose thread logs it,
//! or whose runtime logs it: the worker threads of a runtime that [`run`] or
//! [`run_multi_thread`] build carry the name of their test. They replace
//! `#[tokio::test]`, and they drop the runtime before the guard, so the events
//! of the endpoints that the runtime drops belong to the test too. An event of
//! a thread that no test owns is filed under every live test, and the failure
//! text names them all.
//!
//! An event of the worker of a test that ended, or an event that comes while no
//! test is live, is kept and fails the next guard with the name of the test that
//! ended. A binary that logs such an event after its last guard has nobody to
//! fail, so it exits with 101.
//!
//! A panic inside the subscriber does not fail a test when a spawned task logs
//! the event, so the subscriber records the event and [`Guard`] panics on the
//! test thread when it drops.
//!
//! # Example
//!
//! ```
//! let _log = habilis_network_test_tracing::init();
//! tracing::info!("an INFO event does not fail the test");
//! ```

mod guard;

pub use guard::{
    Guard, allow_warn, captured_logs, catch_panic, clear_captured_logs, expect_warn, init,
    init_capturing, init_with_writer, saw_warn,
};
#[cfg(not(target_arch = "wasm32"))]
pub use guard::{at_end, run, run_multi_thread};
