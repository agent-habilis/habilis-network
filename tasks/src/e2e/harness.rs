//! The wasm-bindgen harness server.
//!
//! `wasm-bindgen-test-runner` has two modes. Its default drives a browser
//! itself over `WebDriver`, which means finding a driver that matches the browser
//! — and for Chrome that meant downloading a chromedriver pinned to a Chrome
//! build. Its `NO_HEADLESS=1` mode instead just *serves* the harness and leaves
//! the browsing to whoever asks.
//!
//! That is the mode used here. The page runs its tests on load and publishes
//! `#matrix-done` once every cell has a row, so any way of driving a browser to
//! a URL and reading an element is enough — which is what lets the two backends
//! next door be as different as CDP and `WebDriver` and still answer the same
//! question.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::util::{reachable, wait_for};

/// The port is the runner's choice, not ours, which is why cells run one at a
/// time rather than in parallel.
pub(super) const URL: &str = "http://127.0.0.1:8000";

/// A running harness server, killed when it goes out of scope.
///
/// The guard is the point: a cell that fails partway — a driver that will not
/// start, a page that never publishes — must not leave a server holding :8000,
/// because the next cell would then silently test the *previous* cell's wasm.
#[derive(Debug)]
pub(super) struct Harness(Child);

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Harness {
    /// Serve `wasm`, and wait until the socket answers.
    pub(super) fn serve(wasm: &Path) -> Result<Self, String> {
        let child = Command::new("wasm-bindgen-test-runner")
            .arg(wasm)
            .env("NO_HEADLESS", "1")
            .env("WASM_BINDGEN_TEST_TIMEOUT", "1800")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("could not start wasm-bindgen-test-runner: {error}"))?;
        let harness = Self(child);

        let up = wait_for(Duration::from_secs(30), Duration::from_millis(500), || {
            reachable(URL).then_some(())
        });
        if up.is_none() {
            return Err("the harness server never came up".to_owned());
        }
        Ok(harness)
    }
}
