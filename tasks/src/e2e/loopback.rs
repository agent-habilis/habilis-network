//! The fast suite, driven by `wasm-bindgen-test-runner` itself.
//!
//! Deliberately *not* the matrix's serve-and-drive path. That one keys on the
//! `#matrix-done` element `browser_matrix.rs` publishes once every cell has a
//! row — a single end-of-sweep signal. `browser_loopback.rs` is four
//! independent `#[wasm_bindgen_test]` functions with no such moment, so
//! pointing the matrix driver at it waits out the whole cell timeout for a
//! marker that never appears. (It did, once, for the full 15 minutes.)
//!
//! So this hands the driving back to the runner, whose default mode already
//! knows how to collect four test results, and supplies only the preamble that
//! is easy to get wrong: the clang that makes `ring` link, `--release`, a
//! driver, and Chrome's mDNS switch.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::Command;

use crate::TaskOutcome;
use crate::util::{output, repo_root};

/// Capabilities for the browser the runner will drive.
///
/// The `binary` pins Chrome for Testing so the chromedriver in `$CHROMEDRIVER`
/// has something version-matched to talk to; the mDNS switch is the same one
/// every other cell needs, for the same reason (a headless browser cannot
/// resolve the `.local` candidate it would otherwise be given, and ICE never
/// leaves `new`).
fn webdriver_json(binary: &str) -> String {
    serde_json::json!({
        "goog:chromeOptions": {
            "binary": binary,
            "args": ["--disable-features=WebRtcHideLocalIpsWithMdns"],
        }
    })
    .to_string()
}

pub(super) fn run(binary: &str, env: &BTreeMap<String, String>) -> TaskOutcome {
    let chromedriver = std::env::var("CHROMEDRIVER").map_err(|_| {
        "the fast suite needs a chromedriver matching its Chrome — set $CHROMEDRIVER\n             \
         (the matrix suite drives Chrome over CDP and needs none; this one hands\n             \
          the driving to wasm-bindgen-test-runner, which speaks WebDriver)"
    })?;

    let caps = repo_root().join("target").join("webdriver.json");
    if let Some(parent) = caps.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    let mut file = std::fs::File::create(&caps)
        .map_err(|error| format!("could not write {}: {error}", caps.display()))?;
    file.write_all(webdriver_json(binary).as_bytes())
        .map_err(|error| format!("could not write {}: {error}", caps.display()))?;

    output::status("Running", "browser_loopback (fast suite)");

    let status = Command::new("cargo")
        .current_dir(repo_root())
        .args([
            "test",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "-p",
            "fofoca-iroh-webrtc-transport",
            "--features",
            "web,bench",
            "--test",
            "browser_loopback",
        ])
        .envs(env)
        .env(
            "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER",
            "wasm-bindgen-test-runner",
        )
        .env("CHROMEDRIVER", chromedriver)
        .env("WASM_BINDGEN_TEST_WEBDRIVER_JSON", &caps)
        .env("WASM_BINDGEN_TEST_TIMEOUT", "300")
        .status()
        .map_err(|error| format!("could not run cargo test: {error}"))?;

    if status.success() {
        output::status("Passed", "browser_loopback");
        return Ok(());
    }
    Err("browser_loopback failed".into())
}
