//! Shared helpers for the tasks in this runner.

pub(crate) mod cdp;
pub(crate) mod output;
#[cfg(any(feature = "mesh", feature = "bench"))]
pub(crate) mod page;
pub(crate) mod wasm;
pub(crate) mod webdriver;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The workspace root — `tasks/..`, resolved from the manifest directory
/// rather than the current one, so `cargo task` behaves the same wherever it is
/// invoked from inside the workspace.
pub(crate) fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the tasks crate always sits directly under the workspace root")
        .to_path_buf()
}

/// Poll `probe` until it yields a value, or give up.
///
/// Used for everything that comes up asynchronously — the harness server's
/// socket, a driver's `/status`, the page's `#matrix-done` — so each of them
/// gets a bounded wait instead of an unbounded one.
pub(crate) fn wait_for<T>(
    timeout: Duration,
    interval: Duration,
    mut probe: impl FnMut() -> Option<T>,
) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = probe() {
            return Some(value);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(interval);
    }
}

/// Re-run this same invocation through cargo with `feature` on.
///
/// The suites behind a feature are not compiled into a default build of the
/// runner, so a bare `cargo task <task>` reaches them by building itself once
/// more with the feature; only that path pays for the feature's dependency
/// closure. `release` because a benchmark run in the dev profile measures the
/// dev profile: an unoptimised QUIC stack on loopback is a fraction of itself.
#[cfg(not(all(feature = "mesh", feature = "bench")))]
pub(crate) fn reexec_with_feature(feature: &str, what: &str, release: bool) -> crate::TaskOutcome {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    output::status(
        "Rerunning",
        &format!("with `--features {feature}` ({what})"),
    );
    let mut command = std::process::Command::new(cargo);
    command.current_dir(repo_root()).args(["run", "--quiet"]);
    if release {
        command.arg("--release");
    }
    let status = command
        .args(["--package", "tasks", "--features", feature, "--"])
        .args(std::env::args_os().skip(1))
        .status()
        .map_err(|error| format!("could not re-run cargo: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what} failed: {status}").into())
    }
}

/// A cell that could not run at all, with a reason a reader can act on.
pub(crate) struct Skip(pub(crate) String);

/// `Runtime.evaluate` and `execute/sync` both hand back a JSON value; a string
/// result should read as its contents, not as a quoted literal.
pub(crate) fn json_to_string(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

/// Is something listening and answering here?
///
/// Any reply counts, including an error status: the question is whether the
/// socket is live, not whether this particular path exists.
pub(crate) fn reachable(url: &str) -> bool {
    ureq::get(url)
        .config()
        .timeout_global(Some(Duration::from_secs(1)))
        .build()
        .call()
        .is_ok()
}
