//! `cargo task wasm` — the `wasm32-unknown-unknown` half of the gate.

use xshell::{Shell, cmd};

use crate::TaskOutcome;
use crate::dev;
use crate::gate::Kind;
use crate::scope::Scope;
use crate::util::output;

const TARGET: &str = "wasm32-unknown-unknown";

/// `cargo task build-wasm` — build habilis-network-wasm and emit its JS glue.
///
/// The one wasm build that ships to a page rather than to a test harness:
/// `packages/habilis-network-wasm` (and the mesh e2e suite's harness) load the glue
/// this drops under `packages/habilis-network-wasm/wasm/`.
pub(crate) fn build_peer(sh: &Shell) -> TaskOutcome {
    ensure_target(sh)?;
    crate::e2e::build::build_browser_peer()?;
    output::status("Built", "habilis-network-wasm");
    Ok(())
}

pub(crate) fn run(sh: &Shell, scope: &Scope) -> TaskOutcome {
    ensure_target(sh)?;
    dev::run(sh, Kind::WasmCheck, scope)?;
    dev::run(sh, Kind::WasmClippy, scope)?;
    check_disallowed_list(sh)
}

/// A path in `clippy.toml` that names no function is only a warning, which `-D warnings` leaves
/// alone, so a typo would switch one entry of the list off and fail nothing. Clippy says it once
/// for each crate that depends on the crate in the path, so one crate that depends on Tokio is
/// enough. The crate is cleaned first: clippy prints the warning only when it lints the crate, and
/// a crate that an earlier row left fresh would not print it.
fn check_disallowed_list(sh: &Shell) -> TaskOutcome {
    const UNREACHABLE: &str = "does not refer to a reachable function";
    output::status("Checking", "the disallowed methods of clippy.toml");
    cmd!(
        sh,
        "cargo clean -p habilis-network-iroh-gossip-transport --target {TARGET}"
    )
    .quiet()
    .run()?;
    let out = cmd!(
        sh,
        "cargo clippy --target {TARGET} -p habilis-network-iroh-gossip-transport -- -D warnings -D clippy::disallowed_methods"
    )
    .quiet()
    .ignore_status()
    .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let dead: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains(UNREACHABLE))
        .collect();
    if dead.is_empty() {
        return Ok(());
    }
    for line in dead {
        output::detail(line);
    }
    Err("clippy.toml lists a path that names no function".into())
}

/// Fail on the missing target rather than on the wall of resolver errors it
/// causes.
///
/// CI installs it through `actions-rust-lang/setup-rust-toolchain`, and
/// `rust-toolchain.toml` pins `profile = "minimal"`, so a fresh checkout has
/// every other thing the gate needs and not this one.
///
/// Nothing here sets `RUSTFLAGS`: the wasm builds need
/// `--cfg getrandom_backend="wasm_js"`, the root `.cargo/config.toml` supplies
/// it, and the environment variable does not merge with that value — it
/// replaces it.
fn ensure_target(sh: &Shell) -> TaskOutcome {
    let installed = cmd!(sh, "rustup target list --installed")
        .quiet()
        .ignore_stderr()
        .read()
        // No rustup is not the same as no target: a distro toolchain has no
        // rustup to ask, and its wasm support is whatever it is. Let the build
        // be the judge.
        .unwrap_or_else(|_| TARGET.to_owned());

    if installed.lines().any(|line| line.trim() == TARGET) {
        return Ok(());
    }
    output::detail(&format!("rustup target add {TARGET}"));
    Err(format!("the {TARGET} target is not installed").into())
}
