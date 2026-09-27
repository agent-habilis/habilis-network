//! `cargo task wasm` — the `wasm32-unknown-unknown` half of the gate.

use xshell::{Shell, cmd};

use crate::TaskOutcome;
use crate::dev;
use crate::gate::Kind;
use crate::scope::Scope;
use crate::util::output;

const TARGET: &str = "wasm32-unknown-unknown";

/// `cargo task build-wasm` — build fofoca-wasm and emit its JS glue.
///
/// The one wasm build that ships to a page rather than to a test harness:
/// `packages/fofoca-wasm` (and the mesh e2e suite's harness) load the glue
/// this drops under `packages/fofoca-wasm/wasm/`.
pub(crate) fn build_peer(sh: &Shell) -> TaskOutcome {
    ensure_target(sh)?;
    crate::e2e::build::build_browser_peer()?;
    output::status("Built", "fofoca-wasm");
    Ok(())
}

pub(crate) fn run(sh: &Shell, scope: &Scope) -> TaskOutcome {
    ensure_target(sh)?;
    dev::run(sh, Kind::WasmCheck, scope)?;
    dev::run(sh, Kind::WasmClippy, scope)?;
    Ok(())
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
