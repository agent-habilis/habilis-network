//! Task runner for the workspace. Run `cargo task <task>` from anywhere in it.
//!
//! Two jobs. The first is the quality gate: everything
//! `.github/workflows/ci.yml` runs — the clippy passes for features that are
//! off by default, the doc-link check, the wasm32 half — lives in
//! [`gate::STEPS`] as data, so a contributor can run the gate instead of
//! transcribing YAML, and can narrow it to one crate with `-p`.
//!
//! The second is `e2e`, which is a runner for a different reason: the WebRTC
//! crate's browser tests need a preamble that is four things long, and every one
//! of them fails in a way that does not name its cause. Homebrew clang or
//! `ring`'s C core silently does not link; `--release` or the wasm is too big to
//! load; a matching driver or session creation 404s; the browser's mDNS switch
//! or ICE never leaves `new`. A runner that gets all four right is the
//! difference between a suite anyone can run and one only its author can.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use xshell::Shell;

mod dev;
mod e2e;
mod ffi;
mod gate;
mod scope;
mod util;
mod wasm;

use scope::Scope;

/// Task result; any `Err` is printed and turns into a non-zero exit.
pub(crate) type TaskOutcome = Result<(), Box<dyn std::error::Error>>;

/// The workspace's quality gate and its browser test suite.
#[derive(Parser)]
#[command(bin_name = "cargo task", long_about = None)]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

// Variant doc comments *are* the `--help` text — no separate usage block to
// drift out of step with the code.
#[derive(Subcommand)]
enum Task {
    /// Run the whole gate: fmt, clippy, doc links, the check matrix, wasm, tests.
    Ci {
        #[command(flatten)]
        scope: Scope,
    },
    /// Format the source.
    Fmt {
        /// Report unformatted files instead of rewriting them, as CI does.
        #[arg(long)]
        check: bool,
        #[command(flatten)]
        scope: Scope,
    },
    /// Run clippy, including the passes for features that are off by default.
    Lint {
        #[command(flatten)]
        scope: Scope,
    },
    /// Type-check the feature matrix.
    Check {
        #[command(flatten)]
        scope: Scope,
    },
    /// Build the docs and fail on a broken intra-doc link.
    Doc {
        #[command(flatten)]
        scope: Scope,
    },
    /// Run the tests, including the suites behind non-default features.
    Test {
        #[command(flatten)]
        scope: Scope,
    },
    /// Check and lint the crates that reach `wasm32-unknown-unknown`.
    Wasm {
        #[command(flatten)]
        scope: Scope,
    },
    /// Build the C ABI staticlib and diff its exports against `fofoca.h`.
    Ffi,
    /// Build fofoca-wasm and emit its JS glue into packages/fofoca-wasm/wasm.
    BuildWasm,
    /// Drive the WebRTC browser tests against real browsers.
    ///
    /// The default `matrix` suite sweeps browser × build profile × main-thread
    /// pressure and prints one summary table; `--suite loopback` runs the fast
    /// four-test regression suite against a single browser instead.
    E2e(e2e::Args),
    /// Remove build artifacts.
    Clean,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let sh = match Shell::new() {
        Ok(sh) => sh,
        Err(error) => return fail(&error.to_string()),
    };
    // Every task runs from the workspace root, so `cargo task check -p x` means
    // the same thing from a crate directory as it does from the top — cargo
    // would otherwise resolve `--workspace` and the config the same way but
    // print paths relative to wherever you happened to stand.
    sh.change_dir(util::repo_root());

    match dispatch(&sh, cli.task) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&error.to_string()),
    }
}

fn dispatch(sh: &Shell, task: Task) -> TaskOutcome {
    match task {
        Task::Ci { scope } => scoped(sh, &scope, dev::ci),
        Task::Fmt { check, scope } => {
            scope.validate(sh)?;
            dev::fmt(sh, &scope, check)
        }
        Task::Lint { scope } => scoped(sh, &scope, dev::lint),
        Task::Check { scope } => scoped(sh, &scope, dev::check),
        Task::Doc { scope } => scoped(sh, &scope, dev::doc),
        Task::Test { scope } => scoped(sh, &scope, dev::test),
        Task::Wasm { scope } => scoped(sh, &scope, wasm::run),
        Task::Ffi => ffi::run(sh),
        Task::BuildWasm => wasm::build_peer(sh),
        Task::E2e(args) => e2e::run(&args),
        Task::Clean => dev::clean(sh),
    }
}

/// Reject an unknown `-p` name before the task builds anything.
fn scoped(sh: &Shell, scope: &Scope, task: fn(&Shell, &Scope) -> TaskOutcome) -> TaskOutcome {
    scope.validate(sh)?;
    task(sh, scope)
}

fn fail(message: &str) -> ExitCode {
    util::output::failure("error", message);
    ExitCode::FAILURE
}
