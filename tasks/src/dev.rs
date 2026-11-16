//! The gate a contributor runs before pushing: `fmt`, `lint`, `check`, `doc`,
//! `test`, and `ci`, which is all of them in the order CI runs them.
//!
//! Each task is a filter over [`crate::gate::STEPS`] rather than a list of its
//! own, so what a task runs and what CI runs are the same statement.

use xshell::{Shell, cmd};

use crate::TaskOutcome;
use crate::gate::{self, Kind};
use crate::scope::Scope;
use crate::util::output;

use crate::wasm;
pub(crate) fn fmt(sh: &Shell, scope: &Scope, check: bool) -> TaskOutcome {
    // No `--workspace`: `cargo fmt` already covers every member of a virtual
    // workspace, and does not accept the flag.
    let packages = scope.package_flags();
    let check: &[&str] = if check { &["--check"] } else { &[] };
    output::status("Formatting", &subject(scope, check));
    cmd!(sh, "cargo fmt {packages...} {check...}")
        .quiet()
        .run()?;
    Ok(())
}

pub(crate) fn lint(sh: &Shell, scope: &Scope) -> TaskOutcome {
    run(sh, Kind::Lint, scope)
}

pub(crate) fn check(sh: &Shell, scope: &Scope) -> TaskOutcome {
    run(sh, Kind::Check, scope)
}

pub(crate) fn test(sh: &Shell, scope: &Scope) -> TaskOutcome {
    run(sh, Kind::Test, scope)
}

/// A doc link that does not resolve is the same drift as a stale comment, and
/// nothing else in the gate would catch it: 25 had accumulated when this was
/// first turned on, including a method renamed out from under its own docs.
pub(crate) fn doc(sh: &Shell, scope: &Scope) -> TaskOutcome {
    let packages = scope.flags();
    let args: &[&str] = &["--no-deps", "--all-features"];
    output::status("Documenting", &subject(scope, args));
    // Scoped to this `Shell`, so it cannot leak into a later step. `RUSTFLAGS`
    // could not be set this way — see `wasm::run`.
    let _restore = sh.push_env("RUSTDOCFLAGS", "-D rustdoc::broken_intra_doc_links");
    cmd!(sh, "cargo doc {packages...} {args...}")
        .quiet()
        .run()?;
    Ok(())
}

pub(crate) fn clean(sh: &Shell) -> TaskOutcome {
    output::status("Cleaning", "build artifacts");
    cmd!(sh, "cargo clean").quiet().run()?;
    Ok(())
}

/// The whole gate, in `.github/workflows/ci.yml`'s order. `?` short-circuits,
/// so the first failure is the last thing printed.
pub(crate) fn ci(sh: &Shell, scope: &Scope) -> TaskOutcome {
    fmt(sh, scope, true)?;
    lint(sh, scope)?;
    doc(sh, scope)?;
    check(sh, scope)?;
    wasm::run(sh, scope)?;
    test(sh, scope)?;
    output::status("Finished", "the gate is green");
    Ok(())
}

/// Run every table row of `kind` that survives the scope filter.
pub(crate) fn run(sh: &Shell, kind: Kind, scope: &Scope) -> TaskOutcome {
    let packages = scope.packages();
    let steps = gate::select(kind, packages);
    if steps.is_empty() {
        // Never silent: a scoped run that had nothing to do and said nothing is
        // indistinguishable from one that passed.
        output::caution(
            "Skipping",
            &format!("{} — no step for {}", kind.label(), packages.join(", ")),
        );
        return Ok(());
    }
    for step in steps {
        let (verb, subject) = step.describe(packages);
        output::status(verb, &subject);
        let argv = step.command(packages);
        cmd!(sh, "cargo {argv...}").quiet().run()?;
    }
    Ok(())
}

fn subject(scope: &Scope, args: &[&str]) -> String {
    let named = scope.packages().join(", ");
    let target = if named.is_empty() {
        "the workspace"
    } else {
        &named
    };
    if args.is_empty() {
        target.to_owned()
    } else {
        format!("{target} {}", args.join(" "))
    }
}
