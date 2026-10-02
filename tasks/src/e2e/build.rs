//! Prerequisite checks and the wasm build.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::TaskOutcome;
use crate::util::wasm::{build_wasm_cdylib, check_wasm_bindgen, wasm_env};
use crate::util::{output, repo_root};

use super::Profile;

/// The tools the sweep shells out to.
pub(super) fn check_tooling() -> TaskOutcome {
    if Command::new("wasm-bindgen-test-runner")
        .arg("--version")
        .output()
        .is_err()
    {
        return Err(
            "wasm-bindgen-test-runner is not on PATH\n             cargo install wasm-bindgen-cli"
                .into(),
        );
    }
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .map_err(|error| format!("could not ask rustup for installed targets: {error}"))?;
    if !String::from_utf8_lossy(&installed.stdout)
        .lines()
        .any(|line| line.trim() == "wasm32-unknown-unknown")
    {
        return Err(
            "the wasm32-unknown-unknown target is not installed\n             rustup target add wasm32-unknown-unknown"
                .into(),
        );
    }
    Ok(())
}

/// Build one test target and hand back the `.wasm` cargo actually produced.
///
/// The path comes from cargo's own JSON rather than a glob of `deps/`: a stale
/// artefact from an earlier build is indistinguishable from a fresh one by
/// filename, and running the wrong binary is the kind of mistake that costs a
/// whole investigation rather than a run.
///
/// `--release` is not a flag anyone can turn off. The debug build of these
/// tests is ~137 MB of wasm and the browser gives up loading it, with the same
/// unhelpful message as every other failure on this path.
pub(super) fn build(
    test: &str,
    profile: Profile,
    env: &BTreeMap<String, String>,
) -> Result<PathBuf, String> {
    let mut command = Command::new("cargo");
    command
        .current_dir(repo_root())
        .args([
            "test",
            "--release",
            "--no-run",
            "--quiet",
            "--target",
            "wasm32-unknown-unknown",
            "-p",
            "habilis-network-iroh-webrtc-transport",
            "--features",
            "web,bench",
            "--test",
            test,
            "--message-format=json",
        ])
        .envs(env);

    if profile == Profile::ReleaseSlow {
        // Models the consumer's development build: a slower wasm holds the
        // shared JS task queue for longer, which is the outbound pump's
        // starvation hypothesis by another route. Not the actual debug build —
        // that one will not load, which is a harness limit and not a finding.
        command.env("CARGO_PROFILE_RELEASE_OPT_LEVEL", "1");
    }

    let built = command
        .output()
        .map_err(|error| format!("could not run cargo: {error}"))?;

    // Last wins: cargo emits one `compiler-artifact` per crate in the graph and
    // the test target is the last to link.
    let artifact = String::from_utf8_lossy(&built.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|message| {
            message
                .get("executable")
                .and_then(serde_json::Value::as_str)
                .map(PathBuf::from)
        })
        .next_back();

    match artifact {
        Some(path) if path.is_file() => Ok(path),
        _ => Err(format!(
            "could not build the {test} wasm for profile '{profile}':\n{}",
            String::from_utf8_lossy(&built.stderr).trim()
        )),
    }
}

/// Build the browser peer (`habilis-network-wasm`) and emit its ES-module glue into
/// `packages/habilis-network-wasm/wasm/`, returning the glue's path.
pub(crate) fn build_wasm_peer(env: &BTreeMap<String, String>) -> Result<PathBuf, String> {
    build_wasm_cdylib(
        "habilis-network-wasm",
        env,
        &repo_root().join("packages/habilis-network-wasm/wasm"),
    )
}

/// Bun serves both e2e suites' pages; probe for it before anything builds.
#[cfg(feature = "mesh")]
pub(crate) fn ensure_bun(why: &str) -> TaskOutcome {
    if Command::new("bun")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| child.wait())
        .is_err()
    {
        return Err(format!("{why} — install bun first").into());
    }
    Ok(())
}

/// The whole browser-peer preamble the two e2e suites and `cargo task
/// build-wasm` share: tooling check, wasm env, build, announce.
pub(crate) fn build_browser_peer() -> Result<PathBuf, String> {
    check_wasm_bindgen().map_err(|error| error.to_string())?;
    let env = wasm_env()?;
    output::status("Building", "the browser peer (habilis-network-wasm)");
    let glue = build_wasm_peer(&env)?;
    output::detail(&format!("             {}", glue.display()));
    Ok(glue)
}

/// Build one binary target and take its path from cargo's own JSON, for the
/// same stale-artifact reason [`build`] does.
#[cfg(feature = "mesh")]
pub(crate) fn build_binary(package: &str, bin: &str) -> Result<PathBuf, String> {
    build_target(package, "--bin", bin)
}

#[cfg(feature = "mesh")]
fn build_target(package: &str, kind: &str, name: &str) -> Result<PathBuf, String> {
    let built = Command::new("cargo")
        .current_dir(repo_root())
        .args([
            "build",
            "--quiet",
            "-p",
            package,
            kind,
            name,
            "--message-format=json",
        ])
        .output()
        .map_err(|error| format!("could not run cargo: {error}"))?;
    let artifact = String::from_utf8_lossy(&built.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|message| {
            message
                .get("executable")
                .and_then(serde_json::Value::as_str)
                .map(PathBuf::from)
        })
        .next_back();
    artifact.filter(|path| path.is_file()).ok_or_else(|| {
        format!(
            "could not build {name} ({kind}):
{}",
            String::from_utf8_lossy(&built.stderr).trim()
        )
    })
}

/// Print the artifact that a cell is about to run, so a run that used a stale
/// or unexpected build says so in its own log.
pub(super) fn announce(profile: Profile, artifact: &Path) {
    output::status("Building", &format!("{profile} wasm"));
    output::detail(&format!("             {}", artifact.display()));
}
