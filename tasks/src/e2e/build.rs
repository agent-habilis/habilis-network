//! Prerequisite checks and the wasm build.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::TaskOutcome;
use crate::util::{output, repo_root};

use super::Profile;

/// Environment the wasm build needs, or an error naming what is missing.
///
/// `ring` compiles its C core for wasm32 and Apple clang has no wasm backend.
/// Without Homebrew's, the link silently leaves 44 `ring_core_*` symbols as
/// imports from a module called `env`, the browser refuses the module with
/// `Failed to resolve module specifier "env"`, and the test runner reports only
/// `Failed to detect test as having been run`. Four layers, none of which
/// mentions clang. The chat-webrtc example's `build-wasm.sh` says the same
/// thing for the same reason.
pub(crate) fn wasm_env() -> Result<BTreeMap<String, String>, String> {
    let clang = [
        "/opt/homebrew/opt/llvm/bin/clang",
        "/usr/local/opt/llvm/bin/clang",
    ]
    .into_iter()
    .map(Path::new)
    .find(|candidate| candidate.is_file());

    let Some(clang) = clang else {
        if cfg!(target_os = "macos") {
            return Err(concat!(
                "no Homebrew LLVM clang found, and Apple clang cannot emit wasm\n",
                "             brew install llvm\n",
                "             (without it `ring`'s C core does not link and the browser\n",
                "              refuses the module with 'Failed to resolve module specifier \"env\"')"
            )
            .to_owned());
        }
        // Every other platform ships a clang that can target wasm32.
        return Ok(BTreeMap::new());
    };

    let bin = clang.parent().expect("a clang path always has a directory");
    Ok(BTreeMap::from([
        (
            "CC_wasm32_unknown_unknown".to_owned(),
            clang.display().to_string(),
        ),
        (
            "AR_wasm32_unknown_unknown".to_owned(),
            bin.join("llvm-ar").display().to_string(),
        ),
    ]))
}

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
            "fofoca-iroh-webrtc-transport",
            "--features",
            "web",
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

/// The plain `wasm-bindgen` CLI, which the browser-peer build shells out to.
/// Distinct from [`check_tooling`]'s `wasm-bindgen-test-runner`: the sweeps
/// need the runner, the peer build needs the generator.
pub(crate) fn check_wasm_bindgen() -> TaskOutcome {
    if Command::new("wasm-bindgen")
        .arg("--version")
        .output()
        .is_err()
    {
        return Err(
            "wasm-bindgen is not on PATH\n             cargo install wasm-bindgen-cli".into(),
        );
    }
    Ok(())
}

/// Build the browser peer (`fofoca-wasm`) and emit its ES-module glue into
/// `packages/fofoca-wasm/wasm/`, returning the glue's path.
///
/// The `.wasm` path comes from cargo's own JSON for the same reason
/// [`build`]'s does — a stale artefact is indistinguishable by filename —
/// except a cdylib reports through `filenames`, not `executable`.
/// `--release` for the same reason too: the debug wasm is enormous and the
/// browser gives up loading it.
pub(crate) fn build_wasm_peer(env: &BTreeMap<String, String>) -> Result<PathBuf, String> {
    let built = Command::new("cargo")
        .current_dir(repo_root())
        .args([
            "build",
            "--release",
            "--quiet",
            "--target",
            "wasm32-unknown-unknown",
            "-p",
            "fofoca-wasm",
            "--message-format=json",
        ])
        .envs(env)
        .output()
        .map_err(|error| format!("could not run cargo: {error}"))?;

    let artifact = String::from_utf8_lossy(&built.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|message| {
            message.get("filenames").and_then(|filenames| {
                filenames.as_array()?.iter().find_map(|name| {
                    let path = PathBuf::from(name.as_str()?);
                    (path.file_name()? == "fofoca_wasm.wasm").then_some(path)
                })
            })
        })
        .next_back();
    let Some(artifact) = artifact.filter(|path| path.is_file()) else {
        return Err(format!(
            "could not build the fofoca-wasm cdylib:\n{}",
            String::from_utf8_lossy(&built.stderr).trim()
        ));
    };

    let out_dir = repo_root().join("packages/fofoca-wasm/wasm");
    let bound = Command::new("wasm-bindgen")
        .args(["--target", "web", "--out-dir"])
        .arg(&out_dir)
        .arg(&artifact)
        .output()
        .map_err(|error| format!("could not run wasm-bindgen: {error}"))?;
    if !bound.status.success() {
        return Err(format!(
            "wasm-bindgen failed:\n{}",
            String::from_utf8_lossy(&bound.stderr).trim()
        ));
    }
    Ok(out_dir.join("fofoca_wasm.js"))
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
    output::status("Building", "the browser peer (fofoca-wasm)");
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
