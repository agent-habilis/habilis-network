//! Building a wasm-bindgen crate for the browser, shared by the e2e suites
//! and the benchmark.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::repo_root;
use crate::TaskOutcome;

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

/// The plain `wasm-bindgen` CLI, which the browser-peer build shells out to.
/// Distinct from the e2e `check_tooling`'s `wasm-bindgen-test-runner`: the sweeps
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

/// Build one wasm-bindgen cdylib `package` for the browser and emit its
/// ES-module glue into `out_dir`, returning the glue's path.
///
/// The `.wasm` path comes from cargo's own JSON for the same reason
/// the e2e `build`'s does — a stale artefact is indistinguishable by filename —
/// except a cdylib reports through `filenames`, not `executable`.
/// `--release` for the same reason too: the debug wasm is enormous and the
/// browser gives up loading it.
pub(crate) fn build_wasm_cdylib(
    package: &str,
    env: &BTreeMap<String, String>,
    out_dir: &Path,
) -> Result<PathBuf, String> {
    let stem = package.replace('-', "_");
    let wasm_name = format!("{stem}.wasm");
    let built = Command::new("cargo")
        .current_dir(repo_root())
        .args([
            "build",
            "--release",
            "--quiet",
            "--target",
            "wasm32-unknown-unknown",
            "-p",
            package,
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
                    (path.file_name()? == wasm_name.as_str()).then_some(path)
                })
            })
        })
        .next_back();
    let Some(artifact) = artifact.filter(|path| path.is_file()) else {
        return Err(format!(
            "could not build the {package} cdylib:\n{}",
            String::from_utf8_lossy(&built.stderr).trim()
        ));
    };

    let bound = Command::new("wasm-bindgen")
        .args(["--target", "web", "--out-dir"])
        .arg(out_dir)
        .arg(&artifact)
        .output()
        .map_err(|error| format!("could not run wasm-bindgen: {error}"))?;
    if !bound.status.success() {
        return Err(format!(
            "wasm-bindgen failed:\n{}",
            String::from_utf8_lossy(&bound.stderr).trim()
        ));
    }
    Ok(out_dir.join(format!("{stem}.js")))
}
