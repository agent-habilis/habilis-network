use std::path::PathBuf;

use xshell::{Shell, cmd};

use super::paths::repo_root;

/// What `cargo metadata --no-deps` says about the workspace.
///
/// Cargo is the one authority on where a build lands: `CARGO_TARGET_DIR` and
/// `build.target-dir` both move it, so a path spelled `target/…` would not follow.
#[derive(serde::Deserialize)]
pub(crate) struct Metadata {
    pub(crate) packages: Vec<Package>,
    pub(crate) target_directory: PathBuf,
}

#[derive(serde::Deserialize)]
pub(crate) struct Package {
    pub(crate) name: String,
}

pub(crate) fn metadata(sh: &Shell) -> Result<Metadata, Box<dyn std::error::Error>> {
    let json = cmd!(sh, "cargo metadata --no-deps --format-version 1")
        .quiet()
        .ignore_stderr()
        .read()?;
    Ok(serde_json::from_str(&json)?)
}

/// Where cargo puts build output, and so where a task leaves the log of a failed run.
pub(crate) fn target_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let sh = Shell::new()?;
    sh.change_dir(repo_root());
    Ok(metadata(&sh)?.target_directory)
}
