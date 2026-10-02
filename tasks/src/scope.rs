//! `-p <crate>` — narrow a task to part of the workspace.
//!
//! One flag, shared by every task that has more than one crate to run against,
//! so `cargo task lint -p habilis-network-chunks` and `cargo task ci -p habilis-network-chunks`
//! mean the same thing by construction.

use clap::Args;
use xshell::{Shell, cmd};

use crate::util::output;

#[derive(Args, Clone, Default)]
pub(crate) struct Scope {
    /// Only this crate. Repeatable; omit for the whole workspace.
    ///
    /// The task keeps the steps that concern the named crates and drops the
    /// rest, so `-p habilis-network` still runs the `blob` feature pass and
    /// `-p habilis-network-util` runs neither that nor any wasm pass.
    #[arg(short = 'p', long = "package", value_name = "CRATE")]
    packages: Vec<String>,
}

impl Scope {
    pub(crate) fn packages(&self) -> &[String] {
        &self.packages
    }

    /// Package selection for a command that understands `--workspace`.
    pub(crate) fn flags(&self) -> Vec<String> {
        if self.packages.is_empty() {
            return vec!["--workspace".to_owned()];
        }
        self.package_flags()
    }

    /// Package selection for a command that does not — `cargo fmt`.
    pub(crate) fn package_flags(&self) -> Vec<String> {
        self.packages
            .iter()
            .flat_map(|name| ["-p".to_owned(), name.clone()])
            .collect()
    }

    /// Reject an unknown crate before any step runs.
    ///
    /// Cargo would reject it too, but only once per step and only after the
    /// steps before it had already built. One typo should cost one error, and
    /// the error should say what the valid names are.
    pub(crate) fn validate(&self, sh: &Shell) -> Result<(), Box<dyn std::error::Error>> {
        if self.packages.is_empty() {
            return Ok(());
        }
        let members = members(sh)?;
        let unknown: Vec<&str> = self
            .packages
            .iter()
            .map(String::as_str)
            .filter(|name| !members.iter().any(|member| member == name))
            .collect();
        if unknown.is_empty() {
            return Ok(());
        }
        output::detail(&format!("workspace crates: {}", members.join(", ")));
        Err(format!("no such crate in this workspace: {}", unknown.join(", ")).into())
    }
}

/// The workspace member names, from cargo rather than a list here that would
/// drift the first time a crate is added.
fn members(sh: &Shell) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct Metadata {
        packages: Vec<Package>,
    }
    #[derive(serde::Deserialize)]
    struct Package {
        name: String,
    }

    let json = cmd!(sh, "cargo metadata --no-deps --format-version 1")
        .quiet()
        .ignore_stderr()
        .read()?;
    let metadata: Metadata = serde_json::from_str(&json)?;
    let mut names: Vec<String> = metadata.packages.into_iter().map(|pkg| pkg.name).collect();
    names.sort();
    Ok(names)
}
