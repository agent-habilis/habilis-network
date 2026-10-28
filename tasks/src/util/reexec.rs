#[cfg(not(all(feature = "mesh", feature = "bench")))]
use super::output;
#[cfg(not(all(feature = "mesh", feature = "bench")))]
use super::paths::repo_root;

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
