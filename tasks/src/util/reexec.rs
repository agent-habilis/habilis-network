#[cfg(not(all(feature = "mesh", feature = "bench")))]
use super::output;
#[cfg(not(all(feature = "mesh", feature = "bench")))]
use super::paths::repo_root;

#[cfg(not(all(feature = "mesh", feature = "bench")))]
use std::env;
#[cfg(all(windows, not(all(feature = "mesh", feature = "bench"))))]
use std::fs;
#[cfg(not(all(feature = "mesh", feature = "bench")))]
use std::process;
/// Re-run this same invocation through cargo with `feature` on.
///
/// The suites behind a feature are not compiled into a default build of the
/// runner, so a bare `cargo task <task>` reaches them by building itself once
/// more with the feature; only that path pays for the feature's dependency
/// closure. `release` because a benchmark run in the dev profile measures the
/// dev profile: an unoptimised QUIC stack on loopback is a fraction of itself.
#[cfg(not(all(feature = "mesh", feature = "bench")))]
pub(crate) fn reexec_with_feature(feature: &str, what: &str, release: bool) -> crate::TaskOutcome {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    output::status(
        "Rerunning",
        &format!("with `--features {feature}` ({what})"),
    );
    #[cfg(windows)]
    move_running_image_aside()?;
    let mut command = process::Command::new(cargo);
    command.current_dir(repo_root()).args(["run", "--quiet"]);
    if release {
        command.arg("--release");
    }
    let status = command
        .args(["--package", "tasks", "--features", feature, "--"])
        .args(env::args_os().skip(1))
        .status()
        .map_err(|error| format!("could not re-run cargo: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what} failed: {status}").into())
    }
}

/// Move the executable of this runner out of the path where cargo puts the
/// rebuilt runner.
///
/// Cargo removes `target\debug\tasks.exe` before it links the new one there.
/// This runner is still running while cargo builds, and Windows does not
/// remove the file of a running executable ("Access is denied"). Windows
/// renames it, so the runner moves its own file to `tasks.exe.<pid>.old` and
/// the path is free. The file of an earlier run is removed first. That fails,
/// and is ignored, only while that run is still running.
///
/// # Errors
/// The path of the runner cannot be read, or the rename fails. The error
/// comes before the build, not after it.
#[cfg(all(windows, not(all(feature = "mesh", feature = "bench"))))]
fn move_running_image_aside() -> Result<(), String> {
    let image = env::current_exe()
        .map_err(|error| format!("could not read the path of the runner: {error}"))?;
    let (Some(folder), Some(name)) = (
        image.parent(),
        image.file_name().and_then(|file| file.to_str()),
    ) else {
        return Ok(());
    };
    let prefix = format!("{name}.");
    if let Ok(entries) = fs::read_dir(folder) {
        for entry in entries.flatten() {
            let path = entry.path();
            let found = entry.file_name().to_string_lossy().into_owned();
            let is_old = path.extension().is_some_and(|extension| extension == "old");
            if is_old && found.starts_with(&prefix) {
                let _ = fs::remove_file(&path);
            }
        }
    }
    let aside = folder.join(format!("{name}.{}.old", process::id()));
    fs::rename(&image, &aside)
        .map_err(|error| format!("could not move {} aside: {error}", image.display()))
}
