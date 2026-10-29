//! A test that asserts on the filter of the binary must not depend on `RUST_LOG`, which wins over
//! the directives of the test. The crate denies `unsafe`, so the test cannot unset the variable
//! itself. It runs again in a child process that has no `RUST_LOG`.

use std::process::Command;

use std::env;
/// Runs `body` when `RUST_LOG` is unset. Otherwise runs the test `name` of this binary in a child
/// process without `RUST_LOG`, and fails if the child fails.
pub(crate) fn without_rust_log(name: &str, body: impl FnOnce()) {
    if env::var_os("RUST_LOG").is_none() {
        body();
        return;
    }
    let exe = env::current_exe().expect("the path of the test binary");
    let mut command = Command::new(exe);
    command
        .args(["--exact", name, "--test-threads=1"])
        .env_remove("RUST_LOG");
    let child = command.output().expect("the child test process starts");
    assert!(
        child.status.success(),
        "{name} failed without RUST_LOG:\n{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
}
