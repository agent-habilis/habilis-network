//! An event after the last guard of a binary has nobody to fail, so the binary
//! exits with 101 and prints it.

use std::process::Command;

use std::{env, process};
const CHILD: &str = "HABILIS_TEST_TRACING_CHILD";

#[test]
fn a_binary_with_a_late_event_at_exit_exits_with_101() {
    let exe = env::current_exe().expect("exe");
    let output: process::Output = Command::new(exe)
        .args(["--exact", "child_logs_after_its_guard", "--nocapture"])
        .env(CHILD, "1")
        .output()
        .expect("run the child");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(101), "{stderr}");
    assert!(
        stderr.contains("logged after test child_logs_after_its_guard ended"),
        "{stderr}"
    );
    assert!(stderr.contains("late at exit"), "{stderr}");
}

#[test]
fn child_logs_after_its_guard() {
    if env::var_os(CHILD).is_none() {
        return;
    }
    drop(habilis_network_test_tracing::init());
    tracing::error!("late at exit");
}
