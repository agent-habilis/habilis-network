//! The WARN of hickory about a line of the hosts file that does not start with an IP reports the
//! config of the host machine, not our code: a CI runner on EC2 has such a line. The guard
//! ignores that one WARN, and only it. These cases build their own guard, so they use the plain
//! test attribute.

use std::panic::AssertUnwindSafe;

fn panic_text(body: impl FnOnce() + Send) -> Option<String> {
    let err = habilis_network_test_tracing::catch_panic(AssertUnwindSafe(body)).err()?;
    let text: Option<&String> = err.downcast_ref();
    text.cloned()
}

#[test]
fn the_hosts_file_warn_of_hickory_passes() {
    let _guard = habilis_network_test_tracing::init();
    tracing::warn!(
        target: "hickory_resolver::hosts",
        "could not parse an IP from hosts file (\"ip-10-0-128-25.ec2.internal\")"
    );
}

#[test]
fn another_hickory_hosts_warn_still_fails() {
    let text = panic_text(|| {
        let _guard = habilis_network_test_tracing::init();
        tracing::warn!(target: "hickory_resolver::hosts", "failed to read the hosts file");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected WARN"), "{text}");
    assert!(text.contains("failed to read the hosts file"), "{text}");
}

#[test]
fn the_same_text_from_another_hickory_target_still_fails() {
    let text = panic_text(|| {
        let _guard = habilis_network_test_tracing::init();
        tracing::warn!(
            target: "hickory_resolver::config",
            "could not parse an IP from hosts file (\"ip-10-0-128-25.ec2.internal\")"
        );
    });
    let text = text.expect("the guard must panic");
    assert!(
        text.contains("unexpected WARN hickory_resolver::config"),
        "{text}"
    );
}

#[test]
fn the_hosts_file_text_as_an_error_still_fails() {
    let text = panic_text(|| {
        let _guard = habilis_network_test_tracing::init();
        tracing::error!(
            target: "hickory_resolver::hosts",
            "could not parse an IP from hosts file (\"ip-10-0-128-25.ec2.internal\")"
        );
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected ERROR"), "{text}");
}

#[test]
fn the_hosts_file_text_not_at_the_start_still_fails() {
    let text = panic_text(|| {
        let _guard = habilis_network_test_tracing::init();
        tracing::warn!(
            target: "hickory_resolver::hosts",
            "retry: could not parse an IP from hosts file (\"ip-10-0-128-25.ec2.internal\")"
        );
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected WARN"), "{text}");
}
