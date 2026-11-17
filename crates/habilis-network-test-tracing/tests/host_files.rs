//! A WARN about a file of the machine, such as a line of `/etc/hosts` that the DNS resolver cannot read, says
//! nothing about the code under test, so the guard does not fail on it. An ERROR from the same target still fails.

use std::panic::AssertUnwindSafe;

const HOSTS: &str = "hickory_resolver::hosts";

fn panic_text(body: impl FnOnce() + Send) -> Option<String> {
    let err = habilis_network_test_tracing::catch_panic(AssertUnwindSafe(body)).err()?;
    let text: Option<&String> = err.downcast_ref();
    text.cloned()
}

#[test]
fn a_warn_about_the_hosts_file_of_the_machine_passes() {
    let text = panic_text(|| {
        let _log = habilis_network_test_tracing::init();
        tracing::warn!(target: HOSTS, "could not parse an IP from hosts file (\"ip-10-0-130-32\")");
    });
    assert_eq!(
        text, None,
        "a line of the hosts file must not fail the test"
    );
}

#[test]
fn an_error_from_the_hosts_target_still_fails() {
    let text = panic_text(|| {
        let _log = habilis_network_test_tracing::init();
        tracing::error!(target: HOSTS, "the resolver broke");
    });
    let text = text.expect("the guard must panic on an error");
    assert!(text.contains("unexpected ERROR"), "{text}");
}
