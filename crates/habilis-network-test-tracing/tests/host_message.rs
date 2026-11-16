//! The resolver of iroh warns about a line of the hosts file that it cannot parse, such as the
//! `ip-10-0-133-152.us-west-2.compute.internal` line of a CI runner. That line is the state of the
//! host, not of the code under test, so this one message does not fail a test. Every other WARN, of
//! this target or of another, still does. These cases build their own guard, so they use the plain
//! test attribute.

use std::panic::AssertUnwindSafe;

const HOSTS_TARGET: &str = "hickory_resolver::hosts";

fn panic_text(body: impl FnOnce() + Send) -> Option<String> {
    let err = habilis_network_test_tracing::catch_panic(AssertUnwindSafe(body)).err()?;
    let text: Option<&String> = err.downcast_ref();
    text.cloned()
}

#[test]
fn a_hosts_file_line_that_the_resolver_cannot_parse_does_not_fail_a_test() {
    let _log = habilis_network_test_tracing::init();
    tracing::warn!(
        target: "hickory_resolver::hosts",
        "could not parse an IP from hosts file (\"ip-10-0-133-152.us-west-2.compute.internal\")"
    );
}

#[test]
fn another_warn_of_the_resolver_still_fails() {
    let text = panic_text(|| {
        let _log = habilis_network_test_tracing::init();
        tracing::warn!(target: "hickory_resolver::hosts", "the hosts file is unreadable");
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected WARN"), "{text}");
    assert!(text.contains(HOSTS_TARGET), "{text}");
}

#[test]
fn the_same_text_on_another_target_still_fails() {
    let text = panic_text(|| {
        let _log = habilis_network_test_tracing::init();
        tracing::warn!(
            target: "habilis_network::gossip",
            "could not parse an IP from hosts file (\"x\")"
        );
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected WARN"), "{text}");
}

#[test]
fn the_message_as_an_error_still_fails() {
    let text = panic_text(|| {
        let _log = habilis_network_test_tracing::init();
        tracing::error!(
            target: "hickory_resolver::hosts",
            "could not parse an IP from hosts file (\"x\")"
        );
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected ERROR"), "{text}");
}
