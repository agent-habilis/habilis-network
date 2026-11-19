//! The forwarder of a multihop mesh whose list has no `relay` refuses a cell that comes over the
//! relay, and says so once as a WARN. A scenario that cuts a pair, or that opens a hop, can race
//! that refusal, so a test of such a mesh allows it with one helper. The allowance is narrow: the
//! refusal for that reason, and no other WARN of the forwarder.

use std::panic::AssertUnwindSafe;

const FORWARDER: &str = "habilis_network_iroh_multihop_transport::underlay";

fn panic_text(body: impl FnOnce() + Send) -> Option<String> {
    let err = habilis_network_test_tracing::catch_panic(AssertUnwindSafe(body)).err()?;
    let text: Option<&String> = err.downcast_ref();
    text.cloned()
}

#[test]
fn a_cell_that_arrived_over_the_relay_may_be_refused() {
    let _guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::allow_relay_cell_refusal();
    tracing::warn!(
        target: "habilis_network_iroh_multihop_transport::underlay",
        total = 1,
        reason = "cell arrived over the relay",
        "multihop forwarder refusing cells"
    );
}

#[test]
fn the_refusal_may_also_not_come() {
    let _guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::allow_relay_cell_refusal();
}

#[test]
fn a_refusal_for_another_reason_still_fails() {
    let text = panic_text(|| {
        let _guard = habilis_network_test_tracing::init();
        habilis_network_test_tracing::allow_relay_cell_refusal();
        tracing::warn!(
            target: "habilis_network_iroh_multihop_transport::underlay",
            total = 1,
            reason = "cell for an unknown hop",
            "multihop forwarder refusing cells"
        );
    });
    let text = text.expect("the guard must panic");
    assert!(text.contains("unexpected WARN"), "{text}");
    assert!(text.contains("cell for an unknown hop"), "{text}");
    assert!(
        text.contains(FORWARDER) || text.contains("multihop forwarder"),
        "{text}"
    );
}
