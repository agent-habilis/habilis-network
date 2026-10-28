#[cfg(all(feature = "multihop", feature = "iroh-test-utils"))]
use std::sync::atomic;
#[cfg(any(
    all(feature = "host", feature = "iroh-test-utils"),
    all(feature = "iroh-test-utils", feature = "multihop")
))]
use std::sync::atomic::Ordering;

// Only the `host` loopback bind names a socket address; a browser has no IP
// stack to bind one on.

/// Tests only: while set, no node of this process gets a `WebRTC` leg on its
/// underlay, which gives a harness the control cell of a measurement of what the
/// leg costs. A flag of the process, like `block_ip_paths`: set it before the node
/// starts.
#[cfg(all(feature = "multihop", feature = "iroh-test-utils"))]
static UNDERLAY_LEG_OFF: atomic::AtomicBool = atomic::AtomicBool::new(false);

/// Tests only: see `UNDERLAY_LEG_OFF`.
#[cfg(all(feature = "host", feature = "iroh-test-utils"))]
pub fn set_underlay_leg_off(
    // true turns the underlay leg off, false turns it back on
    off: bool,
) {
    UNDERLAY_LEG_OFF.store(off, Ordering::SeqCst);
}

/// The cap of the `WebRTC` leg of the underlay for a node with `max_peers` (G):
/// `Some(G)`, or `None` while a test switched the leg off.
#[cfg(feature = "multihop")]
#[cfg_attr(
    not(feature = "iroh-test-utils"),
    expect(
        clippy::unnecessary_wraps,
        reason = "None only when a test switched the leg off"
    )
)]
pub(crate) fn underlay_cap(max_peers: usize) -> Option<usize> {
    #[cfg(feature = "iroh-test-utils")]
    if UNDERLAY_LEG_OFF.load(Ordering::SeqCst) {
        return None;
    }
    Some(max_peers)
}
