/// Whether a drop counter has reached a value worth logging: the first one,
/// then every 256th.
///
/// Both backends are lossy by design, so a congested lane is indistinguishable
/// from a broken one unless it says something — but saying it per datagram
/// would itself be the problem. `total` is the counter *after* the increment.
#[cfg(any(feature = "native", feature = "web"))]
pub(crate) fn should_log_drop(total: u64) -> bool {
    total == 1 || total.is_multiple_of(256)
}

/// Whether the drops of a lane are sustained: a handful of drops is how QUIC learns the pace of a
/// lane (it retransmits and slows down), and a lane that keeps dropping is the one that needs a
/// warning. `total` is the counter *after* the increment.
#[cfg(any(feature = "native", feature = "web"))]
pub(crate) fn drops_are_sustained(total: u64) -> bool {
    total >= 256
}

#[cfg(all(test, any(feature = "native", feature = "web")))]
mod drop_policy_tests {
    use habilis_network_test_tracing::test;

    use super::{drops_are_sustained, should_log_drop};

    /// The first drop of a lane is logged and is no warning: QUIC retransmits it and slows down,
    /// as it does on any lossy path. A lane that keeps dropping warns, from the 256th drop on.
    #[test]
    fn a_first_drop_is_no_warning_and_a_sustained_one_is() {
        assert!(should_log_drop(1), "the first drop is logged");
        assert!(!drops_are_sustained(1), "the first drop is not sustained");
        assert!(!drops_are_sustained(255), "255 drops are not sustained");
        assert!(should_log_drop(256), "256 drops are logged again");
        assert!(drops_are_sustained(256), "256 drops are sustained");
        assert!(drops_are_sustained(512), "512 drops are sustained");
    }
}
