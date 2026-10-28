//! The application close codes of the transport plane, in one list.
//!
//! A code is wire-load-bearing only weakly: a peer too old to know it just sees
//! a closed connection and retries, which is the behaviour it had before. But
//! two meanings on one number would be a silent bug, so every code of the plane
//! lives here and a test holds them apart. Each ALPN reads its own subset.

/// We are at our direct-peer ceiling.
///
/// Distinct from a failure so the dialer can tell "no room" from "ICE broke"
/// and back off instead of re-offering every tick.
pub(crate) const CAP_REFUSED: u32 = 1;
/// The negotiation failed.
pub(crate) const SIGNAL_FAILED: u32 = 2;
/// The negotiation ran out of time, or the Router is shutting down.
pub(crate) const SIGNAL_ABORTED: u32 = 3;
/// A gossip connection whose path may not carry payload.
pub(crate) const GOSSIP_RELAY_REFUSED: u32 = 4;
/// A unicast connection whose path may not carry payload.
pub(crate) const UNICAST_RELAY_REFUSED: u32 = 5;
// 6 was `EVICTED` on this branch (removed in 597dedf), and builds of the PR
// sent it. Do not reuse it while those builds can still be in a mesh.
// 7 was `RENDEZVOUS_RELEASED`, sent by builds of the PR that closed the link
// to the rendezvous themselves; the same applies.
/// A unicast connection nothing sent on for the idle timeout: closed by the
/// pool on the dial side, by the acceptor on the other.
pub(crate) const IDLE: u32 = 8;
/// A signal from an endpoint that is not a neighbor of the underlay. Its only sender is
/// `underlay_webrtc`, which exists with the `multihop` feature.
#[cfg(any(feature = "multihop", test))]
pub(crate) const NOT_A_NEIGHBOR: u32 = 9;
/// A direct connection closed because the node is at its ceiling of direct
/// connections and this one was the least recently used. The dialer backs off
/// before it dials this peer on its own again: a send still dials at once.
pub(crate) const EVICTED: u32 = 11;
/// A gossip connection whose selected path is the gossip rung: gossip would carry the
/// frames that gossip needs to carry itself.
pub(crate) const GOSSIP_ON_GOSSIP_PATH: u32 = 10;
// The next free number is 12.

#[cfg(test)]
mod tests {
    use super::{
        CAP_REFUSED, EVICTED, GOSSIP_ON_GOSSIP_PATH, GOSSIP_RELAY_REFUSED, IDLE, NOT_A_NEIGHBOR,
        SIGNAL_ABORTED, SIGNAL_FAILED, UNICAST_RELAY_REFUSED,
    };
    use habilis_network_test_tracing::test;
    use std::collections::HashSet;

    #[test]
    fn no_two_codes_share_a_number() {
        let all = [
            CAP_REFUSED,
            SIGNAL_FAILED,
            SIGNAL_ABORTED,
            GOSSIP_RELAY_REFUSED,
            UNICAST_RELAY_REFUSED,
            IDLE,
            NOT_A_NEIGHBOR,
            GOSSIP_ON_GOSSIP_PATH,
            EVICTED,
        ];
        let distinct: HashSet<_> = all.into_iter().collect();
        assert_eq!(distinct.len(), all.len());
    }
}
