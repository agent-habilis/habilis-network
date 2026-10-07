//! Path selection for an endpoint that has multihop and no `WebRTC`: the same
//! ladder as the `WebRTC` selector, IP, then multihop, then gossip, then the relay.
//!
//! iroh's default selector treats a custom transport as primary. This one puts
//! multihop below a direct path and above the relay: a route through other
//! members beats the relay, which is kept for lookup. The rung order is the one
//! in [`Rung`], shared with the `WebRTC` selector, so that it does not change
//! with the list of transports.

use habilis_network_iroh_transport_util::{Rung, climb, custom_rung, ip_remote, is_blocked};
use iroh::endpoint::transports::{
    PathSelection, PathSelectionContext, PathSelectionData, PathSelector,
};

/// The ladder of one node. `local` is the endpoint this selector serves, so that a
/// test can take a rung, or an IP port, away from this node alone: the underlay
/// has an endpoint of its own, with its own id.
#[derive(Debug)]
pub(crate) struct MultihopLadder {
    local: iroh::EndpointId,
}

impl MultihopLadder {
    pub(crate) fn new(local: iroh::EndpointId) -> Self {
        Self { local }
    }

    /// Whether a path of `rung`, to the IP address `remote` (none for a relay or a
    /// custom path), is one that a test has not taken from this node. Always true
    /// without the `test-hooks` of `habilis-network-iroh-transport-util`.
    fn usable(&self, rung: Rung, remote: Option<std::net::SocketAddr>) -> bool {
        !is_blocked(self.local, rung, remote)
    }
}

impl PathSelector for MultihopLadder {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let paths: Vec<PathSelectionData<'_>> = ctx.paths().collect();
        let chosen = climb(&paths, custom_rung, |rung, path| {
            self.usable(rung, ip_remote(path))
        });
        let mut selection = PathSelection::none();
        if let Some(path) = chosen {
            selection.set(path);
        }
        selection
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_iroh_transport_util::{block_ip_to, block_rung};

    use super::*;

    /// The ladder names this crate's transport by the id that the transport uses.
    /// The ids are written twice, here and in the util crate, which is below this
    /// one; this is the guard that they stay equal.
    #[test]
    fn the_ladder_knows_the_multihop_transport_id_of_this_crate() {
        assert_eq!(custom_rung(crate::MULTIHOP_TRANSPORT_ID), Rung::Multihop);
    }

    fn node(seed: u8) -> iroh::EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn at(port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// The underlay has its own endpoint, and a test must be able to take its IP
    /// paths away: the ladder reads the same tables as the `WebRTC` selector.
    #[test]
    fn the_ladder_of_a_node_gives_up_an_ip_port_that_a_test_blocked() {
        let (local, other) = (node(21), node(22));
        let ladder = MultihopLadder::new(local);
        block_ip_to(local, [5000]);
        assert!(!ladder.usable(Rung::Ip, Some(at(5000))), "the blocked port");
        assert!(ladder.usable(Rung::Ip, Some(at(5001))), "another port");
        assert!(ladder.usable(Rung::Multihop, None), "another rung");
        assert!(ladder.usable(Rung::Relay, None), "another rung");
        assert!(
            MultihopLadder::new(other).usable(Rung::Ip, Some(at(5000))),
            "another node"
        );
        block_ip_to(local, []);
        assert!(
            ladder.usable(Rung::Ip, Some(at(5000))),
            "an empty set clears"
        );
    }

    #[test]
    fn the_ladder_of_a_node_gives_up_a_rung_that_a_test_blocked() {
        let (local, other) = (node(23), node(24));
        let ladder = MultihopLadder::new(local);
        block_rung(local, Rung::Multihop, true);
        assert!(!ladder.usable(Rung::Multihop, None));
        assert!(ladder.usable(Rung::Ip, Some(at(1))), "another rung");
        assert!(MultihopLadder::new(other).usable(Rung::Multihop, None));
        block_rung(local, Rung::Multihop, false);
        assert!(ladder.usable(Rung::Multihop, None));
    }
}
