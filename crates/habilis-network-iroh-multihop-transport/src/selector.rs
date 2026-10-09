//! Path selection for an endpoint that has multihop and no `WebRTC`: the same
//! ladder as the `WebRTC` selector, IP, then multihop, then gossip, then the relay.
//!
//! iroh's default selector treats a custom transport as primary. This one puts
//! multihop below a direct path and above the relay: a route through other
//! members beats the relay, which is kept for lookup. The rung order is the one
//! in [`Rung`], shared with the `WebRTC` selector, so that it does not change
//! with the list of transports.

use std::sync::Mutex;

use habilis_network_iroh_transport_util::{
    Rung, custom_rung, ip_remote, is_blocked_to, liveness::Liveness, remote_id,
};
use iroh::endpoint::transports::{
    PathSelection, PathSelectionContext, PathSelectionData, PathSelector,
};
use n0_future::time::Instant;

/// The ladder of one node. `local` is the endpoint this selector serves, so that a
/// test can take a rung, or an IP port, away from this node alone: the underlay
/// has an endpoint of its own, with its own id.
#[derive(Debug)]
pub(crate) struct MultihopLadder {
    local: iroh::EndpointId,
    /// What each address received at the last calls: a path that the peer never sends on does not
    /// stay selected. One selector serves every remote of the endpoint.
    liveness: Mutex<Liveness>,
}

impl MultihopLadder {
    pub(crate) fn new(local: iroh::EndpointId) -> Self {
        Self {
            local,
            liveness: Mutex::new(Liveness::new()),
        }
    }

    /// Whether a path of `rung`, to the IP address `remote` (none for a relay or a
    /// custom path), is one that a test has not taken from this node. Always true
    /// without the `test-hooks` of `habilis-network-iroh-transport-util`.
    fn usable(
        &self,
        rung: Rung,
        remote: Option<std::net::SocketAddr>,
        remote_id: Option<iroh::EndpointId>,
    ) -> bool {
        !is_blocked_to(self.local, rung, remote, remote_id)
    }
}

impl MultihopLadder {
    /// [`PathSelector::select`] at `now`, so that a test can move the clock.
    fn select_at(&self, now: Instant, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let paths: Vec<PathSelectionData<'_>> = ctx.paths().collect();
        let chosen = self
            .liveness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .choose(now, &paths, custom_rung, |rung, path| {
                self.usable(rung, ip_remote(path), remote_id(path))
            });
        let mut selection = PathSelection::none();
        if let Some(path) = chosen {
            selection.set(path);
        }
        selection
    }
}

impl PathSelector for MultihopLadder {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        self.select_at(Instant::now(), ctx)
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_iroh_transport_util::{block_ip_to, block_rung, block_rung_to};

    use super::*;

    /// The ladder names this crate's transport by the id that the transport uses.
    /// The ids are written twice, here and in the util crate, which is below this
    /// one; this is the guard that they stay equal.
    #[test]
    fn the_ladder_knows_the_multihop_transport_id_of_this_crate() {
        assert_eq!(custom_rung(crate::MULTIHOP_TRANSPORT_ID), Rung::Multihop);
    }

    /// A multihop path that receives nothing, while gossip is heard from, does not stay selected.
    #[test]
    fn a_multihop_path_that_receives_nothing_does_not_stay_selected() {
        use std::time::Duration;

        use habilis_network_iroh_transport_util::GOSSIP_TRANSPORT_ID;
        use iroh::endpoint::PathStats;
        use iroh::endpoint::transports::{Addr, FourTuple};

        let address = |transport: u64| {
            FourTuple::from_remote(Addr::Custom(iroh_base::CustomAddr::from_parts(
                transport,
                &[1],
            )))
        };
        let (multihop, gossip) = (
            address(crate::MULTIHOP_TRANSPORT_ID),
            address(GOSSIP_TRANSPORT_ID),
        );
        let entry = |path_address, rx| {
            let mut stats = PathStats::default();
            stats.udp_rx.datagrams = rx;
            PathSelectionData::for_test(path_address, Some(stats))
        };
        let ladder = MultihopLadder::new(node(31));
        let start = Instant::now();

        let first =
            PathSelectionContext::for_test(None, vec![entry(&multihop, 6), entry(&gossip, 3)]);
        assert_eq!(
            ladder.select_at(start, &first).selected_for_test(),
            Some(&multihop)
        );
        let later =
            PathSelectionContext::for_test(None, vec![entry(&multihop, 6), entry(&gossip, 23)]);
        assert_eq!(
            ladder
                .select_at(start + Duration::from_secs(10), &later)
                .selected_for_test(),
            Some(&gossip)
        );
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
        assert!(
            !ladder.usable(Rung::Ip, Some(at(5000)), None),
            "the blocked port"
        );
        assert!(
            ladder.usable(Rung::Ip, Some(at(5001)), None),
            "another port"
        );
        assert!(ladder.usable(Rung::Multihop, None, None), "another rung");
        assert!(ladder.usable(Rung::Relay, None, None), "another rung");
        assert!(
            MultihopLadder::new(other).usable(Rung::Ip, Some(at(5000)), None),
            "another node"
        );
        block_ip_to(local, []);
        assert!(
            ladder.usable(Rung::Ip, Some(at(5000)), None),
            "an empty set clears"
        );
    }

    #[test]
    fn the_ladder_of_a_node_gives_up_a_rung_that_a_test_blocked() {
        let (local, other) = (node(23), node(24));
        let ladder = MultihopLadder::new(local);
        block_rung(local, Rung::Multihop, true);
        assert!(!ladder.usable(Rung::Multihop, None, None));
        assert!(ladder.usable(Rung::Ip, Some(at(1)), None), "another rung");
        assert!(MultihopLadder::new(other).usable(Rung::Multihop, None, None));
        block_rung(local, Rung::Multihop, false);
        assert!(ladder.usable(Rung::Multihop, None, None));
    }

    /// The ladder also gives up the `WebRTC` rung to one remote only, which is what
    /// lets a test cut one pair of three members and keep the others.
    #[test]
    fn the_ladder_of_a_node_gives_up_webrtc_to_one_remote_only() {
        let (local, cut, kept) = (node(25), node(26), node(27));
        let ladder = MultihopLadder::new(local);
        block_rung_to(local, Rung::WebRtc, cut, true);
        assert!(!ladder.usable(Rung::WebRtc, None, Some(cut)));
        assert!(
            ladder.usable(Rung::WebRtc, None, Some(kept)),
            "another remote"
        );
        assert!(
            ladder.usable(Rung::Ip, Some(at(1)), Some(cut)),
            "another rung"
        );
        block_rung_to(local, Rung::WebRtc, cut, false);
        assert!(ladder.usable(Rung::WebRtc, None, Some(cut)));
    }
}
