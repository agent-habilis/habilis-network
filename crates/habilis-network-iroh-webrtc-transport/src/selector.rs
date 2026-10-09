//! Path selection that makes the relay a **rendezvous**, not a transport:
//! prefer a direct IP path, then `WebRTC`, then multihop, and fall to the relay
//! only when none of them is available.
//!
//! # Why a selector at all
//!
//! The relay is load-bearing for *signalling* — the JSEP exchange rides it —
//! so by the time the mount dial happens, the endpoint's address book already
//! holds a warm relay path for that peer. iroh merges a dial's address into
//! that book and fans the Initial out across everything it knows, so targeting
//! a `WebRTC`-only `EndpointAddr` does not keep the relay out of the race; the
//! warm path simply answers first.
//!
//! That alone would be recoverable — iroh re-selects as paths open. The part
//! that is not is iroh's default `BiasedRttPathSelector`, which skips any path
//! whose stats are not readable yet, and re-selection that fires only on
//! connection/path events with no periodic pass. A `WebRTC` path that opens a
//! moment before its first RTT sample is skipped exactly once and the relay
//! stays selected for the life of the connection. [`best_of`] is the fix: an
//! unmeasured path is a live candidate, not a non-candidate.
//!
//! # Why this is not "drop the relay"
//!
//! Only the *data plane* moves. iroh exposes no way to close a path, and the
//! demoted relay path is what lets a connection survive a dead data channel —
//! so the relay stays open and unused rather than being torn down.

use std::sync::Mutex;

use habilis_network_iroh_transport_util::{blocked, custom_rung, liveness::Liveness, rung_of};
use iroh::endpoint::transports::{
    PathSelection, PathSelectionContext, PathSelectionData, PathSelector,
};
use n0_future::time::Instant;

/// Prefers, in order: direct IP, `WebRTC`, multihop, gossip, relay.
///
/// On a browser target the first rung is always empty — iroh's whole IP stack
/// is `cfg(not(wasm_browser))`, and ICE *is* the tab's hole punch. A browser has
/// no multihop either, so the order collapses to `webrtc > relay` there without a
/// separate policy.
///
/// An endpoint has a single `Builder::path_selector` slot, so this selector and
/// `MultihopLadder` cannot both be installed. They rank by the same ladder
/// (`Rung`) and name a custom transport with the same function, `custom_rung` of
/// `habilis-network-iroh-transport-util`, which is what makes the last-call-wins
/// wiring safe.
#[derive(Debug)]
pub(crate) struct WebRtcPreferred {
    /// The endpoint this selector serves, so that a test can take paths away
    /// from one node to some others and not from the whole process.
    local: iroh_base::EndpointId,
    /// What each address received at the last calls: a path that the peer never sends on does not
    /// stay selected. One selector serves every remote of the endpoint.
    liveness: Mutex<Liveness>,
}

impl WebRtcPreferred {
    pub(crate) fn new(local: iroh_base::EndpointId) -> Self {
        Self {
            local,
            liveness: Mutex::new(Liveness::new()),
        }
    }

    /// [`PathSelector::select`] at `now`, so that a test can move the clock.
    fn select_at(&self, now: Instant, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let paths: Vec<PathSelectionData<'_>> = ctx.paths().collect();
        // The first rung with a usable path wins; within a rung, lowest RTT; a path whose
        // address stays silent while another rung is heard from is skipped for a while.
        let chosen = self
            .liveness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .choose(now, &paths, custom_rung, |rung, path| {
                !blocked(self.local, rung, path)
            });
        // Trace level, off by default: every call, with what it saw and chose, so
        // that a path that stays unselected can be told from a selector that never
        // ran.
        if tracing::enabled!(target: "habilis_ladder", tracing::Level::TRACE) {
            let seen: Vec<String> = paths
                .iter()
                .map(|path| {
                    format!(
                        "{:?} {:?} rtt_rx={:?}",
                        rung_of(path, custom_rung),
                        path.network_path().remote(),
                        path.stats()
                            .map(|stats| (stats.rtt, stats.udp_rx.datagrams))
                    )
                })
                .collect();
            tracing::trace!(
                target: "habilis_ladder",
                local = %self.local.fmt_short(),
                current = ?ctx.current().map(iroh::endpoint::transports::FourTuple::remote),
                ?seen,
                chosen = ?chosen.map(|path| path.network_path().remote()),
                "path selection"
            );
        }
        let mut selection = PathSelection::none();
        if let Some(path) = chosen {
            selection.set(path);
        }
        selection
    }
}

impl PathSelector for WebRtcPreferred {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        self.select_at(Instant::now(), ctx)
    }
}

#[cfg(feature = "test-hooks")]
pub use habilis_network_iroh_transport_util::{
    block_ip_paths, block_ip_to, block_rung, block_rung_to,
};

#[cfg(test)]
mod tests {
    use habilis_network_iroh_transport_util::{Rung, custom_rung};

    /// The ladder names this crate's transport by the id that the transport uses.
    /// The ids are written twice, here and in the util crate, which is below this
    /// one; this is the guard that they stay equal. It was green on its first run.
    #[test]
    fn the_ladder_knows_the_webrtc_transport_id_of_this_crate() {
        assert_eq!(custom_rung(crate::WEBRTC_TRANSPORT_ID), Rung::WebRtc);
    }

    /// The shape of the flake of the send ladder matrix: the WebRTC path stays at 6 datagrams
    /// while the multihop path grows. The first call takes the better rung, ten seconds later the
    /// selector has seen that the WebRTC address received nothing.
    #[test]
    fn a_webrtc_path_that_receives_nothing_does_not_stay_selected() {
        use std::time::Duration;

        use habilis_network_iroh_transport_util::MULTIHOP_TRANSPORT_ID;
        use iroh::endpoint::PathStats;
        use iroh::endpoint::transports::{
            Addr, FourTuple, PathSelectionContext, PathSelectionData,
        };
        use n0_future::time::Instant;

        let address = |transport: u64| {
            FourTuple::from_remote(Addr::Custom(iroh_base::CustomAddr::from_parts(
                transport,
                &[1],
            )))
        };
        let (webrtc, multihop) = (
            address(crate::WEBRTC_TRANSPORT_ID),
            address(MULTIHOP_TRANSPORT_ID),
        );
        let entry = |path_address, rx| {
            let mut stats = PathStats::default();
            stats.udp_rx.datagrams = rx;
            PathSelectionData::for_test(path_address, Some(stats))
        };
        let selector =
            super::WebRtcPreferred::new(iroh_base::SecretKey::from_bytes(&[7; 32]).public());
        let start = Instant::now();

        let first =
            PathSelectionContext::for_test(None, vec![entry(&webrtc, 6), entry(&multihop, 3)]);
        assert_eq!(
            selector.select_at(start, &first).selected_for_test(),
            Some(&webrtc)
        );
        let later =
            PathSelectionContext::for_test(None, vec![entry(&webrtc, 6), entry(&multihop, 23)]);
        assert_eq!(
            selector
                .select_at(start + Duration::from_secs(10), &later)
                .selected_for_test(),
            Some(&multihop)
        );
    }
}
