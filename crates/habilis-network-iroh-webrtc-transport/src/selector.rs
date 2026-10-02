//! Path selection that makes the relay a **rendezvous**, not a transport:
//! prefer a direct IP path, then `WebRTC`, and fall to the relay only when
//! neither is available.
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

use habilis_network_iroh_transport_util::best_of;
use iroh::endpoint::transports::{
    Addr, PathSelection, PathSelectionContext, PathSelectionData, PathSelector,
};

use crate::WEBRTC_TRANSPORT_ID;

/// Prefers, in order: direct IP, `WebRTC`, relay, any other custom transport.
///
/// On a browser target the first tier is always empty — iroh's whole IP stack
/// is `cfg(not(wasm_browser))`, and ICE *is* the tab's hole punch — so the
/// order collapses to `webrtc > relay` there without a separate policy.
#[derive(Debug)]
pub(crate) struct WebRtcPreferred;

impl PathSelector for WebRtcPreferred {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let paths: Vec<PathSelectionData<'_>> = ctx.paths().collect();
        let tier = |want: Tier| best_of(paths.iter().filter(move |path| tier_of(path) == want));
        // First non-empty tier wins; within a tier, lowest RTT.
        let chosen = (!ip_blocked())
            .then(|| tier(Tier::Ip))
            .flatten()
            .or_else(|| tier(Tier::WebRtc))
            .or_else(|| tier(Tier::Relay))
            .or_else(|| tier(Tier::OtherCustom));
        let mut selection = PathSelection::none();
        if let Some(path) = chosen {
            selection.set(path);
        }
        selection
    }
}

#[cfg(feature = "test-hooks")]
static IP_BLOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Tests only: while set, no IP path is selected, in every endpoint of the
/// process. iroh re-runs selection on its path-stat updates, so a live
/// connection leaves UDP within a few seconds and returns once it is cleared.
#[cfg(feature = "test-hooks")]
pub fn block_ip_paths(blocked: bool) {
    IP_BLOCKED.store(blocked, std::sync::atomic::Ordering::SeqCst);
}

fn ip_blocked() -> bool {
    #[cfg(feature = "test-hooks")]
    {
        IP_BLOCKED.load(std::sync::atomic::Ordering::SeqCst)
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        false
    }
}

/// Preference tiers, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    Ip,
    WebRtc,
    Relay,
    /// Any custom transport that is not ours — today, multihop.
    ///
    /// Deliberately ranked last rather than left unhandled. An endpoint has a
    /// single `Builder::path_selector` slot, so this selector and
    /// `MultihopBackup` cannot both be installed; ranking foreign custom
    /// transports below the relay reproduces multihop's own "backup" policy,
    /// which is what makes the last-call-wins wiring safe.
    OtherCustom,
}

fn tier_of(path: &PathSelectionData<'_>) -> Tier {
    match path.network_path().remote() {
        Addr::Ip(_) => Tier::Ip,
        Addr::Relay(..) => Tier::Relay,
        Addr::Custom(addr) if addr.id() == WEBRTC_TRANSPORT_ID => Tier::WebRtc,
        Addr::Custom(_) => Tier::OtherCustom,
    }
}
