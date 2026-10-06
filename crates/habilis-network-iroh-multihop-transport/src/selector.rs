//! Path selection for an endpoint that has multihop and no `WebRTC`: the same
//! ladder as the `WebRTC` selector, IP, then multihop, then the relay.
//!
//! iroh's default selector treats a custom transport as primary. This one puts
//! multihop below a direct path and above the relay: a route through other
//! members beats the relay, which is kept for lookup. The rung order is the one
//! in [`Rung`], shared with the `WebRTC` selector, so that it does not change
//! with the list of transports.

use habilis_network_iroh_transport_util::{Rung, climb};
use iroh::endpoint::transports::{
    PathSelection, PathSelectionContext, PathSelectionData, PathSelector,
};

use crate::MULTIHOP_TRANSPORT_ID;

#[derive(Debug)]
pub(crate) struct MultihopLadder;

/// The rung of a custom transport id. A foreign one ranks below the relay. See
/// `WebRtcPreferred` in the `WebRTC` crate for why the two functions agree.
fn custom_rung(id: u64) -> Rung {
    if id == MULTIHOP_TRANSPORT_ID {
        Rung::Multihop
    } else {
        Rung::Other
    }
}

impl PathSelector for MultihopLadder {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let paths: Vec<PathSelectionData<'_>> = ctx.paths().collect();
        let chosen = climb(&paths, custom_rung, |_, _| true);
        let mut selection = PathSelection::none();
        if let Some(path) = chosen {
            selection.set(path);
        }
        selection
    }
}
