//! Path selection that makes multihop a **backup**: prefer any direct or relay
//! path, and fall to a multihop path only when nothing else is available.
//!
//! iroh's default selector treats a custom transport as primary; that is the
//! opposite of what we want — relaying through peers should be the last resort,
//! not the first. This selector inverts that.

use habilis_network_iroh_transport_util::best_of;
use iroh::endpoint::transports::{
    Addr, PathSelection, PathSelectionContext, PathSelectionData, PathSelector,
};

use crate::MULTIHOP_TRANSPORT_ID;

#[derive(Debug)]
pub(crate) struct MultihopBackup;

impl PathSelector for MultihopBackup {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let paths: Vec<PathSelectionData<'_>> = ctx.paths().collect();
        // Prefer a direct/relay path; only if none exists use a multihop path.
        let chosen = best_of(paths.iter().filter(|path| !is_multihop(path)))
            .or_else(|| best_of(paths.iter().filter(|path| is_multihop(path))));
        let mut selection = PathSelection::none();
        if let Some(path) = chosen {
            selection.set(path);
        }
        selection
    }
}

fn is_multihop(path: &PathSelectionData<'_>) -> bool {
    matches!(path.network_path().remote(), Addr::Custom(addr) if addr.id() == MULTIHOP_TRANSPORT_ID)
}
