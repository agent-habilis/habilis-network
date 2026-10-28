//! A change of path kind for one peer.

use super::path_kind::PathKind;

use iroh::EndpointId;

/// How long "no path selected" must last before a watcher reports it. iroh
/// can leave the selection empty between a path's `Abandoned` and the next
/// `Established` (fork `remote_state.rs:650-651`, `:1516-1517`); seen in the
/// e2e as a 2 ms blip, each of which started a whole new race.
pub(crate) const NO_PATH_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// A watcher's report: `kind` is now the selected path to `peer`, on the
/// pooled connection `conn_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathChange {
    pub(crate) peer: EndpointId,
    pub(crate) kind: PathKind,
    pub(crate) conn_id: usize,
}
