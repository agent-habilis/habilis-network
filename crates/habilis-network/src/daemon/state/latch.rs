/// A flag that a member sets for one event and clears when the event is handled. A latch is in
/// the set while it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Latch {
    /// A `NeighborUp` wanted to flood our `PeerInfo` inside the window and was held back. The
    /// alive tick pays it once the window ends.
    PeerInfoDeferred,
    /// Set once this process's resident memory first crosses `tuning::resident_memory_warn_mb`,
    /// so the `warn` fires exactly once per process rather than every prune tick. Purely
    /// observability — never gates behavior (see `timers::tick_prune`).
    ResidentMemoryWarned,
}
