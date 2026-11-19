use std::sync::atomic::{AtomicU64, Ordering};

use iroh::RelayUrl;

/// The monitor of one beacon. A beacon that is shed ends its monitor, but a decision of that
/// monitor can still be on its way to the event loop, so the loop tells it from the decision of the
/// monitor of the beacon that it holds now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Generation(u64);

impl Generation {
    /// A generation that no other monitor of this process has.
    pub(crate) fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// What the event loop does with the rung of a [`RungDecision`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum RungChange {
    /// Re-home the beacon: it sheds the beacon and claims a new one on the rung. The rung of the
    /// beacon failed, or the probe at startup found another.
    #[default]
    Rehome,
    /// The beacon already moved its own relay to the rung, in place, and goes on serving. The loop
    /// only follows it: the rung that it registers for joiners, and the rung of the next claim.
    Moved,
}

/// The rung that a rung selector picked, and who picked it. The selectors run off the event loop:
/// the probe at startup, and the monitor of each beacon.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RungDecision {
    /// The monitor that picked the rung. `None` for the probe at startup, which no beacon owns: its
    /// decision is applied whichever beacon is held. The window is short, one probe at the start
    /// of the process.
    pub(crate) from: Option<Generation>,
    /// The rung to home on. `None` when no rung answers.
    pub(crate) rung: Option<RelayUrl>,
    /// What the loop does with the rung.
    pub(crate) change: RungChange,
}

impl RungDecision {
    /// The rung that the probe at startup picked, or the first rung of the ladder before the probe
    /// has answered.
    pub(crate) fn at_startup(rung: Option<RelayUrl>) -> Self {
        Self {
            from: None,
            rung,
            change: RungChange::Rehome,
        }
    }
}
