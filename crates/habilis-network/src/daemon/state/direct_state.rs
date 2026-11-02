use crate::gossip;
/// What a linked peer's selected data path is, as last observed. A link
/// starts on the relay and migrates to a direct path once iroh punches one,
/// so a value taken at `NeighborUp` is a first reading, refreshed by the
/// census.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectState {
    /// A probe (or a `WebRTC` negotiation) is in flight; the peer is held off
    /// the overlay until it reports.
    Pending,
    /// A hole-punched IP path or a custom transport (`WebRTC`, multihop).
    Direct,
    /// The relay is the only active path.
    RelayOnly,
}

impl DirectState {
    /// From a `conn_path` reading; `None` when the reading proves nothing.
    /// `Mixed` is such a reading: iroh keeps the relay path open beside a
    /// punched one, and `conn_path` cannot tell which is selected, so a mixed
    /// link is neither proven direct nor known relay-only.
    pub(crate) fn classify(summary: gossip::PathSummary) -> Option<Self> {
        use crate::gossip::PathSummary;
        match summary {
            PathSummary::Direct => Some(Self::Direct),
            PathSummary::Relay => Some(Self::RelayOnly),
            PathSummary::Mixed | PathSummary::Unknown => None,
        }
    }
}
