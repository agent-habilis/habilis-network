//! Why an inbound connection is refused.





/// Why a negotiation was not admitted. Diagnostic — every arm means "not now".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A round for this peer is already running.
    InFlight,
    /// We already hold a usable session with this peer.
    HaveSession,
    /// This peer refused us at *its* cap recently.
    Cooling,
    /// We evicted this peer lately, and its offer would take the place back.
    Evicted,
    /// The Router is shutting down.
    ShuttingDown,
    /// A test denied this peer: no round with it, offered or answered.
    Denied,
    /// The table of a route edge is at its cap: the units and the rounds in flight reach it, and
    /// nobody is evicted for a newcomer. The offerer waits as for any cap refusal.
    AtCapacity,
}
