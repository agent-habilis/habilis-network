use iroh::RelayUrl;

/// The outcome of comparing a freshly-selected rung against the current
/// one — applied by the event loop's rung-update arm when the beacon's
/// self-monitor publishes a new rung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RungRefresh {
    /// Keep the current rung (still the first reachable, or we must not
    /// act — not the beacon, or relay disabled).
    NoChange,
    /// Re-home the beacon onto this rung (the current one died, or an
    /// earlier preferred one recovered). `None` ⇒ no rung reachable;
    /// drop to mDNS/DHT.
    Rehome(Option<RelayUrl>),
}
