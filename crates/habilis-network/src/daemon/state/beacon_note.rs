/// A note that a member keeps about its own beacon claim. A note is in the set while it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BeaconNote {
    /// A holder with a lower member id said, in its `PeerInfo`, that it holds the rendezvous
    /// too. The next due re-check then sheds at once, whatever depends on this beacon: the
    /// rival's flag already settled who keeps it. Cleared by the shed and by a fresh claim.
    YieldToLower,
    /// What the last `PeerInfo` we flooded said about `hosts_rendezvous`, so the flag is sent
    /// again when it changes.
    FlagFlooded,
}
