/// A note that a member keeps about its own beacon claim. A note is in the set while it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BeaconNote {
    /// What the last `PeerInfo` we flooded said about `hosts_rendezvous`, so the flag is sent
    /// again when it changes.
    FlagFlooded,
}
