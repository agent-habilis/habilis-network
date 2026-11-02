/// A hold that a test places on this node to force an order of events. A hold is in the set
/// while the test keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TestHold {
    /// While held, this node advertises no link-vector, on the tick or on a link event. A test
    /// holds it to force the order "the path is lost before any route exists".
    #[cfg(feature = "multihop")]
    LinkState,
    /// While held, this node claims no rendezvous, neither on a heal tick nor in a reclaim window.
    /// A test uses it to force the order "a late joiner claims the free rung before any old member
    /// does", which a heal tick of a few seconds would otherwise win.
    Claims,
    /// The beacon is shed at the top of the next turn of the loop, as a re-check shed does
    /// (`Beacons::ShedBeacon`). The loop takes the hold, so it is set once per shed.
    Shed,
    /// The beacon stops answering at the top of the next turn of the loop (`Beacons::StallBeacon`).
    /// The loop takes the hold, so it is set once per stall.
    Stall,
}
