/// What a member's `PeerInfo` says about the rendezvous, and whether we believe the sender. One
/// struct for the pair, because both are a `bool` and a swap compiles and flips the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RivalFlag {
    /// The signer proved the endpoint it sent from.
    pub(crate) proven: bool,
    /// The `PeerInfo` carries the beacon flag: the member holds the rendezvous.
    pub(crate) held: bool,
}
