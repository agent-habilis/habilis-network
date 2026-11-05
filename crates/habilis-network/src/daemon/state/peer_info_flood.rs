use crate::util::clock::Instant;

/// When our `PeerInfo` last went out, and how far its refresh is spread. The flood has a spread of
/// its own, so the members of a mesh that flood together do not refresh together.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerInfoFlood {
    /// When the flood went out, whatever triggered it.
    pub(crate) at: Instant,
    /// The factor, between 0.75 and 1.25, that spreads the refresh period after this flood.
    pub(crate) spread: f64,
}

impl PeerInfoFlood {
    /// A flood at `at`, with a spread drawn at random.
    pub(crate) fn at(at: Instant) -> Self {
        Self {
            at,
            spread: rand::Rng::random_range(&mut rand::rng(), 0.75..=1.25),
        }
    }
}
