use std::ops::RangeInclusive;

use crate::util::clock::Instant;

/// The range of the factor that spreads the refresh period after a flood. No factor is below 1.0,
/// so a mesh of any size sends at most 1 refresh per `PEERINFO_REFRESH_PER_PEER`, and not only on
/// average. A factor below 1.0 would break that bound.
const SPREAD: RangeInclusive<f64> = 1.0..=1.5;

/// When our `PeerInfo` last went out, and how far its refresh is spread. The flood has a spread of
/// its own, so the members of a mesh that flood together do not refresh together.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerInfoFlood {
    /// When the flood went out, whatever triggered it.
    pub(crate) at: Instant,
    /// The factor, within [`SPREAD`], that spreads the refresh period after this flood.
    pub(crate) spread: f64,
}

impl PeerInfoFlood {
    /// A flood at `at`, with a spread drawn at random.
    pub(crate) fn at(at: Instant) -> Self {
        Self {
            at,
            spread: rand::Rng::random_range(&mut rand::rng(), SPREAD),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PeerInfoFlood, SPREAD};
    use crate::util::clock::Instant;
    use crate::util::tuning::{PEERINFO_REFRESH_PER_PEER, peerinfo_refresh_period};

    /// The stated bound of the refresh: the mesh sends at most 1 refresh per
    /// `PEERINFO_REFRESH_PER_PEER`. Each of `members` nodes refreshes once per period, and the
    /// shortest period is the period of the roster times the least spread.
    #[test]
    fn the_shortest_refresh_period_keeps_the_mesh_bound() {
        let _guard = ::habilis_network_test_tracing::init();
        for members in [60_usize, 100, 1000] {
            let shortest = peerinfo_refresh_period(members).mul_f64(*SPREAD.start());
            let per_refresh = shortest / u32::try_from(members).expect("a small count");
            assert!(
                per_refresh >= PEERINFO_REFRESH_PER_PEER,
                "{members} members refresh once per {per_refresh:?}, faster than {PEERINFO_REFRESH_PER_PEER:?}"
            );
        }
    }

    #[test]
    fn a_drawn_spread_stays_in_the_range() {
        let _guard = ::habilis_network_test_tracing::init();
        let now = Instant::now();
        for _ in 0..1000 {
            let flood = PeerInfoFlood::at(now);
            assert!(
                SPREAD.contains(&flood.spread),
                "the spread {} is outside {SPREAD:?}",
                flood.spread
            );
        }
    }
}
