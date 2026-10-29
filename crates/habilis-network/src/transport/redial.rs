//! Tests only: how often a peer is reconnected soon after a connection to it closed.
//!
//! The idle close of a connection saves memory, and costs a dial when the peer is needed
//! again. A harness that samples the peers (once per second is enough) counts, for plain
//! QUIC connections and for `WebRTC` sessions apart, the closes and the reconnects within
//! [`REDIAL_WINDOW`] of a close. The share of closes that are followed by a reconnect says
//! whether the idle timeout is too short for the traffic.

mod redials;
pub(crate) use redials::Redials;
mod track;

#[cfg(test)]
mod tests {
    use super::track::Track;
    use crate::testing;
    use crate::util::clock::Instant;
    use std::time::Duration;

    fn after(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    #[test]
    fn a_connection_that_comes_back_soon_after_a_close_is_a_redial() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut track, peer, start) = (Track::default(), testing::endpoint_id(1), Instant::now());
        track.observe(start, peer, true);
        track.observe(after(start, 130), peer, false);
        track.observe(after(start, 190), peer, true);
        assert_eq!(
            (track.closes(), track.redials()),
            (1, 1),
            "a quick return after a close is one redial"
        );
    }

    #[test]
    fn a_connection_that_comes_back_after_the_window_is_not_a_redial() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut track, peer, start) = (Track::default(), testing::endpoint_id(1), Instant::now());
        track.observe(start, peer, true);
        track.observe(after(start, 130), peer, false);
        track.observe(after(start, 130 + 301), peer, true);
        assert_eq!(
            (track.closes(), track.redials()),
            (1, 0),
            "a return after the window is not a redial"
        );
    }

    #[test]
    fn the_first_connection_of_a_peer_is_not_a_redial() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut track, peer, start) = (Track::default(), testing::endpoint_id(1), Instant::now());
        track.observe(start, peer, true);
        track.observe(after(start, 1), peer, true);
        assert_eq!(
            (track.closes(), track.redials()),
            (0, 0),
            "the first connection of a peer is not a redial"
        );
    }

    #[test]
    fn each_peer_is_counted_on_its_own() {
        let _guard = ::habilis_network_test_tracing::init();
        let (mut track, start) = (Track::default(), Instant::now());
        let (one, two) = (testing::endpoint_id(1), testing::endpoint_id(2));
        track.observe(start, one, true);
        track.observe(start, two, true);
        track.observe(after(start, 10), one, false);
        track.observe(after(start, 20), one, true);
        track.observe(after(start, 30), two, false);
        assert_eq!(
            (track.closes(), track.redials()),
            (2, 1),
            "each peer is counted on its own"
        );
    }
}
