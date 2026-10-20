//! Tests only: how often a peer is reconnected soon after a connection to it closed.
//!
//! The idle close of a connection saves memory, and costs a dial when the peer is needed
//! again. A harness that samples the peers (once per second is enough) counts, for plain
//! QUIC connections and for `WebRTC` sessions apart, the closes and the reconnects within
//! [`REDIAL_WINDOW`] of a close. The share of closes that are followed by a reconnect says
//! whether the idle timeout is too short for the traffic.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use iroh::EndpointId;

use crate::util::clock::Instant;

/// A connection that comes back within this long of a close is a re-dial.
pub(crate) const REDIAL_WINDOW: Duration = Duration::from_mins(5);

/// The closes and re-dials of one kind of direct connection.
#[derive(Debug, Default)]
pub(crate) struct Track {
    present: HashSet<EndpointId>,
    closed_at: HashMap<EndpointId, Instant>,
    closes: u64,
    redials: u64,
}

impl Track {
    /// Note whether `peer` holds a connection of this kind at `now`.
    pub(crate) fn observe(&mut self, now: Instant, peer: EndpointId, present: bool) {
        let was_present = self.present.contains(&peer);
        if was_present && !present {
            self.present.remove(&peer);
            self.closed_at.insert(peer, now);
            self.closes += 1;
        } else if !was_present && present {
            self.present.insert(peer);
            let soon = self
                .closed_at
                .get(&peer)
                .is_some_and(|closed| now.duration_since(*closed) <= REDIAL_WINDOW);
            self.redials += u64::from(soon);
        }
    }

    pub(crate) fn closes(&self) -> u64 {
        self.closes
    }

    pub(crate) fn redials(&self) -> u64 {
        self.redials
    }
}

/// The three tracks of a node: every live QUIC connection (the gossip links too), the pooled
/// unicast connections that a send used, and the `WebRTC` sessions.
#[derive(Debug, Default)]
pub(crate) struct Redials {
    pub(crate) quic: Track,
    pub(crate) pool: Track,
    pub(crate) session: Track,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::endpoint_id;

    fn after(start: Instant, secs: u64) -> Instant {
        start + Duration::from_secs(secs)
    }

    #[test]
    fn a_connection_that_comes_back_soon_after_a_close_is_a_redial() {
        let (mut track, peer, start) = (Track::default(), endpoint_id(1), Instant::now());
        track.observe(start, peer, true);
        track.observe(after(start, 130), peer, false);
        track.observe(after(start, 190), peer, true);
        assert_eq!((track.closes(), track.redials()), (1, 1));
    }

    #[test]
    fn a_connection_that_comes_back_after_the_window_is_not_a_redial() {
        let (mut track, peer, start) = (Track::default(), endpoint_id(1), Instant::now());
        track.observe(start, peer, true);
        track.observe(after(start, 130), peer, false);
        track.observe(after(start, 130 + 301), peer, true);
        assert_eq!((track.closes(), track.redials()), (1, 0));
    }

    #[test]
    fn the_first_connection_of_a_peer_is_not_a_redial() {
        let (mut track, peer, start) = (Track::default(), endpoint_id(1), Instant::now());
        track.observe(start, peer, true);
        track.observe(after(start, 1), peer, true);
        assert_eq!((track.closes(), track.redials()), (0, 0));
    }

    #[test]
    fn each_peer_is_counted_on_its_own() {
        let (mut track, start) = (Track::default(), Instant::now());
        let (one, two) = (endpoint_id(1), endpoint_id(2));
        track.observe(start, one, true);
        track.observe(start, two, true);
        track.observe(after(start, 10), one, false);
        track.observe(after(start, 20), one, true);
        track.observe(after(start, 30), two, false);
        assert_eq!((track.closes(), track.redials()), (2, 1));
    }
}
