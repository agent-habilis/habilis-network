//! The idle-close window of a unicast connection, and the redial counter.

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
