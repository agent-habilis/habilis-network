use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use iroh::{EndpointAddr, EndpointId};

use crate::util::clock::Instant;

/// How many members one node asks to be its neighbor in one minute. A LAN with many members
/// announces them all at once, and the overlay needs a few links, not one to each.
pub(super) const MAX_LAN_GRAFTS_PER_MINUTE: usize = 8;

pub(super) const GRAFT_WINDOW: Duration = Duration::from_mins(1);

/// How long a member that is still not a neighbor waits before it is asked a second time. A
/// request can be refused (a full view refuses a low-priority one) or lost, and the record of the
/// member does not change again, so without a second request the member stays outside.
pub(super) const RETRY_FIRST: Duration = Duration::from_mins(1);

/// How long such a member waits between the later requests.
pub(super) const RETRY_STEADY: Duration = Duration::from_mins(5);

/// A member that was asked: the record it had, when it was asked last, and how often again.
#[derive(Debug)]
pub(super) struct Asked {
    address: EndpointAddr,
    pub(super) at: Instant,
    again: u32,
}

impl Asked {
    /// How long to wait after the last request before the next one: `RETRY_FIRST` after the first
    /// request, `RETRY_STEADY` after each later one.
    fn wait(&self) -> Duration {
        if self.again == 0 {
            RETRY_FIRST
        } else {
            RETRY_STEADY
        }
    }
}

/// What this node already asked of the members it heard on the LAN.
#[derive(Debug, Default)]
pub(crate) struct LanGrafts {
    /// The record each member had when we asked it. The same record is asked again only after
    /// its wait, and only while the member is not a neighbor; a changed one is asked at once: the
    /// first request can fail on an address that was not complete yet.
    pub(super) asked: HashMap<EndpointId, Asked>,
    recent: VecDeque<Instant>,
}

impl LanGrafts {
    /// Whether to ask the member at `addr` to be a neighbor now. `linked` is whether it already is
    /// one. A `true` counts against the cap.
    pub(crate) fn plan(&mut self, address: &EndpointAddr, linked: bool, now: Instant) -> bool {
        let known = self
            .asked
            .get_mut(&address.id)
            .filter(|asked| asked.address == *address);
        let again = match known {
            Some(asked) if linked => {
                // A neighbor now: if the link is lost later, the wait starts from the first one.
                asked.at = now;
                asked.again = 0;
                return false;
            }
            Some(asked) if now.saturating_duration_since(asked.at) < asked.wait() => return false,
            Some(asked) => asked.again.saturating_add(1),
            None if linked => return false,
            None => 0,
        };
        while self
            .recent
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= GRAFT_WINDOW)
        {
            self.recent.pop_front();
        }
        if self.recent.len() >= MAX_LAN_GRAFTS_PER_MINUTE {
            return false;
        }
        self.recent.push_back(now);
        self.asked.insert(
            address.id,
            Asked {
                address: address.clone(),
                at: now,
                again,
            },
        );
        true
    }

    /// The records of the members that were asked, for the tick that asks again.
    pub(crate) fn asked_records(&self) -> Vec<EndpointAddr> {
        self.asked
            .values()
            .map(|asked| asked.address.clone())
            .collect()
    }

    /// The LAN says the member is gone: a later announcement is news again.
    pub(crate) fn forget(&mut self, id: &EndpointId) {
        self.asked.remove(id);
    }
}
