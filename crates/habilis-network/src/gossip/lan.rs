use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use iroh::{EndpointAddr, EndpointId};

use crate::daemon::ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::lookup::LanEvent;
use crate::util::clock::Instant;

/// How many members one node asks to be its neighbor in one minute. A LAN with many members
/// announces them all at once, and the overlay needs a few links, not one to each.
pub(crate) const MAX_LAN_GRAFTS_PER_MINUTE: usize = 8;

const GRAFT_WINDOW: Duration = Duration::from_mins(1);

/// What this node already asked of the members it heard on the LAN.
#[derive(Debug, Default)]
pub(crate) struct LanGrafts {
    /// The record each member had when we asked it. The same record is not asked again, a changed
    /// one is: the first request can fail on an address that was not complete yet.
    asked: HashMap<EndpointId, EndpointAddr>,
    recent: VecDeque<Instant>,
}

impl LanGrafts {
    /// Whether to ask the member at `addr` to be a neighbor now. `linked` is whether it already is
    /// one. A `true` counts against the cap.
    pub(crate) fn plan(&mut self, addr: &EndpointAddr, linked: bool, now: Instant) -> bool {
        if linked || self.asked.get(&addr.id) == Some(addr) {
            return false;
        }
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
        self.asked.insert(addr.id, addr.clone());
        true
    }

    /// The LAN says the member is gone: a later announcement is news again.
    pub(crate) fn forget(&mut self, id: &EndpointId) {
        self.asked.remove(id);
    }
}

/// Act on what the LAN says about a member of this mesh: ask it to be a neighbor, before any
/// beacon is claimed.
pub(crate) async fn on_lan_event(
    event: LanEvent,
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
) {
    match event {
        LanEvent::Seen(addr) => {
            let linked = state.linked_endpoints.contains(&addr.id);
            if !state.lan_grafts.plan(&addr, linked, Instant::now()) {
                return;
            }
            let peer = addr.id;
            crate::lookup::add_peer_addr(&state.address_book, addr);
            if let Err(error) = ctx.sender.neighbor_peers(vec![peer]).await {
                tracing::warn!(
                    target: "habilis_network::lookup",
                    %error,
                    peer = %peer.fmt_short(),
                    "lan: the request to a member to be a neighbor failed"
                );
            }
        }
        LanEvent::Gone(id) => state.lan_grafts.forget(&id),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::{EndpointAddr, SecretKey};

    use super::{GRAFT_WINDOW, LanGrafts, MAX_LAN_GRAFTS_PER_MINUTE};
    use crate::util::clock::Instant;

    fn member(seed: u8) -> EndpointAddr {
        EndpointAddr::new(SecretKey::from_bytes(&[seed; 32]).public())
    }

    #[test]
    fn a_member_is_asked_once_for_one_record() {
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let addr = member(1);
        assert!(grafts.plan(&addr, false, now));
        assert!(!grafts.plan(&addr, false, now));
    }

    #[test]
    fn a_changed_record_is_asked_again() {
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let addr = member(1);
        assert!(grafts.plan(&addr, false, now));
        let moved = addr.with_ip_addr("192.0.2.1:4000".parse().expect("an address"));
        assert!(grafts.plan(&moved, false, now));
    }

    #[test]
    fn a_linked_member_is_not_asked() {
        let mut grafts = LanGrafts::default();
        assert!(!grafts.plan(&member(1), true, Instant::now()));
    }

    #[test]
    fn a_member_that_left_is_asked_again_when_it_returns() {
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let addr = member(1);
        assert!(grafts.plan(&addr, false, now));
        grafts.forget(&addr.id);
        assert!(grafts.plan(&addr, false, now));
    }

    #[test]
    fn the_requests_of_one_minute_are_capped() {
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        for seed in 0..MAX_LAN_GRAFTS_PER_MINUTE {
            let seed = u8::try_from(seed).expect("a small count");
            assert!(grafts.plan(&member(seed), false, now));
        }
        assert!(!grafts.plan(&member(200), false, now));
        assert!(
            grafts.plan(
                &member(200),
                false,
                now + GRAFT_WINDOW + Duration::from_secs(1)
            ),
            "the window frees the cap"
        );
    }
}
