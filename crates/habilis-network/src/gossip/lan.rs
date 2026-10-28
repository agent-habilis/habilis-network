use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use iroh::{EndpointAddr, EndpointId};

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::lookup::LanEvent;
use crate::util::clock::Instant;

/// How many members one node asks to be its neighbor in one minute. A LAN with many members
/// announces them all at once, and the overlay needs a few links, not one to each.
pub(crate) const MAX_LAN_GRAFTS_PER_MINUTE: usize = 8;

const GRAFT_WINDOW: Duration = Duration::from_mins(1);

/// How long a member that is still not a neighbor waits before it is asked a second time. A
/// request can be refused (a full view refuses a low-priority one) or lost, and the record of the
/// member does not change again, so without a second request the member stays outside.
const RETRY_FIRST: Duration = Duration::from_mins(1);

/// How long such a member waits between the later requests.
const RETRY_STEADY: Duration = Duration::from_mins(5);

/// A member that was asked: the record it had, when it was asked last, and how often again.
#[derive(Debug)]
struct Asked {
    addr: EndpointAddr,
    at: Instant,
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
    asked: HashMap<EndpointId, Asked>,
    recent: VecDeque<Instant>,
}

impl LanGrafts {
    /// Whether to ask the member at `addr` to be a neighbor now. `linked` is whether it already is
    /// one. A `true` counts against the cap.
    pub(crate) fn plan(&mut self, addr: &EndpointAddr, linked: bool, now: Instant) -> bool {
        let known = self
            .asked
            .get_mut(&addr.id)
            .filter(|asked| asked.addr == *addr);
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
            addr.id,
            Asked {
                addr: addr.clone(),
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
            .map(|asked| asked.addr.clone())
            .collect()
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
            if !linked {
                state.note_second_group_sign(ctx.endpoint.id(), Instant::now());
            }
            if state.lan_grafts.plan(&addr, linked, Instant::now()) {
                ask(addr, state, ctx).await;
            }
        }
        LanEvent::Gone(id) => state.lan_grafts.forget(&id),
    }
}

/// Ask again the members of the LAN that were asked and are still not neighbors, once their wait
/// is over. The LAN does not repeat a record that did not change, so no event comes for them.
pub(crate) async fn ask_unlinked_again(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
    for addr in state.lan_grafts.asked_records() {
        let linked = state.linked_endpoints.contains(&addr.id);
        if state.lan_grafts.plan(&addr, linked, Instant::now()) {
            ask(addr, state, ctx).await;
        }
    }
}

/// Ask one member of the LAN to be a neighbor. An error only logs: the record stays, and the
/// member is asked again when its wait is over.
async fn ask(addr: EndpointAddr, state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
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

#[cfg(test)]
mod tests {
    use habilis_network_test_tracing::test;
    use std::time::Duration;

    use iroh::{EndpointAddr, SecretKey};

    use super::{GRAFT_WINDOW, LanGrafts, MAX_LAN_GRAFTS_PER_MINUTE, RETRY_FIRST, RETRY_STEADY};
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
    fn a_member_that_is_still_not_a_neighbor_is_asked_again_after_a_wait() {
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let addr = member(1);
        assert!(grafts.plan(&addr, false, now));
        assert!(
            !grafts.plan(
                &addr,
                false,
                now + RETRY_FIRST.saturating_sub(Duration::from_secs(1))
            ),
            "the wait is not over"
        );
        assert!(
            grafts.plan(&addr, false, now + RETRY_FIRST),
            "the request may have been refused or lost, and the record will not change again"
        );
    }

    #[test]
    fn the_wait_between_two_requests_grows_to_a_steady_one() {
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let addr = member(1);
        assert!(grafts.plan(&addr, false, now));
        let second = now + RETRY_FIRST;
        assert!(grafts.plan(&addr, false, second));
        assert!(
            !grafts.plan(&addr, false, second + RETRY_FIRST),
            "after the first wait the steady one holds"
        );
        assert!(grafts.plan(&addr, false, second + RETRY_STEADY));
    }

    #[test]
    fn a_member_that_is_a_neighbor_is_not_asked_again() {
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let addr = member(1);
        assert!(grafts.plan(&addr, false, now));
        assert!(!grafts.plan(&addr, true, now + RETRY_FIRST));
    }

    #[test]
    fn a_request_that_is_asked_again_counts_against_the_cap() {
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let first = member(1);
        assert!(grafts.plan(&first, false, now));
        let later = now + RETRY_FIRST;
        for seed in 0..MAX_LAN_GRAFTS_PER_MINUTE {
            let seed = u8::try_from(seed).expect("a small count");
            assert!(grafts.plan(&member(100 + seed), false, later));
        }
        assert!(
            !grafts.plan(&first, false, later),
            "the cap of the minute is spent, so the second request waits"
        );
    }

    /// A request that returned an error is asked again once its wait is over. The error only
    /// logs: the record stays, and the tick of the heal arm asks the member again.
    #[cfg(all(feature = "host", feature = "multihop"))]
    #[test]
    async fn a_request_that_returned_an_error_is_asked_again_after_the_wait() {
        use crate::lookup::LanEvent;
        use crate::testing::{LaneNode, LogCapture};

        const FAILED: &str = "the request to a member to be a neighbor failed";
        let (logs, _guard) = LogCapture::start(tracing::Level::WARN);
        let node = LaneNode::start().await;
        node.stop_gossip().await;
        let ctx = node.ctx();
        let mut state = node.state();
        let addr = member(1);

        super::on_lan_event(LanEvent::Seen(addr.clone()), &mut state, &ctx).await;
        assert_eq!(
            logs.text().matches(FAILED).count(),
            1,
            "the first request returned an error"
        );

        super::ask_unlinked_again(&mut state, &ctx).await;
        assert_eq!(
            logs.text().matches(FAILED).count(),
            1,
            "the wait is not over, so nothing is asked"
        );

        let asked = state
            .lan_grafts
            .asked
            .get_mut(&addr.id)
            .expect("the record stays after an error");
        asked.at = asked
            .at
            .checked_sub(RETRY_FIRST)
            .expect("an instant that is earlier");
        super::ask_unlinked_again(&mut state, &ctx).await;
        assert_eq!(
            logs.text().matches(FAILED).count(),
            2,
            "the member is asked again once its wait is over"
        );
    }

    /// A member of this mesh that the LAN names and that is not a neighbor is a sign that
    /// another group of the mesh may exist: the re-check of a holder comes back to its fast base.
    #[cfg(feature = "host")]
    #[test]
    async fn a_member_of_the_lan_that_is_not_a_neighbor_is_a_sign_of_a_second_group() {
        use crate::lookup::LanEvent;
        use crate::testing::LaneNode;

        let node = LaneNode::start().await;
        let ctx = node.ctx();
        let mut state = node.state();
        state.hosts_rendezvous = true;
        let far = Instant::now() + Duration::from_hours(1);
        state.next_rival_recheck = Some(far);

        super::on_lan_event(LanEvent::Seen(member(1)), &mut state, &ctx).await;

        assert!(
            state.next_rival_recheck.is_some_and(|next| next < far),
            "the re-check came back from an hour out"
        );
        node.stop_gossip().await;
        node.endpoint.close().await;
    }

    #[cfg(feature = "host")]
    #[test]
    async fn a_member_of_the_lan_that_is_a_neighbor_is_no_sign() {
        use crate::lookup::LanEvent;
        use crate::testing::LaneNode;

        let node = LaneNode::start().await;
        let ctx = node.ctx();
        let mut state = node.state();
        state.hosts_rendezvous = true;
        let far = Instant::now() + Duration::from_hours(1);
        state.next_rival_recheck = Some(far);
        let addr = member(1);
        state.linked_endpoints.insert(addr.id);

        super::on_lan_event(LanEvent::Seen(addr), &mut state, &ctx).await;

        assert_eq!(state.next_rival_recheck, Some(far));
        node.stop_gossip().await;
        node.endpoint.close().await;
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
