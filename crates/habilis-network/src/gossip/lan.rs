use iroh::EndpointAddr;

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::lookup::LanEvent;
use crate::util::clock::Instant;

use crate::lookup;
mod lan_grafts;

pub(crate) use lan_grafts::LanGrafts;

/// Act on what the LAN says about a member of this mesh: ask it to be a neighbor, before any
/// beacon is claimed.
pub(crate) async fn on_lan_event(
    event: LanEvent,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    match event {
        LanEvent::Seen(address) => {
            let linked = state.linked_endpoints.contains(&address.id);
            if !linked {
                state.note_second_group_sign(context.endpoint.id(), Instant::now());
            }
            if state.lan_grafts.plan(&address, linked, Instant::now()) {
                ask(address, state, context).await;
            }
        }
        LanEvent::Gone(id) => state.lan_grafts.forget(&id),
    }
}

/// Ask again the members of the LAN that were asked and are still not neighbors, once their wait
/// is over. The LAN does not repeat a record that did not change, so no event comes for them.
pub(crate) async fn ask_unlinked_again(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    for address in state.lan_grafts.asked_records() {
        let linked = state.linked_endpoints.contains(&address.id);
        if state.lan_grafts.plan(&address, linked, Instant::now()) {
            ask(address, state, context).await;
        }
    }
}

/// Ask one member of the LAN to be a neighbor. An error only logs: the record stays, and the
/// member is asked again when its wait is over.
async fn ask(address: EndpointAddr, state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    let peer = address.id;
    lookup::add_peer_addr(&state.address_book, address);
    if let Err(error) = context.sender.neighbor_peers(vec![peer]).await {
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
    use crate::daemon::state::RendezvousFlag;
    use std::time::Duration;

    use iroh::{EndpointAddr, SecretKey};

    use super::LanGrafts;
    use super::lan_grafts::{GRAFT_WINDOW, MAX_LAN_GRAFTS_PER_MINUTE, RETRY_FIRST, RETRY_STEADY};
    use crate::util::clock::Instant;

    fn member(seed: u8) -> EndpointAddr {
        EndpointAddr::new(SecretKey::from_bytes(&[seed; 32]).public())
    }

    #[test]
    fn a_member_is_asked_once_for_one_record() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let address = member(1);
        assert!(
            grafts.plan(&address, false, now),
            "a member is asked for a record the first time"
        );
        assert!(
            !grafts.plan(&address, false, now),
            "a member is not asked again for the same record at once"
        );
    }

    #[test]
    fn a_changed_record_is_asked_again() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let address = member(1);
        assert!(
            grafts.plan(&address, false, now),
            "a changed record is asked for again"
        );
        let moved = address.with_ip_addr("192.0.2.1:4000".parse().expect("an address"));
        assert!(
            grafts.plan(&moved, false, now),
            "a moved record is asked for again"
        );
    }

    #[test]
    fn a_linked_member_is_not_asked() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut grafts = LanGrafts::default();
        assert!(
            !grafts.plan(&member(1), true, Instant::now()),
            "a linked member is not asked"
        );
    }

    #[test]
    fn a_member_that_left_is_asked_again_when_it_returns() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let address = member(1);
        assert!(
            grafts.plan(&address, false, now),
            "a member that left is asked again when it returns"
        );
        grafts.forget(&address.id);
        assert!(
            grafts.plan(&address, false, now),
            "the returning member is asked again"
        );
    }

    #[test]
    fn a_member_that_is_still_not_a_neighbor_is_asked_again_after_a_wait() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let address = member(1);
        assert!(
            grafts.plan(&address, false, now),
            "a member still not a neighbor is asked again after a wait"
        );
        assert!(
            !grafts.plan(
                &address,
                false,
                now + RETRY_FIRST.saturating_sub(Duration::from_secs(1))
            ),
            "the wait is not over"
        );
        assert!(
            grafts.plan(&address, false, now + RETRY_FIRST),
            "the request may have been refused or lost, and the record will not change again"
        );
    }

    #[test]
    fn the_wait_between_two_requests_grows_to_a_steady_one() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let address = member(1);
        assert!(
            grafts.plan(&address, false, now),
            "the first request goes out at once"
        );
        let second = now + RETRY_FIRST;
        assert!(
            grafts.plan(&address, false, second),
            "the second request goes out at its wait"
        );
        assert!(
            !grafts.plan(&address, false, second + RETRY_FIRST),
            "after the first wait the steady one holds"
        );
        assert!(
            grafts.plan(&address, false, second + RETRY_STEADY),
            "the request after the wait is steady"
        );
    }

    #[test]
    fn a_member_that_is_a_neighbor_is_not_asked_again() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let address = member(1);
        assert!(
            grafts.plan(&address, false, now),
            "the first request for a neighbor member goes out"
        );
        assert!(
            !grafts.plan(&address, true, now + RETRY_FIRST),
            "a neighbor member is not asked again after the first wait"
        );
    }

    #[test]
    fn a_request_that_is_asked_again_counts_against_the_cap() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        let first = member(1);
        assert!(
            grafts.plan(&first, false, now),
            "the first request counts against the cap"
        );
        let later = now + RETRY_FIRST;
        for seed in 0..MAX_LAN_GRAFTS_PER_MINUTE {
            let seed = u8::try_from(seed).expect("a small count");
            assert!(
                grafts.plan(&member(100 + seed), false, later),
                "a second member's request is allowed under the cap"
            );
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
    fn a_request_that_returned_an_error_is_asked_again_after_the_wait() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::lookup::LanEvent;
            use crate::testing::{LaneNode, LogCapture};

            const FAILED: &str = "the request to a member to be a neighbor failed";
            let (logs, _guard) = LogCapture::start(tracing::Level::WARN);
            let node = LaneNode::start().await;
            node.stop_gossip().await;
            let context = node.context();
            let mut state = node.state();
            let address = member(1);

            super::on_lan_event(LanEvent::Seen(address.clone()), &mut state, &context).await;
            assert_eq!(
                logs.text().matches(FAILED).count(),
                1,
                "the first request returned an error"
            );

            super::ask_unlinked_again(&mut state, &context).await;
            assert_eq!(
                logs.text().matches(FAILED).count(),
                1,
                "the wait is not over, so nothing is asked"
            );

            let asked = state
                .lan_grafts
                .asked
                .get_mut(&address.id)
                .expect("the record stays after an error");
            asked.at = asked
                .at
                .checked_sub(RETRY_FIRST)
                .expect("an instant that is earlier");
            super::ask_unlinked_again(&mut state, &context).await;
            assert_eq!(
                logs.text().matches(FAILED).count(),
                2,
                "the member is asked again once its wait is over"
            );
        });
    }

    /// A member of this mesh that the LAN names and that is not a neighbor is a sign that
    /// another group of the mesh may exist: the re-check of a holder comes back to its fast base.
    #[cfg(feature = "host")]
    #[test]
    fn a_member_of_the_lan_that_is_not_a_neighbor_is_a_sign_of_a_second_group() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::lookup::LanEvent;
            use crate::testing::LaneNode;

            let node = LaneNode::start().await;
            let context = node.context();
            let mut state = node.state();
            state
                .rendezvous_flags
                .insert(RendezvousFlag::HostsRendezvous);
            let far = Instant::now() + Duration::from_hours(1);
            state.next_rival_recheck = Some(far);

            super::on_lan_event(LanEvent::Seen(member(1)), &mut state, &context).await;

            assert!(
                state.next_rival_recheck.is_some_and(|next| next < far),
                "the re-check came back from an hour out"
            );
            node.stop_gossip().await;
            node.endpoint.close().await;
        });
    }

    #[cfg(feature = "host")]
    #[test]
    fn a_member_of_the_lan_that_is_a_neighbor_is_no_sign() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            use crate::lookup::LanEvent;
            use crate::testing::LaneNode;

            let node = LaneNode::start().await;
            let context = node.context();
            let mut state = node.state();
            state
                .rendezvous_flags
                .insert(RendezvousFlag::HostsRendezvous);
            let far = Instant::now() + Duration::from_hours(1);
            state.next_rival_recheck = Some(far);
            let address = member(1);
            state.linked_endpoints.insert(address.id);

            super::on_lan_event(LanEvent::Seen(address), &mut state, &context).await;

            assert_eq!(
                state.next_rival_recheck,
                Some(far),
                "the lan neighbor leaves the re-check time at its far value"
            );
            node.stop_gossip().await;
            node.endpoint.close().await;
        });
    }

    #[test]
    fn the_requests_of_one_minute_are_capped() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut grafts = LanGrafts::default();
        let now = Instant::now();
        for seed in 0..MAX_LAN_GRAFTS_PER_MINUTE {
            let seed = u8::try_from(seed).expect("a small count");
            assert!(
                grafts.plan(&member(seed), false, now),
                "the first requests of one minute are allowed"
            );
        }
        assert!(
            !grafts.plan(&member(200), false, now),
            "requests beyond the cap of one minute are refused"
        );
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
