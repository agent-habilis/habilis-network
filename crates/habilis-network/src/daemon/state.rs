mod event_loop_state;

mod idle_counters;
mod mesh_secrets;
mod ping_round;
mod state_init;

mod direct_counts;
mod direct_state;
#[cfg(feature = "multihop")]
mod parked_link_states;
mod reach;
mod rival_flag;
mod roster_entry;
mod roster_snapshot;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
mod test_drop;

use std::time::Duration;

use iroh::EndpointId;

use crate::util::clock;

use crate::util::tuning;

pub use event_loop_state::EventLoopState;

pub(crate) use idle_counters::IdleCounters;
pub(crate) use mesh_secrets::MeshSecrets;
pub(crate) use ping_round::PingRound;
pub(crate) use state_init::StateInit;

pub(crate) use direct_counts::DirectCounts;
pub(crate) use direct_state::DirectState;
#[cfg(feature = "multihop")]
pub(crate) use parked_link_states::ParkedLinkStates;
pub use reach::Reach;
pub(crate) use rival_flag::RivalFlag;
pub use roster_entry::RosterEntry;
pub use roster_snapshot::RosterSnapshot;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub use test_drop::TestDrop;
/// How long after it let go of the rendezvous a node wants it again. Every node waits the same
/// period, plus a share of up to half of it that the id of the node fixes: the pubkey bytes are
/// uniform, so n members do not come back together.
fn rendezvous_return_after(local: EndpointId) -> Duration {
    let period = tuning::rendezvous_periodic_return();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&local.as_bytes()[..8]);
    let share_ms = u64::from_le_bytes(prefix) % (clock::millis_saturating(period) / 2).max(1);
    period + Duration::from_millis(share_ms)
}

/// How long an author whose digest we could not read stays unreported. A build
/// that does not know the window format sends one every round, and one line per
/// author per window says it without filling the log.
const UNREADABLE_DIGEST_LOG_WINDOW: Duration = Duration::from_mins(10);

/// The most link vectors that wait for the binding of their author: one per author, and a mesh
/// holds fewer members than this. A flood of authors that never bind cannot grow the park.
#[cfg(feature = "multihop")]
const MAX_PARKED_LINK_STATES: usize = 256;

#[cfg(test)]
mod tests {
    use super::{
        DirectCounts, DirectState, Duration, EndpointId, EventLoopState, PingRound, Reach,
        RivalFlag,
    };
    use crate::protocol::{
        AppFrameParams, AuthorKey, ContentHash, MeshId, Message, MessageBody, MessageId, UnixSecs,
    };
    use crate::testing::{author_of, endpoint_id, fresh_state, fresh_state_with_book, nick};
    use crate::util::clock::Instant;
    use crate::util::tuning::{KNOWN_ENDPOINTS_CAP, QUIET_CAP, RELINK_COOLDOWN};
    use n0_future::time::Instant as TokioInstant;

    use crate::protocol::message;
    use crate::transport::probe::PathKind;
    use crate::util::tuning;
    use iroh::address_lookup::memory;
    fn lower_and_higher() -> (EndpointId, EndpointId) {
        let first = endpoint_id(1);
        let second = endpoint_id(2);
        if first < second {
            (first, second)
        } else {
            (second, first)
        }
    }

    /// Two holders of one rendezvous that share an overlay, one dependent on each: the lower
    /// holder's flag must end the split now, not after the wait for the dependent.
    #[test]
    fn a_flag_from_a_lower_holder_makes_us_yield_at_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        let now = Instant::now();

        state.note_rival_beacon_flag(
            high,
            AuthorKey::from([9u8; 32]),
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            now,
        );

        assert!(
            state.yield_to_lower,
            "a lower holder's flag makes us yield at once"
        );
        assert_eq!(
            state.next_rival_recheck,
            Some(now),
            "the re-check comes due at the current instant"
        );
    }

    /// The winner keeps its beacon. Its re-check is pushed one steady round, not dropped: a
    /// holder that never re-checks never finds a co-host it does not know of.
    #[test]
    fn a_flag_from_a_higher_holder_pushes_our_re_check_out() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        state.rival_recheck_rounds = 2;
        state.rival_recheck_deferrals = 1;
        let now = Instant::now();

        state.note_rival_beacon_flag(
            low,
            AuthorKey::from([9u8; 32]),
            high,
            RivalFlag {
                proven: true,
                held: true,
            },
            now,
        );

        assert!(
            !state.yield_to_lower,
            "a higher holder's flag does not make us yield"
        );
        let next = state
            .next_rival_recheck
            .expect("the re-check is pushed out, not dropped");
        assert!(next > now, "a steady round out, not due");
        assert_eq!(state.rival_recheck_rounds, 2, "the rounds stay");
        assert_eq!(state.rival_recheck_deferrals, 1, "the deferrals stay");
    }

    /// The longest wait that the first round of a re-check can have: its fast base plus the
    /// offset of the id.
    fn brisk_wait() -> Duration {
        tuning::rival_recheck_first() + tuning::RIVAL_RECHECK_OFFSET_SPAN
    }

    /// A holder that has found no member has a re-check an hour or two out. A sign that another
    /// group may exist is all it has to go on: the re-check comes back to the fast base, and the
    /// rounds start from it again.
    #[test]
    fn a_sign_of_a_second_group_brings_the_re_check_to_the_brisk_base() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        state.rival_recheck_rounds = 7;
        let now = Instant::now();
        state.next_rival_recheck = Some(now + Duration::from_hours(1));

        state.note_second_group_sign(endpoint_id(1), now);

        let next = state.next_rival_recheck.expect("a re-check is armed");
        assert!(
            next <= now + brisk_wait(),
            "the re-check is due within the fast base"
        );
        assert_eq!(state.rival_recheck_rounds, 0, "the rounds start again");
    }

    /// A burst of members that arrive must not shed the beacon again and again.
    #[test]
    fn a_second_sign_inside_one_steady_interval_changes_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        let now = Instant::now();
        let far = now + Duration::from_hours(1);
        state.next_rival_recheck = Some(far);
        state.note_second_group_sign(endpoint_id(1), now);
        assert!(
            state.next_rival_recheck.is_some_and(|next| next < far),
            "the first sign counts"
        );

        state.next_rival_recheck = Some(far);
        state.rival_recheck_rounds = 3;
        state.note_second_group_sign(endpoint_id(1), now + Duration::from_secs(10));

        assert_eq!(
            state.next_rival_recheck,
            Some(far),
            "a second sign inside one steady interval keeps the first re-check time"
        );
        assert_eq!(
            state.rival_recheck_rounds, 3,
            "the round count does not move on a second sign inside one interval"
        );
    }

    #[test]
    fn a_sign_changes_nothing_while_we_do_not_hold_the_beacon() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let now = Instant::now();
        let far = now + Duration::from_hours(1);
        state.next_rival_recheck = Some(far);

        state.note_second_group_sign(endpoint_id(1), now);

        assert_eq!(
            state.next_rival_recheck,
            Some(far),
            "a sign while we do not hold the beacon leaves the re-check time alone"
        );
    }

    /// A loopback room has no re-check, and the creator never has one: a sign arms nothing.
    #[test]
    fn a_sign_arms_no_re_check_where_none_applies() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        state.next_rival_recheck = None;

        state.note_second_group_sign(endpoint_id(1), Instant::now());

        assert_eq!(
            state.next_rival_recheck, None,
            "no re-check is armed where none applies"
        );
    }

    #[test]
    fn a_sign_does_not_push_out_a_re_check_that_is_due_sooner() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        state.rival_recheck_rounds = 4;
        let now = Instant::now();
        let soon = now + Duration::from_secs(1);
        state.next_rival_recheck = Some(soon);

        state.note_second_group_sign(endpoint_id(1), now);

        assert_eq!(
            state.next_rival_recheck,
            Some(soon),
            "a sign does not push out a re-check that is due sooner"
        );
        assert_eq!(
            state.rival_recheck_rounds, 4,
            "the round count does not advance for a re-check that is not due"
        );
    }

    /// A flag is remembered only from a proven sender that is not us, and moves our re-check
    /// only while we hold the beacon.
    #[test]
    fn a_flag_that_does_not_count_changes_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = lower_and_higher();
        let signer = AuthorKey::from([9u8; 32]);
        let now = Instant::now();

        let mut no_flag = fresh_state();
        no_flag.hosts_rendezvous = true;
        no_flag.note_rival_beacon_flag(
            high,
            signer,
            low,
            RivalFlag {
                proven: true,
                held: false,
            },
            now,
        );

        let mut unproven = fresh_state();
        unproven.hosts_rendezvous = true;
        unproven.note_rival_beacon_flag(
            high,
            signer,
            low,
            RivalFlag {
                proven: false,
                held: true,
            },
            now,
        );

        let mut ourselves = fresh_state();
        ourselves.hosts_rendezvous = true;
        ourselves.note_rival_beacon_flag(
            high,
            signer,
            high,
            RivalFlag {
                proven: true,
                held: true,
            },
            now,
        );

        for state in [no_flag, unproven, ourselves] {
            assert!(
                !state.yield_to_lower,
                "a flag that does not count does not make us yield"
            );
            assert_eq!(
                state.next_rival_recheck, None,
                "a flag that does not count arms no re-check"
            );
            assert!(
                !state.rival_holder_known(),
                "a flag that does not count is not remembered as a rival holder"
            );
        }
    }

    /// A node that does not hold the rendezvous still learns who does: it is what keeps it from
    /// probing to claim. Its own re-check has nothing to move.
    #[test]
    fn a_flag_read_while_we_do_not_hold_is_remembered() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();

        state.note_rival_beacon_flag(
            high,
            AuthorKey::from([9u8; 32]),
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );

        assert!(
            state.rival_holder_known(),
            "a flag read while we do not hold the beacon is remembered"
        );
        assert!(
            !state.yield_to_lower,
            "a flag read while we do not hold the beacon does not make us yield"
        );
        assert_eq!(
            state.next_rival_recheck, None,
            "a flag read while we do not hold the beacon arms no re-check"
        );
    }

    /// A member that let go of the rendezvous and reads a holder that no member of its mesh hosts
    /// owes a return, and the debt opens the reclaim window that pays it.
    #[test]
    fn a_holder_outside_the_mesh_owes_a_return_to_a_released_member() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state.linked_endpoints.insert(endpoint_id(1));
        assert!(!state.rendezvous_wanted(), "enough links: it let go");

        state.note_holder_outside_mesh(Instant::now());

        assert!(state.rendezvous_wanted(), "a return is owed");
        assert!(state.reclaim_until.is_some(), "the reclaim ticker pays it");
    }

    /// The healthy case, which every released member reads on every heal tick: the holder is a
    /// member of our own mesh, and its flag is known. Nothing is owed, or the mesh would visit the
    /// rendezvous for ever.
    #[test]
    fn a_holder_of_our_own_mesh_owes_nothing() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state.linked_endpoints.insert(endpoint_id(1));
        state.note_rival_beacon_flag(
            high,
            AuthorKey::from([9u8; 32]),
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );
        assert!(
            state.rival_holder_known(),
            "a holder of our own mesh still records a rival flag"
        );

        state.note_holder_outside_mesh(Instant::now());

        assert!(
            state.rendezvous_comeback_until.is_none(),
            "no comeback window is owed on our own mesh"
        );
        assert!(
            !state.rendezvous_wanted(),
            "the rendezvous is not wanted on our own mesh"
        );
    }

    /// A member that still holds the link, or hosts the beacon, or wants the rendezvous anyway
    /// (it has fewer links than the release count) owes nothing: a joiner would otherwise stay
    /// a dwell longer at every start.
    #[test]
    fn a_member_that_has_the_link_or_wants_it_anyway_owes_no_return() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut linked = fresh_state();
        linked.rendezvous_release_links = 1;
        linked.linked_endpoints.insert(endpoint_id(1));
        linked.rendezvous_linked = true;
        linked.note_holder_outside_mesh(Instant::now());
        assert!(
            linked.rendezvous_comeback_until.is_none(),
            "it holds the link"
        );

        let mut host = fresh_state();
        host.rendezvous_release_links = 1;
        host.linked_endpoints.insert(endpoint_id(1));
        host.hosts_rendezvous = true;
        host.note_holder_outside_mesh(Instant::now());
        assert!(host.rendezvous_comeback_until.is_none(), "it hosts it");

        let mut joiner = fresh_state();
        joiner.note_holder_outside_mesh(Instant::now());
        assert!(
            joiner.rendezvous_comeback_until.is_none(),
            "it wants it anyway"
        );
    }

    /// A debt that is owed is not moved by the next read: the window runs out on its own, and a
    /// read after it owes once again. Without this a node that reads the holder on every heal
    /// tick would hold the debt open for ever.
    #[test]
    fn a_second_read_inside_the_window_does_not_move_it() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.rendezvous_release_links = 1;
        state.linked_endpoints.insert(endpoint_id(1));
        let first = Instant::now();
        state.note_holder_outside_mesh(first);
        let due = state.rendezvous_comeback_until;
        assert!(due.is_some(), "the first read opens a comeback window");

        state.note_holder_outside_mesh(first + Duration::from_secs(5));

        assert_eq!(
            state.rendezvous_comeback_until, due,
            "a second read keeps the deadline of the window"
        );
    }

    /// A holder that crashes never says that it let go. Its flag goes with the member.
    #[test]
    fn the_flag_of_a_forgotten_member_is_dropped() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.note_rival_beacon_flag(
            high,
            AuthorKey::from([1u8; 32]),
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );
        state.note_rival_beacon_flag(
            high,
            AuthorKey::from([2u8; 32]),
            endpoint_id(7),
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );

        state.forget_rival_holder(low);

        assert!(state.rival_holder_known(), "the other holder stays");
        state.forget_rival_holder(endpoint_id(7));
        assert!(
            !state.rival_holder_known(),
            "a forgotten member takes its rival flag with it"
        );
    }

    /// A holder that sends its flag again and again must not keep our re-check away: the push
    /// happens once per holder, and exists only to hold our release until the higher one yields.
    #[test]
    fn a_holder_that_repeats_its_flag_pushes_our_re_check_out_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        let first = Instant::now();

        state.note_rival_beacon_flag(
            low,
            AuthorKey::from([9u8; 32]),
            high,
            RivalFlag {
                proven: true,
                held: true,
            },
            first,
        );
        let pushed = state.next_rival_recheck;
        assert!(pushed.is_some_and(|due| due > first), "pushed out once");

        state.note_rival_beacon_flag(
            low,
            AuthorKey::from([9u8; 32]),
            high,
            RivalFlag {
                proven: true,
                held: true,
            },
            first + Duration::from_secs(5),
        );

        assert_eq!(
            state.next_rival_recheck, pushed,
            "the repeat changes nothing"
        );
    }

    /// The push is to at least a steady round out. A re-check that is already later stays.
    #[test]
    fn a_push_never_brings_a_later_re_check_closer() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = lower_and_higher();
        let mut state = fresh_state();
        state.hosts_rendezvous = true;
        let now = Instant::now();
        let far = now + Duration::from_secs(100_000);
        state.next_rival_recheck = Some(far);

        state.note_rival_beacon_flag(
            low,
            AuthorKey::from([9u8; 32]),
            high,
            RivalFlag {
                proven: true,
                held: true,
            },
            now,
        );

        assert_eq!(
            state.next_rival_recheck,
            Some(far),
            "a later push never brings the re-check closer"
        );
    }

    /// The holder says it let go (a `PeerInfo` without the flag), or the member leaves: the
    /// rendezvous is no longer known to be held by it.
    #[test]
    fn a_holder_stops_counting_when_it_drops_the_flag_or_leaves() {
        let _guard = ::habilis_network_test_tracing::init();
        let (low, high) = lower_and_higher();
        let signer = AuthorKey::from([9u8; 32]);
        let mut state = fresh_state();
        state.note_rival_beacon_flag(
            high,
            signer,
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );
        assert!(
            state.rival_holder_known(),
            "a holder counts until it drops the flag or leaves"
        );

        state.note_rival_beacon_flag(
            high,
            signer,
            low,
            RivalFlag {
                proven: true,
                held: false,
            },
            Instant::now(),
        );
        assert!(!state.rival_holder_known(), "no flag takes it out");

        state.note_rival_beacon_flag(
            high,
            signer,
            low,
            RivalFlag {
                proven: true,
                held: true,
            },
            Instant::now(),
        );
        state
            .peer_endpoints
            .insert(nick("bob"), iroh::EndpointAddr::new(low));
        state.forget_peer_endpoint("bob");
        assert!(
            !state.rival_holder_known(),
            "the roster removal takes it out"
        );
    }

    /// The accessor hands out the book that the state was built with, not a copy of it: an address
    /// written through it is in the book of the endpoint.
    #[test]
    fn the_address_book_of_the_state_is_the_book_it_was_given() {
        let _guard = ::habilis_network_test_tracing::init();
        let book = memory::MemoryLookup::new();
        let state = fresh_state_with_book(book.clone());
        let bob = endpoint_id(1);
        assert!(
            book.get_endpoint_info(bob).is_none(),
            "the book starts empty"
        );

        crate::lookup::add_peer_addr(
            state.address_book(),
            iroh::EndpointAddr::new(bob).with_ip_addr("192.0.2.1:4000".parse().expect("address")),
        );

        assert!(
            book.get_endpoint_info(bob).is_some(),
            "an address written through the accessor reaches the book of the endpoint"
        );
    }

    /// A linked pair that proved a direct path and loses UDP is re-raced at once: the relay
    /// policy closes at 15 s, and the retry tick would wait up to 30 s for the offer.
    #[test]
    fn a_proven_pair_on_the_relay_is_raced_again_when_its_link_goes_down() {
        use crate::transport::probe::PathKind;
        let _guard = ::habilis_network_test_tracing::init();
        let (bob, now) = (endpoint_id(1), Instant::now());
        let address = iroh::EndpointAddr::new(bob)
            .with_relay_url("https://relay.invalid".parse().expect("relay url"));
        let node = |direct: Option<DirectState>, kind: PathKind| {
            let mut node = fresh_state();
            node.peer_endpoints.insert(nick("bob"), address.clone());
            node.direct.extend(direct.map(|verdict| (bob, verdict)));
            node.path_kinds.insert(bob, kind);
            node
        };

        let mut proven = node(Some(DirectState::Direct), PathKind::Relay);
        assert_eq!(
            proven.relay_race_on_link_loss(bob, now),
            Some(address.clone()),
            "the relay race returns the address to dial again"
        );
        assert!(
            proven.lane_session_wanted(bob, now),
            "the offer is not held back"
        );
        assert_eq!(
            proven.relay_race_on_link_loss(endpoint_id(2), now),
            None,
            "an unknown peer"
        );
        for (direct, kind, why) in [
            (Some(DirectState::Direct), PathKind::Ip, "UDP still holds"),
            (
                Some(DirectState::RelayOnly),
                PathKind::Relay,
                "never proven",
            ),
            (None, PathKind::Relay, "no verdict"),
        ] {
            assert_eq!(
                node(direct, kind).relay_race_on_link_loss(bob, now),
                None,
                "{why}"
            );
        }
    }

    /// The recursion rule closes a gossip link on the gossip rung, and no re-graft follows (see
    /// `a_pair_that_rides_the_gossip_rung_is_not_regrafted`). The pair must be raced again then,
    /// or nothing brings a link back while the IP path is gone.
    #[test]
    fn a_proven_pair_on_the_gossip_rung_is_raced_again_when_its_link_goes_down() {
        use crate::transport::probe::PathKind;
        let _guard = ::habilis_network_test_tracing::init();
        let (bob, now) = (endpoint_id(1), Instant::now());
        let address = iroh::EndpointAddr::new(bob)
            .with_relay_url("https://relay.invalid".parse().expect("relay url"));
        let mut node = fresh_state();
        node.peer_endpoints.insert(nick("bob"), address.clone());
        node.direct.insert(bob, DirectState::Direct);
        node.path_kinds.insert(bob, PathKind::Gossip);

        assert_eq!(
            node.relay_race_on_link_loss(bob, now),
            Some(address),
            "the gossip rung race returns the address to dial again"
        );
        assert!(
            node.lane_session_wanted(bob, now),
            "the offer is not held back"
        );
    }

    /// A proven pair that loses its link is re-grafted in about a second, whatever the other links
    /// of the node are,
    /// not at the heal tick (10 to 15 s). A pair that flaps is paced by the relink cooldown.
    #[test]
    fn a_proven_peer_that_lost_its_link_is_regrafted_in_about_a_second() {
        let _guard = ::habilis_network_test_tracing::init();
        let (bob, carol) = (endpoint_id(1), endpoint_id(2));
        let now = Instant::now();
        let after = |millis: u64| now + Duration::from_millis(millis);
        let lost = |peers_left: &[EndpointId], verdict: DirectState| {
            let mut node = fresh_state();
            node.direct.insert(bob, verdict);
            for peer in peers_left {
                node.link(*peer);
            }
            node
        };

        let mut centered = lost(&[], DirectState::Direct);
        assert!(
            centered.plan_regraft_on_link_loss(bob, now, 0.0),
            "a centered jitter regrafts the peer at once"
        );
        assert!(centered.take_regrafts_due(after(900)).is_empty(), "not yet");
        assert_eq!(centered.take_regrafts_due(after(1100)), vec![bob], "due");
        assert!(
            centered.take_regrafts_due(after(1200)).is_empty(),
            "taken once"
        );

        let mut early = lost(&[], DirectState::Direct);
        assert!(
            early.plan_regraft_on_link_loss(bob, now, -1.0),
            "an early jitter does not regraft the peer yet"
        );
        assert_eq!(
            early.take_regrafts_due(after(750)),
            vec![bob],
            "jitter down"
        );
        let mut late = lost(&[], DirectState::Direct);
        assert!(
            late.plan_regraft_on_link_loss(bob, now, 1.0),
            "a late jitter still regrafts the peer"
        );
        assert!(late.take_regrafts_due(after(1250)).is_empty(), "jitter up");
        assert_eq!(
            late.take_regrafts_due(after(1350)),
            vec![bob],
            "only the peer that lost its link is due for a regraft"
        );

        let mut back = lost(&[], DirectState::Direct);
        back.plan_regraft_on_link_loss(bob, now, 0.0);
        back.link(bob);
        assert!(
            back.take_regrafts_due(after(1100)).is_empty(),
            "the link came back"
        );

        let mut other_link = lost(&[carol], DirectState::Direct);
        assert!(
            other_link.plan_regraft_on_link_loss(bob, now, 0.0),
            "a proven pair is grafted again whatever the other links are"
        );
        let mut unproven = lost(&[], DirectState::RelayOnly);
        assert!(
            !unproven.plan_regraft_on_link_loss(bob, now, 0.0),
            "never proven"
        );
        let mut flapping = lost(&[], DirectState::Direct);
        flapping.note_relink(bob, now);
        assert!(
            !flapping.plan_regraft_on_link_loss(bob, now, 0.0),
            "on the relink cooldown"
        );
    }

    /// A pair that reads as the relay is raced again by `relay_race_on_link_loss`, and its graft
    /// follows the attach. A quick re-graft would dial the relay for nothing and arm the backoff.
    #[test]
    fn a_pair_that_reads_as_the_relay_is_not_regrafted_quickly() {
        use crate::transport::probe::PathKind;
        let _guard = ::habilis_network_test_tracing::init();
        let (bob, now) = (endpoint_id(1), Instant::now());
        let lost = |kind: PathKind| {
            let mut node = fresh_state();
            node.direct.insert(bob, DirectState::Direct);
            node.path_kinds.insert(bob, kind);
            node
        };

        assert!(
            !lost(PathKind::Relay).plan_regraft_on_link_loss(bob, now, 0.0),
            "the relay reading belongs to the race"
        );
        assert!(
            lost(PathKind::Ip).plan_regraft_on_link_loss(bob, now, 0.0),
            "an IP path is grafted again"
        );
    }

    /// A gossip link on the gossip rung is closed by the recursion rule, so a graft of the pair
    /// only makes the gossip layer dial a link that dies.
    #[test]
    fn a_pair_that_rides_the_gossip_rung_is_not_regrafted() {
        use crate::transport::probe::PathKind;
        let _guard = ::habilis_network_test_tracing::init();
        let (bob, now) = (endpoint_id(1), Instant::now());
        let mut node = fresh_state();
        node.direct.insert(bob, DirectState::Direct);
        node.path_kinds.insert(bob, PathKind::Gossip);

        assert!(
            node.rides_gossip_rung(bob),
            "the pair is seen to ride the gossip rung"
        );
        assert!(
            !node.plan_regraft_on_link_loss(bob, now, 0.0),
            "no re-graft is planned for a pair on the gossip rung"
        );
    }

    /// The release rule's two answers, on a node that lets go at two links.
    fn two_link_node() -> EventLoopState {
        let mut state = fresh_state();
        state.rendezvous_release_links = 2;
        state
    }

    #[test]
    fn a_node_below_the_release_count_wants_the_rendezvous() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.rendezvous_linked = true;
        state.linked_endpoints.insert(endpoint_id(1));
        assert!(
            state.rendezvous_wanted(),
            "a node below the release count wants the rendezvous"
        );
        assert!(
            !state.should_release_rendezvous(Instant::now()),
            "one link is not enough"
        );
    }

    #[test]
    fn a_node_at_the_release_count_lets_go_and_stops_wanting_it() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.rendezvous_linked = true;
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        assert!(
            state.should_release_rendezvous(Instant::now()),
            "a node at the release count lets go of the rendezvous"
        );

        state.rendezvous_linked = false;
        assert!(
            !state.rendezvous_wanted(),
            "enough links: no graft, no offer"
        );
        assert!(
            !state.should_release_rendezvous(Instant::now()),
            "nothing left to let go of"
        );
    }

    /// Gossip ends the link some time after the release, and the heal tick and
    /// every link event ask again meanwhile. A node already released must not be
    /// due again, or it tells gossip to leave a second time and logs it twice.
    #[test]
    fn a_node_that_has_released_is_not_due_again_while_the_link_is_still_up() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.rendezvous_linked = true;
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        assert!(
            state.should_release_rendezvous(Instant::now()),
            "the first release is due while the link is up"
        );

        state.mark_rendezvous_released(endpoint_id(9));

        assert!(
            !state.should_release_rendezvous(Instant::now()),
            "a node that released is not due again while its link stays up"
        );
    }

    /// A mesh that split into islands, each with links enough, never visits the rendezvous on its
    /// own: nothing is owed and no link is below the count. Each node comes back once in a long
    /// while, and the beacon introduces the islands to each other.
    #[test]
    fn a_node_that_let_go_wants_the_rendezvous_again_when_its_return_falls_due() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.rendezvous_linked = true;
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.mark_rendezvous_released(endpoint_id(9));
        state.rendezvous_linked = false;
        assert!(
            !state.rendezvous_wanted(),
            "it let go a moment ago: no visit yet"
        );
        assert!(
            state.rendezvous_return_due.is_some(),
            "a release sets the time of its return"
        );

        state.rendezvous_return_due = Some(Instant::now());
        state.pay_periodic_return(Instant::now(), endpoint_id(9));

        assert!(
            state.rendezvous_wanted(),
            "a return that fell due is wanted although the links are enough"
        );
    }

    /// A return that fell due and found no link is not wanted for ever: the visit is bounded
    /// like an owed one, or a member whose visit cannot link grafts and offers at every tick.
    #[test]
    fn a_return_that_fell_due_and_got_no_link_is_not_wanted_after_the_comeback_window() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.mark_rendezvous_released(endpoint_id(9));
        let window = tuning::RENDEZVOUS_COMEBACK;
        state.rendezvous_return_due = Instant::now().checked_sub(window + Duration::from_secs(1));

        assert!(
            !state.rendezvous_wanted(),
            "a return that fell due a window ago and found no link is wanted for ever"
        );
    }

    /// The periodic return is paid on the heal tick as an owed one: wanted for the comeback
    /// window, due again one period later, and not paid twice.
    #[test]
    fn a_periodic_return_that_fell_due_is_paid_once_and_set_again_one_period_later() {
        let _guard = ::habilis_network_test_tracing::init();
        let local = endpoint_id(9);
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.mark_rendezvous_released(local);
        let now = Instant::now();
        state.rendezvous_return_due = Some(now);

        state.pay_periodic_return(now, local);

        assert!(state.rendezvous_wanted(), "the visit is wanted now");
        let period = tuning::RENDEZVOUS_PERIODIC_RETURN;
        let next = state.rendezvous_return_due.expect("it is set again");
        assert!(next >= now + period, "the next return is a period away");
        let owed_until = state.rendezvous_comeback_until;

        state.pay_periodic_return(now + Duration::from_secs(1), local);

        assert_eq!(
            state.rendezvous_comeback_until, owed_until,
            "a return that is not due is not paid again"
        );
        state.rendezvous_comeback_until = now.checked_sub(Duration::from_secs(1));
        assert!(!state.rendezvous_wanted(), "the visit ends with its window");
    }

    #[test]
    fn the_return_of_a_node_that_let_go_falls_due_one_period_later_at_the_earliest() {
        let _guard = ::habilis_network_test_tracing::init();
        let period = tuning::RENDEZVOUS_PERIODIC_RETURN;
        for seed in 1..=8 {
            let after = super::rendezvous_return_after(endpoint_id(seed));
            assert!(
                after >= period,
                "seed {seed}: {after:?} is before the period"
            );
            assert!(
                after <= period + period / 2,
                "seed {seed}: {after:?} is later than half a period more"
            );
        }
        assert_ne!(
            super::rendezvous_return_after(endpoint_id(1)),
            super::rendezvous_return_after(endpoint_id(2)),
            "two members do not come back together"
        );
    }

    #[test]
    fn a_visit_that_the_period_asked_for_lasts_its_dwell_time_before_the_node_lets_go() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.mark_rendezvous_released(endpoint_id(9));
        let now = Instant::now();
        state.rendezvous_return_due = Some(now);

        state.note_rendezvous_link_up(now);

        assert!(
            !state.should_release_rendezvous(now),
            "the visit lasts its dwell time: the beacon needs it to introduce the islands"
        );
        let after_dwell = now + tuning::RENDEZVOUS_DWELL;
        assert!(
            state.should_release_rendezvous(after_dwell),
            "the node still lets go once the dwell the period asked for has passed"
        );
    }

    #[test]
    fn a_link_that_comes_up_before_the_return_is_due_asks_for_no_dwell() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.mark_rendezvous_released(endpoint_id(9));
        let now = Instant::now();

        state.note_rendezvous_link_up(now);

        assert!(
            state.should_release_rendezvous(now),
            "the node lets go at once when no dwell is owed"
        );
    }

    #[test]
    fn a_link_that_comes_back_ends_the_wait_for_the_return() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.mark_rendezvous_released(endpoint_id(9));
        assert!(
            state.rendezvous_return_due.is_some(),
            "the return is due while the rendezvous link is down"
        );

        state.note_rendezvous_link_up(Instant::now());

        assert!(
            state.rendezvous_return_due.is_none(),
            "the link coming back clears the owed return"
        );
    }

    #[test]
    fn a_node_that_falls_below_the_count_comes_back() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        assert!(
            !state.rendezvous_wanted(),
            "a node that falls below the count stops wanting the rendezvous"
        );

        state.linked_endpoints.remove(&endpoint_id(2));

        assert!(
            state.rendezvous_wanted(),
            "falling below the count makes the node want the rendezvous again"
        );
    }

    #[test]
    fn the_node_that_hosts_the_rendezvous_keeps_its_link() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.hosts_rendezvous = true;
        state.rendezvous_linked = true;
        for seed in 1..=5 {
            state.linked_endpoints.insert(endpoint_id(seed));
        }
        assert!(
            !state.should_release_rendezvous(Instant::now()),
            "its link keeps the beacon's gossip view non-empty for a joiner"
        );
        assert!(
            state.rendezvous_wanted(),
            "hosting the rendezvous keeps the node wanting it"
        );
    }

    #[test]
    fn an_owed_return_makes_a_node_with_enough_links_want_it() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.owe_rendezvous_return(Instant::now());
        assert!(
            state.rendezvous_wanted(),
            "an owed return makes a node with enough links want the rendezvous"
        );
    }

    /// A debt with an end: a node refused again and again at the rendezvous
    /// stops offering when the return it owed expires.
    #[test]
    fn an_owed_return_ends_at_its_deadline() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        let long_ago = Instant::now()
            .checked_sub(tuning::RENDEZVOUS_COMEBACK + Duration::from_secs(1))
            .expect("a past instant");
        state.owe_rendezvous_return(long_ago);

        assert!(
            !state.rendezvous_wanted(),
            "past the deadline the node no longer wants the rendezvous"
        );
    }

    /// A node that came back stays its dwell time before it lets go again, and
    /// lets go on its own once the time has passed, with no link event to
    /// trigger it.
    #[test]
    fn a_node_that_came_back_lets_go_again_after_its_dwell_time() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.owe_rendezvous_return(Instant::now());
        let now = Instant::now();
        state.note_rendezvous_link_up(now);
        assert!(
            state.rendezvous_linked,
            "the rendezvous link stays up after the return"
        );
        assert!(
            !state.should_release_rendezvous(now),
            "the visit has just begun"
        );

        let later = now + tuning::RENDEZVOUS_DWELL + Duration::from_secs(1);

        assert!(
            state.should_release_rendezvous(later),
            "the dwell time has passed and the links are enough"
        );
        assert!(
            state.rendezvous_comeback_until.is_none(),
            "the debt was paid by the visit"
        );
    }

    /// A first visit has no dwell: a joiner lets go as soon as it has the links.
    #[test]
    fn a_first_visit_has_no_dwell_time() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = two_link_node();
        state.linked_endpoints.insert(endpoint_id(1));
        state.linked_endpoints.insert(endpoint_id(2));
        state.note_rendezvous_link_up(Instant::now());
        assert!(
            state.should_release_rendezvous(Instant::now()),
            "a first visit has no dwell time and lets go at once"
        );
    }

    /// An unsigned chat message carrying `id` — enough to exercise
    /// `mark_seen`, which keys on `dedup_key()` (`SHA-256(pubkey ‖ id)`).
    fn msg_with_id(id: &MessageId) -> message::Verified {
        plain_with_id(id).sign(&crate::protocol::Identity::generate())
    }

    fn plain_with_id(id: &MessageId) -> Message {
        let mut message = Message::new_app(
            &MeshId::from("test"),
            &nick("author-nick"),
            AppFrameParams::new(
                crate::protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                None,
                None,
                MessageBody::from("body"),
            ),
        );
        message.id = id.clone();
        message
    }

    /// A content hash for a test: the hash of the name.
    fn hash_of(name: &str) -> ContentHash {
        ContentHash::of(name.as_bytes())
    }

    #[test]
    fn note_msg_seq_detects_equivocation_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let key = author_of("alice-key");
        // First sighting at a seq → recorded, no fork.
        assert!(
            !state.note_msg_seq(&key, 0, hash_of("hashA")),
            "the same hash at seq 0 is no equivocation"
        );
        // Same message again (same hash) → no fork.
        assert!(
            !state.note_msg_seq(&key, 0, hash_of("hashA")),
            "repeating the same hash at seq 0 is still no equivocation"
        );
        // Different hash at the SAME seq → fork, reported exactly once.
        assert!(
            state.note_msg_seq(&key, 0, hash_of("hashB")),
            "conflict is a fork"
        );
        assert!(
            !state.note_msg_seq(&key, 0, hash_of("hashC")),
            "already flagged: one event per key"
        );
    }

    #[test]
    fn note_msg_seq_is_per_key_and_per_seq() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        assert!(
            !state.note_msg_seq(&author_of("alice"), 0, hash_of("h0")),
            "alice's first message at seq 0 is no equivocation"
        );
        // A new seq for the same author is just the next entry, not a fork.
        assert!(
            !state.note_msg_seq(&author_of("alice"), 1, hash_of("h1")),
            "alice's first message at seq 1 is no equivocation"
        );
        // A different key reusing seq 0 with its own hash is independent.
        assert!(
            !state.note_msg_seq(&author_of("bob"), 0, hash_of("other")),
            "bob's seq 0 is not alice's equivocation"
        );
        // But a conflict on alice's seq 0 still fires.
        assert!(
            state.note_msg_seq(&author_of("alice"), 0, hash_of("h0-prime")),
            "a second hash at alice's seq 0 is equivocation"
        );
    }

    #[test]
    fn forget_msg_seq_prunes_author_and_fork_flag() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.note_msg_seq(&author_of("alice"), 0, hash_of("h0"));
        assert!(
            state.note_msg_seq(&author_of("alice"), 0, hash_of("h0-prime")),
            "fork"
        );
        assert!(
            state.forked.contains(&author_of("alice")),
            "alice is flagged as a fork"
        );
        // Evicting the *recorded* twin (hash "h0") drops alice from both maps.
        state.forget_msg_seq(&author_of("alice"), 0, &hash_of("h0"));
        assert!(
            !state.author_seqs.contains_key(&author_of("alice")),
            "forgetting alice drops her sequence state"
        );
        assert!(
            !state.forked.contains(&author_of("alice")),
            "fork flag pruned with author"
        );
    }

    #[test]
    fn forget_msg_seq_keeps_evidence_when_other_twin_evicted() {
        // A fork keeps two twins at one (author, seq). Evicting the twin we did
        // NOT record must not clear the recorded slot / fork flag — otherwise a
        // later resend of the still-retained twin re-detects the fork as new.
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.note_msg_seq(&author_of("alice"), 0, hash_of("recorded"));
        assert!(
            state.note_msg_seq(&author_of("alice"), 0, hash_of("twin")),
            "fork fires"
        );
        assert!(
            state.forked.contains(&author_of("alice")),
            "alice stays flagged as a fork after one twin is evicted"
        );
        // Evict the non-recorded twin ("twin"): the slot for "recorded" stays.
        state.forget_msg_seq(&author_of("alice"), 0, &hash_of("twin"));
        assert!(
            state.author_seqs.contains_key(&author_of("alice")),
            "recorded slot retained"
        );
        assert!(
            state.forked.contains(&author_of("alice")),
            "fork flag retained"
        );
        // A resend of the recorded twin does not re-fire the fork (already
        // flagged), proving the evidence survived the eviction.
        assert!(
            !state.note_msg_seq(&author_of("alice"), 0, hash_of("twin")),
            "the evicted twin is not seen as a new equivocation"
        );
    }

    #[test]
    fn note_dag_moves_tip_set() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        // First message (no parents) becomes the sole tip.
        assert!(
            !state.note_dag(hash_of("h1"), &[], UnixSecs::from(100)),
            "a root node with no parents is not flagged"
        );
        let tips_h1: Vec<_> = state.dag_parents().collect();
        assert_eq!(
            tips_h1,
            vec![hash_of("h1")],
            "h1 is the only tip after its first note"
        );
        // A child referencing h1 makes h1 no longer a tip; h2 is the new one.
        assert!(
            !state.note_dag(hash_of("h2"), &[hash_of("h1")], UnixSecs::from(101)),
            "a child of h1 is not flagged"
        );
        let tips_h2: Vec<_> = state.dag_parents().collect();
        assert_eq!(
            tips_h2,
            vec![hash_of("h2")],
            "h2 replaces h1 as the only tip"
        );
    }

    #[test]
    fn note_dag_keeps_concurrent_tips() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.note_dag(hash_of("a"), &[], UnixSecs::from(1));
        state.note_dag(hash_of("b"), &[], UnixSecs::from(1)); // concurrent: no shared parent
        let mut both = vec![hash_of("a"), hash_of("b")];
        both.sort();
        let tips: Vec<_> = state.dag_parents().collect();
        assert_eq!(tips, both, "both tips, in hash order");
    }

    #[test]
    fn note_dag_flags_backdating() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.note_dag(hash_of("parent"), &[], UnixSecs::from(200));
        // Child claims an earlier timestamp than a parent it references.
        assert!(
            state.note_dag(hash_of("child"), &[hash_of("parent")], UnixSecs::from(100)),
            "a child stamped before its parent is flagged as backdated"
        );
        // A forward timestamp is fine.
        assert!(
            !state.note_dag(hash_of("ok"), &[hash_of("parent")], UnixSecs::from(300)),
            "a child stamped after its parent is not flagged"
        );
    }

    #[test]
    fn forget_hash_prunes_dag() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.note_dag(hash_of("h"), &[], UnixSecs::from(1));
        state.forget_hash(&hash_of("h"));
        assert!(
            state.dag_parents().next().is_none(),
            "forgetting the hash leaves no parents in the DAG"
        );
    }

    /// A valid (curve-point) `EndpointId` derived deterministically from
    /// a seed — `EndpointId::from_bytes` rejects arbitrary bytes.
    // The `known_endpoints` / `quiet` fields are `BoundedFifoSet`s wired with
    // their caps — the generic FIFO/dedup/remove behavior is covered in
    // `bounded_fifo_set`; these only assert the state wires the right cap.
    #[test]
    fn known_endpoints_field_is_capped() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let first = endpoint_id(0);
        state.known_endpoints.insert(first);
        for index in 0..KNOWN_ENDPOINTS_CAP {
            state
                .known_endpoints
                .insert(endpoint_id(u8::try_from(index + 1).unwrap()));
        }
        assert!(
            state.known_endpoints.len() <= KNOWN_ENDPOINTS_CAP,
            "the endpoints cache never grows past its cap"
        );
        assert!(
            !state.known_endpoints.contains(&first),
            "oldest evicted past the cap"
        );
    }

    #[test]
    fn roster_reach_tags_only_live_links_direct() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let linked_ep = endpoint_id(1);
        let stale_ep = endpoint_id(2);
        // A peer whose advertised endpoint is a live link → direct.
        state.peers.insert(nick("linked"));
        state
            .peer_endpoints
            .insert(nick("linked"), iroh::EndpointAddr::new(linked_ep));
        state.linked_endpoints.insert(linked_ep);
        // Advertised, but the endpoint is not (any longer) a live link → gossip.
        state.peers.insert(nick("unlinked"));
        state
            .peer_endpoints
            .insert(nick("unlinked"), iroh::EndpointAddr::new(stale_ep));
        // No PeerInfo seen yet → no binding → gossip.
        state.peers.insert(nick("unknown"));
        // Quiet evictees are never live-linked → gossip.
        state.quiet.insert(nick("quiet"));

        let snapshot = state.roster_snapshot();
        let reach = |name: &str| {
            let found = snapshot
                .peers
                .iter()
                .find(|entry| entry.nickname.as_str() == name);
            found
                .unwrap_or_else(|| panic!("{name} missing from roster"))
                .reach
        };
        assert_eq!(
            reach("linked"),
            Reach::Direct,
            "a linked peer reads as direct"
        );
        assert_eq!(
            reach("unlinked"),
            Reach::Gossip,
            "an unlinked peer reads as gossip reach"
        );
        assert_eq!(
            reach("unknown"),
            Reach::Gossip,
            "an unknown peer reads as gossip reach"
        );
        assert_eq!(
            reach("quiet"),
            Reach::Gossip,
            "a quiet peer reads as gossip reach"
        );
    }

    #[test]
    fn direct_state_follows_conn_path_readings_and_counts() {
        use crate::gossip::PathSummary;
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        // The mapping only reaches `RelayOnly` on a mesh whose relay may carry
        // payload; the lookup-only half is
        // `a_relay_reading_never_demotes_a_proven_peer_on_a_lookup_only_mesh`.
        state.relay_transport = crate::transport::PayloadPath::RelayAllowed;
        state.observe_path(endpoint_id(1), PathSummary::Direct);
        state.observe_path(endpoint_id(2), PathSummary::Relay);
        state.direct.insert(endpoint_id(3), DirectState::Pending);
        assert_eq!(
            state.direct_counts(),
            DirectCounts {
                direct: 1,
                relay_only: 1,
                pending: 1
            },
            "the direct counts track each path reading"
        );
    }

    /// A mixed or empty reading proves nothing about the selected path, so
    /// it must neither promote an unproven peer nor demote a proven one.
    #[test]
    fn a_mixed_or_unknown_reading_never_changes_what_is_known() {
        use crate::gossip::PathSummary;
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.observe_path(endpoint_id(1), PathSummary::Mixed);
        state.observe_path(endpoint_id(2), PathSummary::Unknown);
        assert!(
            state.direct.is_empty(),
            "a mixed reading leaves the direct map empty"
        );
        state.direct.insert(endpoint_id(3), DirectState::Direct);
        state.observe_path(endpoint_id(3), PathSummary::Mixed);
        state.observe_path(endpoint_id(3), PathSummary::Unknown);
        assert_eq!(
            state.direct.get(&endpoint_id(3)),
            Some(&DirectState::Direct),
            "peer 3 keeps its direct state through a mixed reading"
        );
        state.direct.insert(endpoint_id(4), DirectState::RelayOnly);
        state.observe_path(endpoint_id(4), PathSummary::Mixed);
        assert_eq!(
            state.direct.get(&endpoint_id(4)),
            Some(&DirectState::RelayOnly),
            "peer 4 keeps its relay-only state through an unknown reading"
        );
    }

    /// On a lookup-only mesh the census reading cannot demote a proven peer.
    /// `gossip::recv` gates its own `observe_path` for the same reason — a link
    /// up *is* the proof there, and `conn_path` cannot see which path is
    /// selected — but the census tick (`daemon::timers`) calls it ungated, so
    /// the gate belongs here. A `Relay` reading on a peer the accept gate and
    /// the probe both admitted would otherwise stop every payload lane to it.
    #[test]
    fn a_relay_reading_never_demotes_a_proven_peer_on_a_lookup_only_mesh() {
        use crate::gossip::PathSummary;
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.relay_transport = crate::transport::PayloadPath::DirectOnly;
        state.direct.insert(endpoint_id(1), DirectState::Direct);
        state.observe_path(endpoint_id(1), PathSummary::Relay);
        assert_eq!(
            state.direct.get(&endpoint_id(1)),
            Some(&DirectState::Direct),
            "the relay may not carry payload, so a relayed reading proves nothing"
        );

        // With the relay allowed as transport the reading is real news: the
        // peer is reachable, over the relay, and the lanes may use it.
        state.relay_transport = crate::transport::PayloadPath::RelayAllowed;
        state.observe_path(endpoint_id(1), PathSummary::Relay);
        assert_eq!(
            state.direct.get(&endpoint_id(1)),
            Some(&DirectState::RelayOnly),
            "a relay reading does not demote a proven peer"
        );
    }

    #[test]
    fn roster_reach_counts_the_rendezvous_link_for_the_beacon() {
        // The beacon gossips *as* the rendezvous, so a joiner's only link to
        // it is the rendezvous link (kept out of `linked_endpoints`). The
        // beacon's `PeerInfo` advertises the rendezvous endpoint, so the
        // roster must still tag it `direct` while we're rendezvous-linked.
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let rendezvous_ep = endpoint_id(7);
        state.rendezvous_id = Some(rendezvous_ep);
        state.peers.insert(nick("beacon"));
        state
            .peer_endpoints
            .insert(nick("beacon"), iroh::EndpointAddr::new(rendezvous_ep));

        let reach = |current: &EventLoopState| {
            let roster = current.roster_snapshot();
            let beacon = roster
                .peers
                .iter()
                .find(|entry| entry.nickname.as_str() == "beacon");
            beacon.expect("beacon in roster").reach
        };

        state.rendezvous_linked = true;
        assert_eq!(reach(&state), Reach::Direct, "linked rendezvous → direct");

        state.rendezvous_linked = false;
        assert_eq!(reach(&state), Reach::Gossip, "rendezvous down → gossip");
    }

    #[test]
    fn roster_transport_mirrors_the_send_decision() {
        use crate::transport::Lane;
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.meshed = true;
        // Known endpoint while meshed → unicast (the send path would dial it).
        state.peers.insert(nick("dialable"));
        state
            .peer_endpoints
            .insert(nick("dialable"), iroh::EndpointAddr::new(endpoint_id(1)));
        state.direct.insert(endpoint_id(1), DirectState::Direct);
        // No PeerInfo yet → nothing to dial → unreachable for directed frames.
        state.peers.insert(nick("unknown"));

        let lane = |current: &EventLoopState, name: &str| {
            let roster = current.roster_snapshot();
            let entry = roster
                .peers
                .iter()
                .find(|entry| entry.nickname.as_str() == name);
            entry
                .unwrap_or_else(|| panic!("{name} missing from roster"))
                .transport
        };
        assert_eq!(
            lane(&state, "dialable"),
            Lane::Unicast,
            "a dialable peer takes the unicast lane"
        );
        assert_eq!(
            lane(&state, "unknown"),
            Lane::Unreachable,
            "an unknown peer has no lane"
        );

        // Unmeshed: the known endpoint is reached via the multihop transport (iroh
        // picks a direct path when meshed, else the multihop one), so the column
        // reads `multihop` rather than a direct `unicast`.
        state.meshed = false;
        assert_eq!(
            lane(&state, "dialable"),
            Lane::Multihop,
            "the lane follows the send decision for a dialable peer"
        );
    }

    #[test]
    fn quiet_field_is_capped() {
        // `quiet` is drained only on return, so the cap is what stops a churn /
        // sybil stream of one-shot nicknames from growing it without bound.
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        for index in 0..(QUIET_CAP + 5) {
            state.quiet.insert(nick(&format!("ghost-{index}")));
        }
        assert!(
            state.quiet.len() <= QUIET_CAP,
            "quiet stays capped under churn: {}",
            state.quiet.len()
        );
    }

    #[test]
    fn mark_seen_delegates_dedup() {
        // Smoke test the `EventLoopState` -> `BoundedFifoSet` delegation; the
        // bounded-FIFO/eviction logic itself is covered in `habilis-network-util`.
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let message = msg_with_id(&MessageId::random());
        assert!(
            !state.mark_seen(&message),
            "first sighting is not a duplicate"
        );
        assert!(state.mark_seen(&message), "second sighting is a duplicate");
    }

    /// A frame still in the message log has been processed. Anti-entropy re-sends any frame a
    /// peer holds, and `seen` alone forgets one under enough traffic of the kinds the log never
    /// keeps; the re-send would then be reprocessed and re-surfaced.
    #[test]
    fn a_retained_frame_stays_a_duplicate_after_seen_forgets_it() {
        use crate::util::tuning::SEEN_IDS_CAP;

        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let message = msg_with_id(&MessageId::random());
        assert!(
            !state.mark_seen(&message),
            "first sighting is not a duplicate"
        );
        state.message_log.push(message.clone());
        for _ in 0..SEEN_IDS_CAP {
            state.mark_seen(&msg_with_id(&MessageId::random()));
        }
        assert!(
            state.mark_seen(&message),
            "a re-send of a frame still in the log is a duplicate"
        );
    }

    /// **One digest per peer per window.**
    ///
    /// Serving a digest costs up to `ANTIENTROPY_MAX_RESEND` mesh-wide
    /// broadcasts. With the budget counted per digest and nothing per peer, one
    /// small crafted frame bought 64 floods from every member that received it,
    /// so the cost grew with the mesh rather than with the attacker.
    #[test]
    fn an_unreadable_digest_is_reported_once_per_author_and_window() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let now = Instant::now();
        assert!(
            state.report_unreadable_digest(author_of("aa"), now),
            "the first is reported"
        );
        assert!(
            !state.report_unreadable_digest(author_of("aa"), now + Duration::from_secs(10)),
            "the same author every round is one line, not one line per round"
        );
        assert!(
            state.report_unreadable_digest(author_of("bb"), now),
            "another author is reported on its own"
        );
        assert!(
            state.report_unreadable_digest(
                author_of("aa"),
                now + super::UNREADABLE_DIGEST_LOG_WINDOW + Duration::from_secs(1)
            ),
            "the author is reported again after the window"
        );
    }

    #[test]
    fn a_peer_is_served_one_digest_per_window() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let now = Instant::now();
        let window = tuning::ANTIENTROPY_SERVE_COOLDOWN;

        assert!(
            state.admit_digest(author_of("aa"), now),
            "the first is served"
        );
        assert!(
            !state.admit_digest(author_of("aa"), now),
            "a second digest inside the window must not buy another round of resends"
        );
        assert!(
            state.admit_digest(author_of("bb"), now),
            "one peer's flood must not deny another peer service"
        );
        assert!(
            state.admit_digest(author_of("aa"), now + window + Duration::from_millis(1)),
            "the honest cadence resumes after the window"
        );
    }

    #[test]
    fn mark_seen_keys_on_pubkey_not_id() {
        // Two messages sharing an id but signed by different keys must NOT
        // dedup against each other — the fix for the id-collision suppression
        // attack. Distinct pubkeys ⇒ distinct `dedup_key`s.
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let id = MessageId::random();
        let victim =
            message::Verified::fixture_unchecked(plain_with_id(&id), AuthorKey::from([0xaa; 32]));
        let attacker =
            message::Verified::fixture_unchecked(plain_with_id(&id), AuthorKey::from([0xbb; 32]));
        assert!(!state.mark_seen(&victim), "victim's message is fresh");
        assert!(
            !state.mark_seen(&attacker),
            "an id-reusing message under a different key must not be deduped as the victim's"
        );
        assert!(state.mark_seen(&victim), "victim's own resend is deduped");
    }

    // Replicates the mesh-wide CPU runaway at its mechanism: a peer whose
    // transport link flaps (each `NeighborDown` drops it from
    // `linked_endpoints`, each re-learned `PeerInfo` re-passes the novelty
    // gate) must NOT re-dial + re-flood once per flap. See memory
    // `cpu-runaway-membership-amplifier`.
    #[test]
    fn relink_cooldown_caps_a_flapping_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let peer = endpoint_id(7);
        let start = Instant::now();

        // Baseline — documents the BUG: the bare novelty gate (remove+insert)
        // re-links on EVERY flap, i.e. unbounded amplification.
        let mut bare_state = fresh_state();
        let mut bare = 0;
        for _ in 0..100u32 {
            bare_state.linked_endpoints.remove(&peer);
            if bare_state.linked_endpoints.insert(peer) {
                bare += 1;
            }
        }
        assert_eq!(
            bare, 100,
            "without a cooldown every flap re-links — the runaway"
        );

        // With the cooldown: 100 flaps inside one window collapse to ONE re-link.
        let mut cooled = fresh_state();
        let mut relinks = 0;
        for index in 0..100u32 {
            let now = start + Duration::from_millis(u64::from(index) * 10);
            cooled.linked_endpoints.remove(&peer);
            if !cooled.relink_on_cooldown(peer, now) && cooled.linked_endpoints.insert(peer) {
                cooled.note_relink(peer, now);
                relinks += 1;
            }
        }
        assert_eq!(relinks, 1, "the cooldown caps re-links to once per window");

        // Past the window a genuine re-link is allowed again (no permanent lockout).
        let later = start + RELINK_COOLDOWN + Duration::from_secs(1);
        assert!(
            !cooled.relink_on_cooldown(peer, later),
            "a cooled peer stays on cooldown at the later time"
        );
    }

    // The arrival flood goes out on the first `NeighborUp`, in the same milliseconds in
    // which the endpoint gets its home relay, so it can carry no relay. Every later
    // flood is gated by the window, and the receiver keeps the first address it saw. A
    // changed address of our own must therefore call for a flood of its own.
    #[test]
    fn a_changed_own_address_is_due_a_flood_and_an_unchanged_one_is_not() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = endpoint_id(1);
        let relay: iroh::RelayUrl = "https://relay.example".parse().expect("a relay url");
        let ip: std::net::SocketAddr = "192.0.2.1:4000".parse().expect("an address");
        let other_ip: std::net::SocketAddr = "192.0.2.2:4000".parse().expect("an address");
        let without_relay = iroh::EndpointAddr::new(id).with_ip_addr(ip);
        let with_relay = without_relay.clone().with_relay_url(relay.clone());

        let mut state = fresh_state();
        assert!(
            !state.address_flood_due(&with_relay),
            "before the first flood there is nothing to repair"
        );

        state.last_flooded_addr = Some(without_relay.clone());
        assert!(
            !state.address_flood_due(&without_relay),
            "an address that did not change is not flooded again"
        );
        assert!(
            state.address_flood_due(&with_relay),
            "the relay arrived after the flood"
        );

        state.last_flooded_addr = Some(with_relay.clone());
        assert!(
            !state.address_flood_due(&with_relay),
            "the flooded address is the current one"
        );
        assert!(
            state.address_flood_due(
                &iroh::EndpointAddr::new(id)
                    .with_relay_url(relay)
                    .with_ip_addr(other_ip)
            ),
            "an IP address changed"
        );
        assert!(
            state.address_flood_due(&iroh::EndpointAddr::new(id).with_ip_addr(ip)),
            "the relay was lost"
        );
    }

    #[test]
    fn the_order_of_the_addresses_does_not_make_an_address_differ() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = endpoint_id(1);
        let first: std::net::SocketAddr = "192.0.2.1:4000".parse().expect("an address");
        let second: std::net::SocketAddr = "192.0.2.2:4000".parse().expect("an address");
        let mut state = fresh_state();
        state.last_flooded_addr = Some(
            iroh::EndpointAddr::new(id)
                .with_ip_addr(first)
                .with_ip_addr(second),
        );
        assert!(
            !state.address_flood_due(
                &iroh::EndpointAddr::new(id)
                    .with_ip_addr(second)
                    .with_ip_addr(first)
            ),
            "reordering the addresses floods nothing new"
        );
    }

    // The residual flap amplifier the re-link cooldown did NOT cover: every
    // `NeighborUp` re-floods our own `PeerInfo` to the whole mesh, and a
    // flapping link re-triggers `NeighborUp` on each up-transition. Every flood
    // is also answered by a graft from each peer that hears it, and a graft at
    // a full view evicts a neighbor, so a window per neighbor lets the floods
    // cascade. The window is per flood: one flapping peer, or five peers, flood
    // once per window.
    #[test]
    fn neighbors_up_in_one_window_flood_peerinfo_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();

        let mut flapping = fresh_state();
        let mut flapping_refloods = 0;
        for index in 0..100u32 {
            let now = start + Duration::from_millis(u64::from(index) * 10);
            if flapping.neighbor_up_refloods_peerinfo(now) {
                flapping.peerinfo_flooded_at = Some(now);
                flapping_refloods += 1;
            }
        }
        assert_eq!(
            flapping_refloods, 1,
            "a flapping peer floods once per window"
        );

        let mut state = fresh_state();
        let mut refloods = 0;
        for index in 0..5u64 {
            let now = start + Duration::from_millis(index * 10);
            if state.neighbor_up_refloods_peerinfo(now) {
                state.peerinfo_flooded_at = Some(now);
                refloods += 1;
            }
        }
        assert_eq!(refloods, 1, "five neighbors flood once per window");

        // Past the window a neighbor up floods once more (no permanent silence).
        let later = start + RELINK_COOLDOWN + Duration::from_secs(1);
        assert!(
            state.neighbor_up_refloods_peerinfo(later),
            "the first neighbor up in a window re-floods peer info"
        );
    }

    // A neighbor that comes up inside the window of a flood does not make a
    // flood of its own. It must not wait for another `NeighborUp`: the flood is
    // paid once the window ends.
    #[test]
    fn a_held_back_neighbor_up_floods_peerinfo_when_the_window_ends() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = fresh_state();
        state.peerinfo_flooded_at = Some(start);

        assert!(
            !state.neighbor_up_refloods_peerinfo(start + Duration::from_secs(1)),
            "a held-back neighbor up does not re-flood inside the window"
        );
        state.defer_peerinfo();

        assert!(
            !state.take_deferred_peerinfo(start + Duration::from_secs(1)),
            "the deferred flood is not due inside the window"
        );
        let later = start + RELINK_COOLDOWN + Duration::from_secs(1);
        assert!(
            state.take_deferred_peerinfo(later),
            "due once the window ends"
        );
        assert!(!state.take_deferred_peerinfo(later), "paid once");
    }

    #[test]
    fn nothing_is_due_when_no_neighbor_up_was_held_back() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = fresh_state();
        state.peerinfo_flooded_at = Some(start);
        assert!(
            !state.take_deferred_peerinfo(start + RELINK_COOLDOWN + Duration::from_secs(1)),
            "an empty deferral yields no flood"
        );
    }

    #[test]
    fn joined_refloods_peerinfo_once_per_window() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let mut state = fresh_state();

        // Twenty re-announces from twenty peers inside one window.
        let mut refloods = 0;
        for index in 0..20u64 {
            let now = start + Duration::from_millis(index * 10);
            if state.joined_refloods_peerinfo(false, now) {
                state.peerinfo_flooded_at = Some(now);
                refloods += 1;
            }
        }
        assert_eq!(refloods, 1, "once per window, not once per peer");

        // A first sighting inside the window is not throttled.
        assert!(
            state.joined_refloods_peerinfo(true, start + Duration::from_secs(1)),
            "a newcomer's joined re-floods peer info"
        );

        // Past the window a re-announce floods once more (no permanent silence).
        let later = start + RELINK_COOLDOWN + Duration::from_secs(1);
        assert!(
            state.joined_refloods_peerinfo(false, later),
            "a joined that is not new still re-floods once the window is open"
        );
    }

    // A `NeighborDown` drops the gossip link, not the pooled unicast
    // connection the verdict describes. Erasing the verdict with the link
    // parked every directed frame on a flap until the alive tick re-probed.
    /// A session to a gossip neighbor is not a unit of the ceiling, because the gossip link
    /// holds the peer anyway. The ledger learns of a neighbor when the link comes up, and that
    /// the peer is not one when it goes down.
    #[test]
    fn a_session_counts_against_the_ceiling_only_while_its_peer_is_not_a_neighbor() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let bob = endpoint_id(1);
        state.webrtc_admission.note_success(bob);
        assert_eq!(
            state.webrtc_admission.direct_units(),
            1,
            "one direct unit counts against the ceiling"
        );

        state.link(bob);
        assert_eq!(state.webrtc_admission.direct_units(), 0, "a neighbor");

        state.unlink(bob);
        assert_eq!(state.webrtc_admission.direct_units(), 1, "no longer one");
    }

    /// A meshed member that lost every link is a silent partition once the gap outlasts a heal,
    /// not before: a link closed on purpose, or a heal on its way, shows the same zero.
    #[test]
    fn a_meshed_member_without_links_is_a_silent_partition_only_after_a_heal() {
        let _guard = ::habilis_network_test_tracing::init();
        let (bob, roster) = (endpoint_id(1), 3);
        let after = tuning::silent_partition_after();
        let mut state = fresh_state();
        state.meshed = true;

        state.link(bob);
        let far = Instant::now() + after + Duration::from_secs(1);
        assert!(!state.silent_partition_due(roster, far), "a link is up");

        state.unlink(bob);
        assert!(
            !state.silent_partition_due(roster, Instant::now()),
            "the gap is young"
        );
        assert!(
            state.silent_partition_due(roster, far),
            "the gap outlasted a heal"
        );
        assert!(
            !state.silent_partition_due(0, far),
            "there is nobody to be apart from"
        );
        state.meshed = false;
        assert!(!state.silent_partition_due(roster, far), "never meshed");
        state.meshed = true;

        // An unlink of a peer that was not linked leaves the clock where it was.
        state.unlink(endpoint_id(2));
        assert!(
            state.silent_partition_due(roster, far),
            "the clock did not restart"
        );

        // A link clears the gap, and the next loss starts a new one.
        state.link(bob);
        state.unlink(bob);
        assert!(
            !state.silent_partition_due(roster, Instant::now()),
            "a new gap is young"
        );
    }

    /// A degraded node that a relayed frame heals while it holds no link is meshed with zero links.
    /// It never lost a link, so no unlink started the gap: the heal starts it, and the census calls
    /// the state a silent partition once the gap outlasts a heal.
    #[test]
    fn a_degraded_node_that_heals_without_a_link_starts_counting_the_gap() {
        let _guard = ::habilis_network_test_tracing::init();
        let roster = 3;
        let after = tuning::silent_partition_after();
        let mut state = fresh_state();
        state.note_degraded();
        let healed_at = Instant::now();

        assert!(state.note_inbound(healed_at), "the first inbound heals it");

        assert!(
            !state.silent_partition_due(roster, healed_at),
            "the gap is young"
        );
        assert!(
            state.silent_partition_due(roster, healed_at + after + Duration::from_secs(1)),
            "meshed with no link for longer than a heal"
        );
    }

    /// A heal does not restart a gap that already runs: the unlink that began it is the start.
    #[test]
    fn a_heal_does_not_restart_a_gap_that_already_runs() {
        let _guard = ::habilis_network_test_tracing::init();
        let (bob, roster) = (endpoint_id(1), 3);
        let after = tuning::silent_partition_after();
        let mut state = fresh_state();
        state.meshed = true;
        state.link(bob);
        state.unlink(bob);
        let began = Instant::now();
        state.note_degraded();

        assert!(
            state.note_inbound(began + after / 2),
            "the first inbound heals it"
        );

        assert!(
            state.silent_partition_due(roster, began + after + Duration::from_secs(1)),
            "the heal restarted the clock"
        );
    }

    #[test]
    fn unlinking_a_peer_keeps_its_path_verdict() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let bob = endpoint_id(1);
        state.linked_endpoints.insert(bob);
        state.direct.insert(bob, DirectState::Direct);
        state.unlink(bob);
        assert!(
            state.linked_endpoints.is_empty(),
            "unlinking a peer empties the linked set"
        );
        assert_eq!(
            state.direct.get(&bob),
            Some(&DirectState::Direct),
            "unlinking a peer keeps its path verdict"
        );
    }

    #[test]
    fn a_late_unproven_verdict_only_demotes_a_pending_peer() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let pending = endpoint_id(1);
        let proven = endpoint_id(2);
        let gone = endpoint_id(3);
        state.direct.insert(pending, DirectState::Pending);
        state.direct.insert(proven, DirectState::Direct);

        assert!(
            state.demote_unproven(pending),
            "a late unproven verdict demotes a pending peer"
        );
        assert_eq!(
            state.direct.get(&pending),
            Some(&DirectState::RelayOnly),
            "the pending peer reads as relay-only after the verdict"
        );
        assert!(
            !state.demote_unproven(proven),
            "a proven peer is not demoted by a late unproven verdict"
        );
        assert_eq!(
            state.direct.get(&proven),
            Some(&DirectState::Direct),
            "the proven peer keeps its direct state"
        );
        assert!(
            !state.demote_unproven(gone),
            "an unknown peer is not demoted"
        );
        assert!(
            !state.direct.contains_key(&gone),
            "an unknown peer gets no direct entry"
        );
    }

    #[test]
    fn forgetting_a_peer_endpoint_drops_its_path_verdict() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let bob = endpoint_id(1);
        state
            .peer_endpoints
            .insert(nick("bob"), iroh::EndpointAddr::new(bob));
        state.direct.insert(bob, DirectState::Direct);
        assert_eq!(
            state.forget_peer_endpoint("bob").map(|address| address.id),
            Some(bob),
            "forgetting a peer endpoint returns its address id"
        );
        assert!(
            state.direct.is_empty(),
            "forgetting a peer endpoint leaves no path verdict"
        );
        assert!(
            state.forget_peer_endpoint("bob").is_none(),
            "a second forget finds nothing"
        );
    }

    // After a failover the rendezvous keeps its id, but a refusal from the old
    // holder says nothing about the new one: the wait starts over.
    #[test]
    fn a_new_rendezvous_verdict_starts_the_refusal_wait_over() {
        use habilis_network_iroh_webrtc_transport::{WebRtcHandle, WebRtcTransport};

        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let rendezvous = endpoint_id(7);
        state.rendezvous_id = Some(rendezvous);
        let hub = WebRtcHandle::new(WebRtcTransport::new(endpoint_id(0)));
        state.webrtc_admission.note_refused(rendezvous);
        assert!(
            state.webrtc_admission.try_admit(rendezvous, &hub).is_err(),
            "the refusal makes us wait"
        );

        state.forget_rendezvous_verdict();

        assert!(
            state.webrtc_admission.try_admit(rendezvous, &hub).is_ok(),
            "a new verdict ends the wait"
        );
    }

    // A departed peer read as riding WebRTC was nudged on every alive tick.
    #[test]
    fn forgetting_a_peer_endpoint_drops_its_path_watch() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let bob = endpoint_id(1);
        state
            .peer_endpoints
            .insert(nick("bob"), iroh::EndpointAddr::new(bob));
        state.path_watchers.insert(bob, Some(7));
        state.path_kinds.insert(bob, PathKind::WebRtc);
        state.forget_peer_endpoint("bob");
        assert!(
            state.path_watchers.is_empty(),
            "forgetting a peer endpoint drops its path watchers"
        );
        assert!(
            state.path_kinds.is_empty(),
            "forgetting a peer endpoint drops its path kinds"
        );
    }

    // `arms_reclaim` fires on any peer loss while the mesh is beaconless, and
    // the two probe rounds are ~5 s apart: clearing the verdict there lets
    // ordinary churn starve the two-verdict rule until nobody claims.
    #[test]
    fn only_a_rendezvous_change_drops_a_free_verdict() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.rendezvous_probe_read_free = true;

        state.arm_reclaim(Instant::now());
        assert!(
            state.rendezvous_probe_read_free,
            "the free-read verdict holds before the rendezvous changes"
        );
        assert!(
            state.reclaim_until.is_some(),
            "the reclaim window is open after the rendezvous changes"
        );

        state.forget_rendezvous_verdict();
        assert!(
            !state.rendezvous_probe_read_free,
            "the rendezvous change drops the free-read verdict"
        );
    }

    // The probe wait ends at the three events that reopen the rendezvous: the reclaim window
    // opens, the arbitration is forgotten, and the rendezvous gets a new address. The address of
    // any other peer does not end it.
    #[test]
    fn the_events_that_reopen_the_rendezvous_end_the_probe_wait() {
        let _guard = ::habilis_network_test_tracing::init();
        let now = Instant::now();
        let rendezvous = endpoint_id(9);
        let stranger = endpoint_id(8);
        let relay: iroh::RelayUrl = "https://relay.example".parse().expect("a relay url");

        let mut state = fresh_state();
        state.rendezvous_id = Some(rendezvous);
        state.probe_backoff.note_verdict(true, now, 0.0);
        assert!(!state.probe_backoff.due(now), "the wait is on");

        state.arm_reclaim(now);
        assert!(state.probe_backoff.due(now), "the reclaim window");

        state.probe_backoff.note_verdict(true, now, 0.0);
        state.forget_rendezvous_verdict();
        assert!(state.probe_backoff.due(now), "the arbitration is forgotten");

        state.probe_backoff.note_verdict(true, now, 0.0);
        state.note_peer_endpoint(nick("stranger"), iroh::EndpointAddr::new(stranger));
        state.note_peer_endpoint(
            nick("stranger"),
            iroh::EndpointAddr::new(stranger).with_relay_url(relay.clone()),
        );
        assert!(
            !state.probe_backoff.due(now),
            "a new address of another peer"
        );

        state.note_peer_endpoint(nick("host"), iroh::EndpointAddr::new(rendezvous));
        state.note_peer_endpoint(
            nick("host"),
            iroh::EndpointAddr::new(rendezvous).with_relay_url(relay),
        );
        assert!(
            state.probe_backoff.due(now),
            "a new address of the rendezvous"
        );
    }

    // Under a long flap storm against a steady peer set, every collection *we*
    // own stays flat — so the soak's monotonic 4.6 GB resident-memory climb is provably
    // below our layer (the iroh transport), not in daemon state. This replays
    // the per-flap state mutations the `NeighborUp`/`NeighborDown` arms +
    // `handle_peer_info` make, for many flaps over simulated hours.
    #[test]
    fn app_state_stays_bounded_under_flap_churn() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let start = Instant::now();
        // A small, *steady* roster (the soak's shape: ~10 members, ~7.4k flaps),
        // not a sybil endpoint stream — endpoints are real curve points.
        let peers: Vec<EndpointId> = (0..8u8).map(endpoint_id).collect();

        for index in 0..10_000u32 {
            let now = start + Duration::from_millis(u64::from(index) * 100);
            let peer = peers[index as usize % peers.len()];
            // NeighborUp → PeerInfo reflood gate + (via handle_peer_info) link.
            if state.neighbor_up_refloods_peerinfo(now) {
                state.peerinfo_flooded_at = Some(now);
            }
            if !state.relink_on_cooldown(peer, now) {
                state.note_relink(peer, now);
                state.linked_endpoints.insert(peer);
                state.known_endpoints.insert(peer);
            }
            // NeighborDown drops the transport link (kept in known_endpoints).
            state.linked_endpoints.remove(&peer);
        }

        // None of our collections grew with the 10k flaps: each is bounded by
        // the roster size or its hard cap, never by the flap count.
        assert!(
            state.relink.len() <= peers.len(),
            "relink flat: {}",
            state.relink.len()
        );
        assert!(
            state.linked_endpoints.len() <= peers.len(),
            "linked_endpoints flat"
        );
        assert!(
            state.known_endpoints.len() <= KNOWN_ENDPOINTS_CAP.min(peers.len()),
            "known_endpoints bounded"
        );
    }

    #[test]
    fn relink_cooldown_is_per_peer_and_bounded() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let start = Instant::now();
        let flapping = endpoint_id(7);
        let other = endpoint_id(8);

        // One peer's cooldown never gates a different peer.
        state.note_relink(flapping, start);
        assert!(
            state.relink_on_cooldown(flapping, start),
            "a flapping peer is on cooldown at the start"
        );
        assert!(
            !state.relink_on_cooldown(other, start),
            "another peer is not on cooldown"
        );

        // Many distinct peers re-linked across more than a full window:
        // expired entries are pruned, so the map never accumulates them all.
        for seed in 0..50u8 {
            let when = start + Duration::from_secs(u64::from(seed));
            state.note_relink(endpoint_id(seed), when);
        }
        assert!(
            state.relink.len() <= usize::try_from(RELINK_COOLDOWN.as_secs()).unwrap() + 1,
            "expired cooldown entries are pruned (map stays bounded)"
        );
    }

    #[test]
    fn dedup_window_covers_the_retention_window() {
        use crate::util::tuning::MESSAGE_LOG_SIZE;

        // The cap relationship itself is asserted at compile time where both
        // consts live; this covers the behaviour it exists for.
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let earliest = msg_with_id(&MessageId::random());
        assert!(
            !state.mark_seen(&earliest),
            "the earliest retained message is still remembered as seen"
        );
        // Mark a full buffer's worth of later messages.
        for _ in 1..MESSAGE_LOG_SIZE {
            state.mark_seen(&msg_with_id(&MessageId::random()));
        }
        // The earliest is still within the dedup window, so an anti-entropy
        // resend of it (while it is still retained in the log) is dropped as
        // a duplicate rather than surfaced a second time.
        assert!(
            state.mark_seen(&earliest),
            "a resend of a still-retained message must be deduped, not re-surfaced"
        );
    }

    const STARVE: Duration = Duration::from_secs(10);

    // The watchdog must only ever fire for a node that (a) was part of a
    // mesh and (b) knows a real peer to re-dial — a lone creator is alone
    // by construction, not starved.
    #[test]
    fn starvation_due_requires_announce_known_peers_and_silence() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let past_threshold = Instant::now() + STARVE + Duration::from_secs(1);
        assert!(
            !state.starvation_due(past_threshold, STARVE),
            "never announced => never starved"
        );
        state.announced = true;
        assert!(
            !state.starvation_due(past_threshold, STARVE),
            "no known peers => alone, not starved"
        );
        state.known_endpoints.insert(endpoint_id(1));
        assert!(
            state.starvation_due(past_threshold, STARVE),
            "starvation is due after the threshold with known peers and silence"
        );
        // Fresh inbound disarms it until the threshold passes again.
        state.note_inbound(past_threshold);
        assert!(
            !state.starvation_due(past_threshold, STARVE),
            "starvation is not due before the threshold"
        );
        assert!(
            state.starvation_due(past_threshold + STARVE + Duration::from_secs(1), STARVE),
            "starvation is due again past the threshold plus the window"
        );
    }

    #[test]
    fn starvation_recovery_backs_off_then_resets_on_inbound() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.announced = true;
        state.known_endpoints.insert(endpoint_id(1));
        let first = Instant::now() + STARVE + Duration::from_secs(1);
        assert!(
            state.starvation_due(first, STARVE),
            "starvation is due at the first silence"
        );
        state.note_recovery(first);
        // One trip: the next attempt waits 2x the threshold, not 1x.
        assert!(
            !state.starvation_due(first + STARVE + Duration::from_secs(1), STARVE),
            "starvation is not due again inside the backoff"
        );
        let second = first + (STARVE * 2) + Duration::from_secs(1);
        assert!(
            state.starvation_due(second, STARVE),
            "the second starvation is due at its time"
        );
        state.note_recovery(second);
        // Two trips: 4x.
        assert!(
            !state.starvation_due(second + (STARVE * 2) + Duration::from_secs(1), STARVE),
            "the backoff doubles after the second trip"
        );
        assert!(
            state.starvation_due(second + (STARVE * 4) + Duration::from_secs(1), STARVE),
            "the backoff quadruples after the second trip"
        );
        // Any inbound resets the backoff to the base threshold.
        let healed = second + (STARVE * 4) + Duration::from_secs(2);
        state.note_inbound(healed);
        assert_eq!(
            state.recovery_trips, 0,
            "an inbound message resets the recovery trips"
        );
        assert!(
            !state.starvation_due(healed + STARVE, STARVE),
            "no starvation is due right after healing"
        );
        assert!(
            state.starvation_due(healed + STARVE + Duration::from_secs(1), STARVE),
            "starvation is due again a threshold after healing"
        );
    }

    #[test]
    fn starvation_backoff_caps_at_eight_threshold() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.announced = true;
        state.known_endpoints.insert(endpoint_id(1));
        let mut last_recovery = Instant::now() + STARVE + Duration::from_secs(1);
        // Trip well past the cap (`recovery_trips.min(3)` => 8x ceiling).
        for _ in 0..6 {
            state.note_recovery(last_recovery);
            last_recovery += STARVE * 8 + Duration::from_secs(1);
        }
        state.note_recovery(last_recovery);
        assert!(
            !state.starvation_due(last_recovery + STARVE * 8, STARVE),
            "inside the capped backoff window"
        );
        assert!(
            state.starvation_due(last_recovery + STARVE * 8 + Duration::from_secs(1), STARVE),
            "the backoff never grows past 8x the threshold"
        );
    }

    // `meshed` restoration on inbound is gated on the `degraded` fault
    // flag: a fresh joiner's pre-mesh inbound (relayed backlog) must not
    // flip `meshed` early — that stays the first real-peer NeighborUp's
    // job — while a degraded node heals on the first proof of traffic.
    #[test]
    fn note_inbound_restores_meshed_only_when_degraded() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let now = Instant::now();
        assert!(
            !state.note_inbound(now),
            "pre-mesh inbound never flips meshed"
        );
        assert!(!state.meshed, "meshed stays off while nothing is degraded");
        state.meshed = true;
        assert!(!state.note_inbound(now), "healthy meshed: no edge");
        assert!(
            state.meshed,
            "a degraded node is meshed again by an inbound message"
        );
        state.note_degraded();
        assert!(!state.meshed, "the degraded state drops meshed again");
        assert!(
            state.note_inbound(now),
            "degraded node heals on first inbound (caller flushes)"
        );
        assert!(state.meshed, "an inbound message restores meshed");
        assert!(!state.degraded, "an inbound message clears degraded");
    }

    /// The second probe of a round is due at the middle of the window, and only once.
    #[test]
    fn the_second_probe_is_due_at_the_middle_of_the_window_and_only_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let t1 = TokioInstant::now();
        let first = Message::new_ping(&MeshId::from("test"), &nick("alice"));
        let mut round = PingRound::new(&first, t1, t1 + Duration::from_secs(10), None);

        assert_eq!(
            round.second_probe_at(),
            Some(t1 + Duration::from_secs(5)),
            "the second probe is due at the middle of the window"
        );
        let second = Message::new_ping(&MeshId::from("test"), &nick("alice"));
        round.probes.insert(second.id, t1 + Duration::from_secs(5));
        assert_eq!(
            round.second_probe_at(),
            None,
            "the second probe is sent only once"
        );
    }

    /// A pong reads its RTT from the probe it names, so a peer that answers only the second
    /// probe gets a true RTT.
    #[test]
    fn a_pong_reads_its_rtt_from_the_probe_it_names() {
        let _guard = ::habilis_network_test_tracing::init();
        let t1 = TokioInstant::now();
        let mesh = MeshId::from("test");
        let first = Message::new_ping(&mesh, &nick("alice"));
        let second = Message::new_ping(&mesh, &nick("alice"));
        let mut round = PingRound::new(&first, t1, t1 + Duration::from_secs(10), None);
        round
            .probes
            .insert(second.id.clone(), t1 + Duration::from_secs(5));

        let at = t1 + Duration::from_secs(5) + Duration::from_millis(30);
        assert!(
            round.record_pong(nick("bob"), &second.id, at),
            "a pong from bob is recorded against the probe it names"
        );
        assert!(
            round.record_pong(nick("carol"), &first.id, t1 + Duration::from_millis(40)),
            "a pong from carol is recorded against the first probe"
        );

        assert_eq!(
            round.pongs[&nick("bob")],
            Duration::from_millis(30),
            "bob's round trip reads 30 ms from its probe"
        );
        assert_eq!(
            round.pongs[&nick("carol")],
            Duration::from_millis(40),
            "carol's round trip reads 40 ms from its probe"
        );
    }

    /// The first pong of a peer is the one kept: the answer to the second probe does not replace
    /// it.
    #[test]
    fn the_first_pong_of_a_peer_is_kept() {
        let _guard = ::habilis_network_test_tracing::init();
        let t1 = TokioInstant::now();
        let mesh = MeshId::from("test");
        let first = Message::new_ping(&mesh, &nick("alice"));
        let second = Message::new_ping(&mesh, &nick("alice"));
        let mut round = PingRound::new(&first, t1, t1 + Duration::from_secs(10), None);
        round
            .probes
            .insert(second.id.clone(), t1 + Duration::from_secs(5));

        round.record_pong(nick("bob"), &first.id, t1 + Duration::from_millis(10));
        round.record_pong(
            nick("bob"),
            &second.id,
            t1 + Duration::from_secs(5) + Duration::from_millis(20),
        );

        assert_eq!(
            round.pongs[&nick("bob")],
            Duration::from_millis(10),
            "the first pong from bob is kept against a later one"
        );
    }

    /// A pong that names no probe of the round, such as the answer to a round that is over, is
    /// dropped.
    #[test]
    fn a_pong_that_names_no_probe_of_the_round_is_dropped() {
        let _guard = ::habilis_network_test_tracing::init();
        let t1 = TokioInstant::now();
        let first = Message::new_ping(&MeshId::from("test"), &nick("alice"));
        let mut round = PingRound::new(&first, t1, t1 + Duration::from_secs(10), None);

        assert!(
            !round.record_pong(
                nick("bob"),
                &MessageId::random(),
                t1 + Duration::from_millis(5)
            ),
            "a pong naming an unknown probe is not recorded"
        );
        assert!(
            round.pongs.is_empty(),
            "no pong is recorded for an unknown probe"
        );
    }
}
