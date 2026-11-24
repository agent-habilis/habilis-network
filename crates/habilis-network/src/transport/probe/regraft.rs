//! Re-grafting the peers that fell out of the view.

use super::grafts;

use iroh::EndpointId;

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::{DirectState, EventLoopState};
use crate::transport::webrtc;
use crate::util::clock::Instant;

use crate::{lookup, transport};
/// Graft again the proven peers whose link went down about a second ago (see
/// [`EventLoopState::plan_regraft_on_link_loss`]). The reclaim ticker calls this, because
/// the heal tick would leave the pair apart for 10 to 15 s.
pub(crate) async fn regraft_due(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    for peer in state.take_regrafts_due(Instant::now()) {
        let Some(address) = state.member_address_of(peer) else {
            continue;
        };
        state.note_relink(peer, Instant::now());
        lookup::add_peer_addr(&state.address_book, address.clone());
        state.unicast_pool.note_addr(&address);
        tracing::debug!(target: transport::LOG_TARGET, %peer, "the link went down: grafting the proven peer again");
        if grafts::ensure_direct(state, context, peer, &address) {
            grafts::graft_proven(state, context, peer).await;
        }
    }
}

/// The member that the fill tick grafts next, among the free ones: a member that
/// is not linked, not the rendezvous and not on its relink cooldown. The natives
/// come before every browser, each group ordered by id, and `pick` indexes the
/// first group and wraps. A fixed pick would send every member below G to the
/// same few peers, and a full peer evicts a random neighbor on each join, so the
/// caller passes a random one. `None` once the active view holds `max_connections` (G)
/// peers, or when nobody is free.
pub(crate) fn next_fill(
    state: &EventLoopState,
    max_connections: usize,
    rendezvous_id: EndpointId,
    now: Instant,
    pick: usize,
) -> Option<iroh::EndpointAddr> {
    if state.linked_endpoints.len() >= max_connections {
        return None;
    }
    let peer_addresses = state.member_addresses();
    let candidates = peer_addresses.iter().filter(|address| {
        address.id != rendezvous_id && !state.linked_endpoints.contains(&address.id)
    });
    let cooled = candidates.filter(|address| !state.relink_on_cooldown(address.id, now));
    let mut free: Vec<&iroh::EndpointAddr> = cooled
        .filter(|address| !state.graft_blocked(address.id, now))
        .collect();
    free.sort_unstable_by_key(|address| {
        (webrtc::lane_needs::needs_webrtc_lane(address), address.id)
    });
    let first_group: usize = free.first().map_or(0, |first| {
        free.iter()
            .take_while(|address| {
                webrtc::lane_needs::needs_webrtc_lane(address)
                    == webrtc::lane_needs::needs_webrtc_lane(first)
            })
            .count()
    });
    free.get(pick.checked_rem(first_group)?)
        .map(|address| (*address).clone())
}

/// Graft one member toward G: the gossip active view is a target, not only a
/// cap. The attempt starts the member's relink cooldown, so a member that did
/// not link waits out the window before it is tried again, and the next tick
/// takes the next member.
pub(crate) async fn fill_active_view(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    let now = Instant::now();
    let pick = rand::Rng::random_range(&mut rand::rng(), 0..usize::MAX);
    let Some(address) = next_fill(
        state,
        context.max_connections,
        context.rendezvous_id,
        now,
        pick,
    ) else {
        return;
    };
    graft_one(state, context, address, now).await;
}

/// The member that a reclaim tick asks for a link when this node lost every one: the member
/// that the fill tick would pick, and none while the node holds a link or the window is closed.
pub(crate) fn isolated_candidate(
    state: &EventLoopState,
    max_connections: usize,
    rendezvous_id: EndpointId,
    now: Instant,
    pick: usize,
) -> Option<iroh::EndpointAddr> {
    if !state.isolated_refill_due(now) {
        return None;
    }
    next_fill(state, max_connections, rendezvous_id, now, pick)
}

/// One reclaim tick of a node that lost every link, as a decision: pick the member to ask.
pub(crate) fn isolated_tick(
    state: &mut EventLoopState,
    max_connections: usize,
    rendezvous_id: EndpointId,
    now: Instant,
    pick: usize,
) -> Option<iroh::EndpointAddr> {
    isolated_candidate(state, max_connections, rendezvous_id, now, pick)
}

/// Every filter of a fill or a retry pass that drops `address`, joined by `+`, or `candidate`
/// when none does. The passes differ (the fill has no `pending` filter), so each flag that holds
/// is named and the reader picks the filter of the pass that he reads.
fn candidate_reason(
    state: &EventLoopState,
    address: &iroh::EndpointAddr,
    rendezvous_id: EndpointId,
    now: Instant,
) -> String {
    let flags: [(bool, &str); 5] = [
        (address.id == rendezvous_id, "rendezvous"),
        (state.linked_endpoints.contains(&address.id), "linked"),
        (
            state.direct.get(&address.id) == Some(&DirectState::Pending),
            "pending",
        ),
        (state.relink_on_cooldown(address.id, now), "cooldown"),
        (state.graft_blocked(address.id, now), "blocked"),
    ];
    let mut held: Vec<&str> = Vec::new();
    for (holds, name) in flags {
        if holds {
            held.push(name);
        }
    }
    if held.is_empty() {
        "candidate".to_owned()
    } else {
        held.join("+")
    }
}

/// The reason of each known member, as `short id=reason` words, for a debug line that names the
/// filter that left a node with nobody to ask.
pub(crate) fn candidate_reasons(
    state: &EventLoopState,
    rendezvous_id: EndpointId,
    now: Instant,
) -> String {
    let words: Vec<String> = state
        .member_addresses()
        .iter()
        .map(|address| {
            let reason = candidate_reason(state, address, rendezvous_id, now);
            format!("{}={reason}", address.id.fmt_short())
        })
        .collect();
    words.join(" ")
}

/// A node that lost every link asks one other known peer per reclaim tick (400 ms) while the
/// fast window is open, with a low priority request that evicts nobody. The lost peers are
/// asked by the regraft, and they are full; the heal tick, 15 s later, was the first attempt to
/// reach a peer with a free slot. The relink cooldown sends each tick to another peer.
pub(crate) async fn refill_isolated(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    let now = Instant::now();
    let pick = rand::Rng::random_range(&mut rand::rng(), 0..usize::MAX);
    let Some(address) = isolated_tick(
        state,
        context.max_connections,
        context.rendezvous_id,
        now,
        pick,
    ) else {
        if state.isolated_refill_due(now) {
            tracing::debug!(
                target: transport::LOG_TARGET,
                local = %context.endpoint.id().fmt_short(),
                members = %candidate_reasons(state, context.rendezvous_id, now),
                "no link left: nobody to ask"
            );
        }
        return;
    };
    tracing::info!(target: transport::LOG_TARGET, peer = %address.id, "no link left: asking another known peer");
    graft_one(state, context, address, now).await;
}

/// Ask `addr` for a link now, and start its relink cooldown.
pub(crate) async fn graft_one(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    address: iroh::EndpointAddr,
    now: Instant,
) {
    state.note_relink(address.id, now);
    lookup::add_peer_addr(&state.address_book, address.clone());
    state.unicast_pool.note_addr(&address);
    tracing::debug!(target: transport::LOG_TARGET, peer = %address.id, linked = state.linked_endpoints.len(), "filling the active view");
    if grafts::ensure_direct(state, context, address.id, &address) {
        grafts::graft_proven(state, context, address.id).await;
    }
}

/// The peers one `retry_direct` pass probes, in a fixed order.
pub(crate) fn retry_candidates(
    state: &EventLoopState,
    rendezvous_id: EndpointId,
    max_connections: usize,
    distrust_links: bool,
) -> Vec<iroh::EndpointAddr> {
    retry_candidates_at(
        state,
        rendezvous_id,
        max_connections,
        distrust_links,
        Instant::now(),
    )
}

/// [`retry_candidates`] at `now`.
pub(crate) fn retry_candidates_at(
    state: &EventLoopState,
    rendezvous_id: EndpointId,
    max_connections: usize,
    distrust_links: bool,
    now: Instant,
) -> Vec<iroh::EndpointAddr> {
    // A graft is the reason for a session, and none runs at G.
    if !distrust_links && state.linked_endpoints.len() >= max_connections {
        return Vec::new();
    }
    let peer_addresses = state.member_addresses();
    let candidates = peer_addresses.iter().filter(|address| {
        address.id != rendezvous_id
            && (distrust_links || !state.linked_endpoints.contains(&address.id))
    });
    let webrtc_session = |address: &iroh::EndpointAddr| {
        state
            .webrtc
            .as_ref()
            .is_some_and(|handle| handle.has_session(&address.id))
    };
    let direct_ok = candidates.filter(|address| {
        state.direct.get(&address.id) != Some(&DirectState::Pending)
            || (webrtc::lane_needs::needs_webrtc_lane(address) && webrtc_session(address))
    });
    let cooled = direct_ok.filter(|address| !state.relink_on_cooldown(address.id, now));
    let mut peers: Vec<iroh::EndpointAddr> = cooled
        .filter(|address| !state.graft_blocked(address.id, now))
        .cloned()
        .collect();
    peers.sort_unstable_by_key(|address| address.id);
    peers
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use iroh::EndpointId;
    use iroh::endpoint::presets;
    use iroh_gossip::net::Gossip;
    use iroh_gossip::proto::TopicId;

    use super::{graft_one, isolated_tick, next_fill, retry_candidates_at};
    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::{DirectState, EventLoopState};
    use crate::gossip::event::CountingSink;
    use crate::protocol::identity::Identity;
    use crate::protocol::{MeshId, Nickname};
    use crate::testing::{endpoint_id, fresh_state, nick, test_key};
    use crate::transport::MeshSender;
    use crate::transport::probe::graft_request::{GraftRequest, GraftTarget, graft_request};
    use crate::util::clock::Instant;
    use crate::util::tuning::{GRAFT_REFUSED_AFTER, RELINK_COOLDOWN, STARVED};

    const MAX_CONNECTIONS: usize = 4;
    const SECOND: Duration = Duration::from_secs(1);
    /// The period of the reclaim tick, in milliseconds.
    const RECLAIM_MILLIS: u64 = 400;

    fn rendezvous() -> EndpointId {
        endpoint_id(1)
    }

    /// A node that links `peers` peers and knows one more member, `candidate`, that it is not
    /// linked to.
    fn state_with_a_member_to_fill(peers: u8) -> EventLoopState {
        let mut state = fresh_state();
        for seed in 10..10 + peers {
            state.linked_endpoints.insert(endpoint_id(seed));
        }
        state.names.insert(test_key("candidate"), nick("candidate"));
        state.bind_peer_endpoint(
            test_key("candidate"),
            nick("candidate"),
            iroh::EndpointAddr::new(endpoint_id(2)),
        );
        state
    }

    /// A node with no neighbor whose `Neighbor` request was read as refused asks with a `Join` at
    /// once, and does not wait for `STARVED`. A node with no neighbor and no refusal, and a node
    /// with a neighbor, keep the wait. The pace after the `Join` is the same as for any starved
    /// node. The test shows the rule, with a fixed clock. It does not show that a real mesh reaches
    /// that state and stays there. The first case is a new member at its start: it sends no `Join`.
    #[test]
    fn a_node_with_no_neighbor_and_a_read_refusal_asks_with_a_join_at_once() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let asked_at = start + SECOND;
        let read_at = asked_at + GRAFT_REFUSED_AFTER;
        let now = read_at + SECOND;
        let candidate = endpoint_id(2);

        let mut fresh = fresh_state();
        fresh.note_link_count(MAX_CONNECTIONS, start);
        assert!(
            !fresh.starved_join_ready(now),
            "a node with no neighbor and no refusal waits for STARVED"
        );

        let mut refused = fresh_state();
        refused.note_link_count(MAX_CONNECTIONS, start);
        refused.graft_backoff.asked(candidate, asked_at);
        refused.settle_graft_backoff(read_at);
        assert!(
            refused.starved_join_ready(now),
            "a node with no neighbor that was refused asks with a Join at once"
        );
        assert!(refused.starved_join_due(now), "the first ask is due");
        assert!(
            !refused.starved_join_ready(now + SECOND),
            "the ask is paced: the next one waits for STARVED"
        );

        let mut linked = state_with_a_member_to_fill(1);
        linked.note_link_count(MAX_CONNECTIONS, start);
        linked.graft_backoff.asked(candidate, asked_at);
        linked.settle_graft_backoff(read_at);
        assert!(
            !linked.starved_join_ready(now),
            "a node with a neighbor waits for STARVED, refused or not"
        );
    }

    /// The fill tick grafts a member while the node holds fewer than G peers.
    #[test]
    fn the_fill_tick_grafts_a_member_at_g_minus_one_peers() {
        let _guard = ::habilis_network_test_tracing::init();
        let state = state_with_a_member_to_fill(3);

        let next = next_fill(&state, MAX_CONNECTIONS, rendezvous(), Instant::now(), 0);

        assert_eq!(
            next.map(|address| address.id),
            Some(endpoint_id(2)),
            "G - 1 peers leave a slot"
        );
    }

    /// Control: at G peers the view is full.
    #[test]
    fn the_fill_tick_grafts_nobody_at_g_peers() {
        let _guard = ::habilis_network_test_tracing::init();
        let state = state_with_a_member_to_fill(4);

        let next = next_fill(&state, MAX_CONNECTIONS, rendezvous(), Instant::now(), 0);

        assert_eq!(next, None, "G peers fill the view");
    }

    /// The retry of the alive tick asks the unlinked members while the node holds fewer than G
    /// peers, and none at G.
    #[test]
    fn the_retry_asks_a_member_at_g_minus_one_peers_and_none_at_g() {
        let _guard = ::habilis_network_test_tracing::init();
        let now = Instant::now();
        let short = state_with_a_member_to_fill(3);
        let full = state_with_a_member_to_fill(4);

        let asked = retry_candidates_at(&short, rendezvous(), MAX_CONNECTIONS, false, now);
        let none = retry_candidates_at(&full, rendezvous(), MAX_CONNECTIONS, false, now);

        assert_eq!(
            asked.len(),
            1,
            "G - 1 peers leave a slot: the member is asked"
        );
        assert!(none.is_empty(), "G peers fill the view: nobody is asked");
    }

    /// A starved node whose fallback is due asks a peer that refused it, which the backoff leaves
    /// alone otherwise. The graft that follows sets the relink cooldown (10 s), so the next pass
    /// does not ask the peer again, and the `Join` of that graft stamps the fallback, so the
    /// backoff holds the peer again: the dial of a refusing peer is once per window, as long as
    /// the graft goes out. A peer with no direct path gets no graft and no cooldown, and is
    /// probed on each pass like any relay-only peer. This test pins the bound that exists for a
    /// peer with a direct path; it has no red step, since the bound was there already.
    #[test]
    fn a_starved_node_retries_a_refusing_peer_with_a_direct_path_once_per_window() {
        let _guard = ::habilis_network_test_tracing::init();
        let start = Instant::now();
        let asked_at = start + STARVED;
        let now = asked_at + GRAFT_REFUSED_AFTER + SECOND;
        let candidate = endpoint_id(2);
        let mut state = state_with_a_member_to_fill(3);
        state.below_target_since = Some(start);
        state.graft_backoff.asked(candidate, asked_at);
        state.settle_graft_backoff(asked_at + GRAFT_REFUSED_AFTER);
        assert!(
            state.starved_join_ready(now),
            "the node is starved, refused and has not fallen back yet"
        );
        let pass = |view: &EventLoopState, at: Instant| {
            retry_candidates_at(view, rendezvous(), MAX_CONNECTIONS, false, at)
        };

        let first = pass(&state, now);
        state.note_relink(candidate, now);
        let during_the_cooldown = pass(&state, now + SECOND);
        assert!(
            state.starved_join_due(now),
            "the graft of the first pass is the fallback"
        );
        let after_the_cooldown = pass(&state, now + RELINK_COOLDOWN + SECOND);

        assert_eq!(
            first.len(),
            1,
            "the fallback is due: the refusing peer is asked"
        );
        assert!(
            during_the_cooldown.is_empty(),
            "the relink cooldown of the graft holds the peer for the next pass"
        );
        assert!(
            after_the_cooldown.is_empty(),
            "the fallback went out: the backoff holds the refusing peer again"
        );
    }

    /// A node on a peerless topic, with the borrows of a `HandlerCtx`, and `max_connections` set.
    struct Node {
        endpoint: iroh::Endpoint,
        _gossip: Gossip,
        sender: MeshSender,
        mesh: MeshId,
        identity: Identity,
        author: Nickname,
        sink: CountingSink,
    }

    impl Node {
        async fn spawn() -> Self {
            let endpoint = iroh::Endpoint::builder(presets::Minimal)
                .bind()
                .await
                .expect("bind a local endpoint");
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let topic = gossip
                .subscribe(TopicId::from_bytes([4u8; 32]), vec![])
                .await
                .expect("subscribe to a peerless topic");
            let (gossip_sender, _receiver) = topic.split();
            Self {
                endpoint,
                _gossip: gossip,
                sender: MeshSender::new(gossip_sender),
                mesh: MeshId::from("test"),
                identity: Identity::generate(),
                author: nick("member"),
                sink: CountingSink::new(),
            }
        }

        fn context(&self) -> HandlerCtx<'_> {
            HandlerCtx {
                sender: &self.sender,
                endpoint: &self.endpoint,
                mesh: &self.mesh,
                author: &self.author,
                identity: &self.identity,
                our_pubkey: self.identity.author_key(),
                max_connections: MAX_CONNECTIONS,
                rendezvous_id: rendezvous(),
                external_msg_tx: None,
                sink: &self.sink,
            }
        }
    }

    /// The fill tick grafts a peer whose path is already known, and that is no new proof of the
    /// path. A node 1 peer short whose only candidate refused it lately, and whose fallback is
    /// due, asks that candidate with a `Join`: the graft must not drop the refusal, as a new
    /// proof of the path does. The `Join` stamps the fallback.
    #[test]
    fn the_fill_tick_keeps_the_refusal_of_a_peer_whose_path_it_did_not_prove_again() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            // The `Join` dials a peer that does not exist: the dial fails, and says so.
            ::habilis_network_test_tracing::allow_warn("iroh_gossip::net", "dial failed");
            let node = Node::spawn().await;
            let context = node.context();
            let now = Instant::now();
            let candidate = endpoint_id(2);
            let mut state = state_with_a_member_to_fill(3);
            state.direct.insert(candidate, DirectState::Direct);
            // The node is starved since over STARVED, and the candidate refused it 5 s ago.
            state.below_target_since = now.checked_sub(STARVED + SECOND);
            state.graft_backoff.asked(
                candidate,
                now.checked_sub(GRAFT_REFUSED_AFTER * 2).unwrap_or(now),
            );
            state.settle_graft_backoff(now.checked_sub(SECOND * 5).unwrap_or(now));
            assert!(state.starved_join_ready(now), "the fallback is due");
            let socket = SocketAddr::from(([192, 0, 2, 7], 4000));
            let address = iroh::EndpointAddr::new(candidate).with_ip_addr(socket);

            graft_one(&mut state, &context, address, now).await;

            let fell_back = state.join_fallback_at.is_some();
            node.endpoint.close().await;
            assert!(
                fell_back,
                "the graft of a known path dropped the refusal, so the fallback asked a Neighbor"
            );
        });
    }
    /// What one run of [`join_delay`] saw.
    struct JoinRun {
        /// From the first `Neighbor` request to the first `Join`, if a `Join` went out.
        delay: Option<Duration>,
        /// The `Join` requests in the 60 s of the run.
        joins: usize,
        /// The members that the reclaim tick and the heal tick picked.
        picks: usize,
        /// Whether each `Join` went to a member that reads `Direct`.
        joins_to_direct: bool,
        /// The member of the first `Join`.
        join_target: Option<EndpointId>,
        /// The `Neighbor` requests to that member after the `Join`.
        asks_after_join: usize,
    }

    /// The `Join` of a node that lost every link goes out within one reclaim tick of the end of the
    /// wait that reads its first request as refused, whatever the phase of the reclaim tick (400 ms)
    /// and of the heal tick (15 s), and whichever member the tick picks. The next `Join` waits for
    /// `STARVED` (`join_fallback_at`, read by `starved_join_ready`), so the reclaim ticks that go
    /// on for 40 s after the `Join` send none.
    ///
    /// The run of 2026-11-24 asked first at 27:48.94 and asked with the `Join` at 28:16.34, 27.4 s
    /// later, because only the heal tick read the refusals: a delay from 20 s to 35 s, by the phase
    /// of the heal tick. The guard of a silent partition fails the test at 25 s. In that run 2 of
    /// the 3 members were cut, so the table has 0, 1, 2 and 3 members that read `RelayOnly`, and
    /// the pick of the member goes through the check that production makes (a `Direct` member is
    /// asked, any other is probed and not asked). The clock is a parameter, so the 152 phases of
    /// each case need no sleep.
    #[test]
    fn the_join_of_a_node_with_no_link_goes_out_one_reclaim_tick_after_the_refusal_is_due() {
        let _guard = ::habilis_network_test_tracing::init();
        let tick = Duration::from_millis(RECLAIM_MILLIS);
        for relay_only in 0..=3_usize {
            let mut shortest = Duration::MAX;
            let mut longest = Duration::ZERO;
            let mut most_picks = 0;
            let mut most_joins = 0;
            let mut most_asks_after_join = 0;
            let mut targets: Vec<EndpointId> = Vec::new();
            for pick in 0..3 {
                for reclaim_phase in [0, 100, 200, 300] {
                    for heal_phase in (0..38).map(|step| step * RECLAIM_MILLIS) {
                        let run = join_delay(reclaim_phase, heal_phase, relay_only, pick);
                        let case = format!(
                            "{relay_only} relay-only, pick {pick}, reclaim phase {reclaim_phase} ms, heal phase {heal_phase} ms"
                        );
                        assert!(
                            run.joins_to_direct,
                            "a Join goes to a Direct member ({case})"
                        );
                        shortest = shortest.min(run.delay.unwrap_or(Duration::MAX));
                        longest = longest.max(run.delay.unwrap_or(Duration::ZERO));
                        most_picks = most_picks.max(run.picks);
                        most_joins = most_joins.max(run.joins);
                        most_asks_after_join = most_asks_after_join.max(run.asks_after_join);
                        if let Some(target) = run.join_target
                            && !targets.contains(&target)
                        {
                            targets.push(target);
                        }
                    }
                }
            }
            eprintln!(
                "Join delay with {relay_only} relay-only of 3: min {shortest:?}, max {longest:?}, most picks in 60 s {most_picks}, most Joins {most_joins}, most Neighbor asks to the Join target after it {most_asks_after_join}, members that got a Join {}",
                targets.len()
            );
            assert_eq!(
                most_asks_after_join, 0,
                "the member that got the Join is not asked again with a Neighbor request ({relay_only} relay-only)"
            );
            assert_eq!(
                targets.len(),
                3 - relay_only,
                "over the pick values, each member that reads Direct gets a Join ({relay_only} relay-only)"
            );
            if relay_only == 3 {
                assert_eq!(most_joins, 0, "no member reads Direct, so no Join goes out");
            } else {
                assert_eq!(
                    most_joins, 1,
                    "one Join in 60 s, and no repeat ({relay_only} relay-only)"
                );
                assert!(
                    shortest >= GRAFT_REFUSED_AFTER,
                    "the Join waits for the read of the refusal ({relay_only} relay-only): min {shortest:?}, max {longest:?}"
                );
                assert!(
                    longest <= GRAFT_REFUSED_AFTER + tick,
                    "the Join goes out within one reclaim tick of the refusal, and one more for each member that is not asked ({relay_only} relay-only): min {shortest:?}, max {longest:?}"
                );
            }
        }
    }

    /// One run of 60 s of a node with 3 known members and no link, of which the last `relay_only`
    /// read `RelayOnly` and the others `Direct`. The reclaim tick picks with `pick`, and the
    /// reclaim tick and the heal tick run at the given phases, as the event loop runs them.
    fn join_delay(reclaim_phase: u64, heal_phase: u64, relay_only: usize, pick: usize) -> JoinRun {
        const WINDOW: u64 = 60_000;
        let start = Instant::now();
        let mut state = fresh_state();
        for (index, (name, seed)) in [("one", 2), ("two", 3), ("three", 4)]
            .into_iter()
            .enumerate()
        {
            state.names.insert(test_key(name), nick(name));
            state.bind_peer_endpoint(
                test_key(name),
                nick(name),
                iroh::EndpointAddr::new(endpoint_id(seed)),
            );
            let verdict = if index + relay_only >= 3 {
                DirectState::RelayOnly
            } else {
                DirectState::Direct
            };
            state.direct.insert(endpoint_id(seed), verdict);
        }
        state.note_link_count(MAX_CONNECTIONS, start);
        state.start_zero_links_gap_at(start);
        state.arm_reclaim(start);
        let mut first_ask: Option<Instant> = None;
        let mut joins: Vec<Instant> = Vec::new();
        let mut picks = 0;
        let mut joins_to_direct = true;
        let mut join_target: Option<EndpointId> = None;
        let mut asks_after_join = 0;
        // What `graft_one` does with a member: it starts the relink cooldown, and asks only a
        // member that reads `Direct` (`ensure_direct`).
        let mut graft = |state: &mut EventLoopState, peer: EndpointId, now: Instant| {
            state.note_relink(peer, now);
            picks += 1;
            if state.direct.get(&peer) != Some(&DirectState::Direct) {
                return;
            }
            let target = GraftTarget {
                peer,
                rendezvous: rendezvous(),
            };
            match graft_request(state, target, MAX_CONNECTIONS, now, true) {
                GraftRequest::Neighbor => {
                    first_ask.get_or_insert(now);
                    if join_target == Some(peer) {
                        asks_after_join += 1;
                    }
                }
                GraftRequest::Join => {
                    joins.push(now);
                    join_target.get_or_insert(peer);
                    joins_to_direct &= state.direct.get(&peer) == Some(&DirectState::Direct);
                }
                GraftRequest::Skip => {}
            }
        };
        for millis in (0..WINDOW).step_by(100) {
            let now = start + Duration::from_millis(millis);
            if millis >= reclaim_phase
                && (millis - reclaim_phase).is_multiple_of(RECLAIM_MILLIS)
                && let Some(address) =
                    isolated_tick(&mut state, MAX_CONNECTIONS, rendezvous(), now, pick)
            {
                graft(&mut state, address.id, now);
            }
            if millis >= heal_phase && (millis - heal_phase).is_multiple_of(15_000) {
                state.note_link_count(MAX_CONNECTIONS, now);
                state.settle_graft_backoff(now);
                let candidates =
                    retry_candidates_at(&state, rendezvous(), MAX_CONNECTIONS, false, now);
                if let Some(address) = candidates.first() {
                    graft(&mut state, address.id, now);
                }
            }
        }
        let delay = first_ask
            .zip(joins.first())
            .map(|(asked, joined)| joined.duration_since(asked));
        JoinRun {
            delay,
            joins: joins.len(),
            picks,
            joins_to_direct,
            join_target,
            asks_after_join,
        }
    }
}
