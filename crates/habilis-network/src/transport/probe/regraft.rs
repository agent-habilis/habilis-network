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

/// A node that lost every link asks one other known peer per reclaim tick (400 ms) while the
/// fast window is open, with a low priority request that evicts nobody. The lost peers are
/// asked by the regraft, and they are full; the heal tick, 15 s later, was the first attempt to
/// reach a peer with a free slot. The relink cooldown sends each tick to another peer.
pub(crate) async fn refill_isolated(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    let now = Instant::now();
    let pick = rand::Rng::random_range(&mut rand::rng(), 0..usize::MAX);
    let Some(address) = isolated_candidate(
        state,
        context.max_connections,
        context.rendezvous_id,
        now,
        pick,
    ) else {
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

    use super::{graft_one, next_fill, retry_candidates_at};
    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::{DirectState, EventLoopState};
    use crate::gossip::event::CountingSink;
    use crate::protocol::identity::Identity;
    use crate::protocol::{MeshId, Nickname};
    use crate::testing::{endpoint_id, fresh_state, nick, test_key};
    use crate::transport::MeshSender;
    use crate::util::clock::Instant;
    use crate::util::tuning::{GRAFT_REFUSED_AFTER, RELINK_COOLDOWN, STARVED};

    const MAX_CONNECTIONS: usize = 4;
    const SECOND: Duration = Duration::from_secs(1);

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
}
