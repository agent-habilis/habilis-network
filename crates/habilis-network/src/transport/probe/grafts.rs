//! Grafting a peer once its direct path is proven.

use super::direct_outcome::DirectOutcome;
use super::graft_request::{GraftRequest, GraftTarget};
use super::{graft_request, lanes, regraft};

use iroh::EndpointId;

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::{DirectState, EventLoopState};
use crate::transport::payload_path::{PROBE_DEADLINE, wait_direct};
use crate::transport::webrtc;
use crate::util::clock::Instant;

use crate::transport;
use iroh_gossip::api;
use n0_future::task;
/// Pure: may a peer be grafted, from what is known right now? A `WebRTC`
/// pair needs its session attached; an IP pair needs a proven direct path.
pub(crate) fn may_graft(known_direct: bool, has_session: bool, needs_webrtc: bool) -> bool {
    if needs_webrtc {
        has_session
    } else {
        known_direct
    }
}

/// Whether `peer` may be grafted right now. `false` means a probe is in
/// flight or a `WebRTC` session is still being negotiated; the loop grafts on
/// the [`DirectOutcome`] that follows, or the alive tick retries.
pub(crate) fn ensure_direct(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    peer: EndpointId,
    peer_addr: &iroh::EndpointAddr,
) -> bool {
    if state.relay_transport.relay_allowed() {
        return true;
    }
    let needs_webrtc = webrtc::lane_needs::needs_webrtc_lane(peer_addr)
        || webrtc::lane_needs::needs_webrtc_lane(&context.endpoint.addr());
    let has_session = state
        .webrtc
        .as_ref()
        .is_some_and(|handle| handle.has_session(&peer));
    let known = state.direct.get(&peer).copied();
    if may_graft(
        known == Some(DirectState::Direct),
        has_session,
        needs_webrtc,
    ) {
        state.direct.insert(peer, DirectState::Direct);
        return true;
    }
    if needs_webrtc || known == Some(DirectState::Pending) {
        // A browser peer proves itself through `negotiate_session`; an IP peer's probe is already
        // running. A graft is the one proactive reason for a session (the exception of plan D4 for
        // gossip links), as a held frame is: a cold pair that nobody sends to would stay `Pending`
        // for ever, and no member would link to another.
        state.direct.entry(peer).or_insert(DirectState::Pending);
        if needs_webrtc {
            state.want_lane_session(peer, Instant::now());
            webrtc::negotiate_session::negotiate_session(state, context, peer, peer_addr.clone());
        }
        return false;
    }
    // At its ceiling the node probes nobody: a probe evicts nobody, and a verdict that it did not
    // run is none. The alive tick asks again when a unit is free.
    if !state.unicast_pool.has_room_for_unprompted_dial(peer) {
        return false;
    }
    state.direct.insert(peer, DirectState::Pending);
    let pool = state.unicast_pool.clone();
    let tx = state.direct_proven.clone();
    task::spawn(async move {
        let direct = match pool.probe_connection(peer).await {
            Ok(connection) => wait_direct(&connection, PROBE_DEADLINE).await,
            Err(error) => {
                tracing::debug!(target: transport::LOG_TARGET, %peer, %error, "direct-path probe could not connect");
                false
            }
        };
        // The graft that follows a proven path forms its link inside the probe
        // hold, and the probe's own connection goes after it unless a send took it.
        pool.probe_done(peer).await;
        let _ = tx.send(DirectOutcome {
            peer,
            direct,
            answered: false,
        });
    });
    false
}

/// Apply a probe's verdict: a proven peer is grafted, an unproven one is
/// recorded `RelayOnly` for the alive tick to retry, unless it proved itself
/// another way while the probe ran.
pub(crate) async fn on_outcome(
    outcome: DirectOutcome,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    if !outcome.applies(state, Instant::now()) {
        return;
    }
    let DirectOutcome { peer, direct, .. } = outcome;
    if direct {
        graft_proven(state, context, peer).await;
    } else if state.demote_unproven(peer) {
        tracing::info!(target: transport::LOG_TARGET, %peer, "no direct path within the probe deadline; peer stays relay-only");
    } else {
        tracing::debug!(target: transport::LOG_TARGET, %peer, "late probe verdict ignored; the peer is no longer pending");
    }
}

/// Ask gossip for the link to `peer`, in the way [`graft_request()`] says.
pub(crate) async fn request_graft(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    peer: EndpointId,
    paced: bool,
) -> Result<(), api::ApiError> {
    if peer != context.rendezvous_id && state.rides_gossip_rung(peer) {
        tracing::debug!(target: transport::LOG_TARGET, %peer, "graft skipped: the pair rides the gossip rung");
        return Ok(());
    }
    match graft_request(
        state,
        GraftTarget {
            peer,
            rendezvous: context.rendezvous_id,
        },
        context.max_connections,
        Instant::now(),
        paced,
    ) {
        GraftRequest::Join => context.sender.join_peers(vec![peer]).await,
        GraftRequest::Neighbor => context.sender.neighbor_peers(vec![peer]).await,
        GraftRequest::Force => context.sender.force_neighbor_peer(peer).await,
        GraftRequest::Skip => Ok(()),
    }
}

/// Record `peer` as `Direct`, graft it if it is not linked already and there
/// is room, and flush any frame parked for it.
pub(crate) async fn graft_proven(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    peer: EndpointId,
) {
    state.note_path_proven(peer);
    // A session to the rendezvous that attached after this node let go of it
    // must not graft it again: every graft of the rendezvous waits for
    // `rendezvous_wanted`.
    if peer == context.rendezvous_id && !state.rendezvous_wanted() {
        return;
    }
    // The rendezvous is asked for at the cap too: a member at its cap may return to it and hold it,
    // and the link takes no unit (see `Ceiling::set_rendezvous`). Without it, once every member
    // let go of the rendezvous, nobody could return and a late joiner saw an empty mesh.
    if !state.linked_endpoints.contains(&peer)
        && (peer == context.rendezvous_id || state.linked_endpoints.len() < context.max_connections)
    {
        state.note_relink(peer, Instant::now());
        if let Err(error) = request_graft(state, context, peer, true).await {
            tracing::warn!(target: transport::LOG_TARGET, %peer, %error, "graft request failed");
        }
    }
}

/// The alive-tick retry: every known peer that is neither linked nor mid-probe
/// gets another `ensure_direct`, subject to the relink cooldown. While the relay
/// may carry payload there is no probe to hold a graft, so the tick fills the
/// active view instead, one member per tick (see `fill_active_view`). The
/// rendezvous is skipped: it accepts no unicast, so it cannot be probed; its
/// link is gated on the beacon's side.
///
/// With `distrust_links` (the re-bridge after a resume or starvation) every
/// link and proven path is stale by definition, so linked peers are retried
/// too and their `Direct` verdicts are forgotten first, or `ensure_direct`
/// would trust the pre-sleep answer.
pub(crate) async fn retry_direct(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    distrust_links: bool,
) {
    // Every alive tick, so that the clock of a starved node does not outlive its cause.
    let now = Instant::now();
    state.note_link_count(state.linked_endpoints.len(), context.max_connections, now);
    state.settle_graft_backoff(now);
    if state.relay_transport.relay_allowed() {
        regraft::fill_active_view(state, context).await;
        return;
    }
    // The lane offers are paced: a browser pays an ICE gathering budget per round. The members
    // left out are not touched, so that no `Pending` mark hides them from the next pass.
    let (lane, rest): (Vec<_>, Vec<_>) = regraft::retry_candidates(
        state,
        context.rendezvous_id,
        context.max_connections,
        distrust_links,
    )
    .into_iter()
    .partition(|address| lanes::is_lane_offer(state, context, address));
    for address in rest {
        lanes::retry_one(state, context, address, distrust_links).await;
    }
    let pick = lanes::lane_pick();
    for address in lanes::plan_lane_offers(lane, state.webrtc_admission.in_flight(), pick) {
        lanes::retry_one(state, context, address, distrust_links).await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::{Endpoint, EndpointId, RelayMode};
    use iroh_gossip::api::GossipReceiver;
    use iroh_gossip::net::{GOSSIP_ALPN, Gossip};
    use iroh_gossip::proto::{self, HyparviewConfig};
    use n0_future::{StreamExt, time};

    use crate::daemon::handler_ctx;
    use crate::gossip::event;
    use crate::protocol::MeshId;
    use crate::protocol::identity::Identity;
    use crate::util::clock::Instant;
    use crate::{lookup, testing, transport};

    const TOPIC: [u8; 32] = [8; 32];

    /// A gossip node on a loopback endpoint, whose active view holds `capacity` links.
    async fn node(capacity: usize) -> (Router, Gossip) {
        let endpoint_builder = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup();
        let endpoint = endpoint_builder
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let config = HyparviewConfig {
            active_view_capacity: capacity,
            ..HyparviewConfig::default()
        };
        let gossip_builder = Gossip::builder().membership_config(config);
        let gossip: Gossip = gossip_builder.spawn(endpoint.clone());
        let handler = gossip.clone();
        let router: Router = Router::builder(endpoint)
            .accept(GOSSIP_ALPN, handler)
            .spawn();
        (router, gossip)
    }

    fn know(of: &Router, other: &Router) {
        lookup::add_peer_addr(
            &lookup::address_book(of.endpoint()),
            other.endpoint().addr(),
        );
    }

    /// The receiver tracks its neighbors as it reads events, so the wait reads them.
    async fn until_linked(receiver: &mut GossipReceiver, peer: EndpointId) -> bool {
        for _ in 0..100 {
            if receiver.neighbors().any(|neighbor| neighbor == peer) {
                return true;
            }
            let _ = time::timeout(Duration::from_millis(100), receiver.next()).await;
        }
        false
    }

    /// Two members are linked to each other and hold their only slot. A third member short of G
    /// with no link gained for its window grafts the first: the graft is a high priority request,
    /// the full peer drops its neighbor, and the third member is linked. A low priority request is
    /// refused by a full peer, and the same graft would leave the third member without a link for
    /// ever.
    #[test]
    fn a_forced_graft_gets_a_link_from_a_full_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (full, full_gossip) = node(1).await;
            let (neighbor, neighbor_gossip) = node(1).await;
            let (short, short_gossip) = node(1).await;
            know(&neighbor, &full);
            know(&short, &full);
            let topic = proto::TopicId::from_bytes(TOPIC);
            let (_full_sender, _full_receiver) = full_gossip
                .subscribe(topic, vec![])
                .await
                .expect("subscribe the full peer")
                .split();
            let bootstrap = vec![full.endpoint().id()];
            let (_neighbor_sender, mut neighbor_receiver) = neighbor_gossip
                .subscribe(topic, bootstrap)
                .await
                .expect("subscribe the neighbor")
                .split();
            assert!(
                until_linked(&mut neighbor_receiver, full.endpoint().id()).await,
                "the neighbor holds the only slot of the full peer"
            );
            let (short_sender, mut short_receiver) = short_gossip
                .subscribe(topic, vec![])
                .await
                .expect("subscribe the short member")
                .split();

            let sender = transport::MeshSender::new(short_sender);
            let mesh = MeshId::from("test");
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let author = testing::nick("short");
            let sink = event::SilentSink;
            let context = handler_ctx::HandlerCtx {
                sender: &sender,
                endpoint: short.endpoint(),
                mesh: &mesh,
                author: &author,
                identity: &identity,
                our_pubkey,
                max_connections: 1,
                rendezvous_id: testing::endpoint_id(9),
                external_msg_tx: None,
                sink: &sink,
            };
            let mut state = testing::fresh_state();
            state.force_jitter = 0.0;
            state.short_since = Instant::now().checked_sub(Duration::from_mins(2));

            super::request_graft(&mut state, &context, full.endpoint().id(), true)
                .await
                .expect("the graft is sent");

            assert!(
                until_linked(&mut short_receiver, full.endpoint().id()).await,
                "a full peer that gets the forced request drops its neighbor and links the short member"
            );
            let _ = tokio::join!(full.shutdown(), neighbor.shutdown(), short.shutdown());
        });
    }
}
