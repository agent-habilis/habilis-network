use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::{EventLoopState, Standing};
use crate::gossip::app::NodeApp;
use crate::gossip::event::NodeEvent;
use crate::logging::messages;
use crate::protocol::messages::Verified;
use crate::protocol::{AuthorKey, Message, Nickname, PresenceSubtype};
use crate::transport;
use iroh::EndpointId;

use super::membership_update;

use crate::gossip;
use crate::util::clock::Instant;

/// A received `Presence` frame plus the roster delta `membership_update::observe`
/// already computed for it, passed to [`handle_presence`]. Constructed by
/// `crate::gossip::recv::ingest`, across the `gossip`/`lifecycle` module
/// boundary — hence `pub(crate)` rather than module-private.
#[derive(Debug, Clone)]
pub(crate) struct PresenceEvent<'message> {
    pub(crate) message: &'message Verified,
    pub(crate) subtype: PresenceSubtype,
    pub(crate) update: &'message membership_update::MembershipUpdate,
    pub(crate) surfaceable: bool,
}

/// The `joined` that shows again a session that was shown already, signed by this node as for a departure.
fn rearrival(key: AuthorKey, nickname: &Nickname, context: &HandlerCtx<'_>) -> NodeEvent {
    let joined = Message::new_joined(context.mesh, nickname).sign(context.identity);
    NodeEvent::Presence {
        message: Box::new(joined.authored()),
        peer: key,
        synthetic: true,
    }
}

/// The presence that reports a departure. The roster knows the key by `departed`, and a goodbye can
/// name another nickname. Then this node signs the `left` that reports it, as it does for an
/// arrival, so that the proof names the peer that was removed.
fn departure(
    goodbye: &Goodbye<'_>,
    key: AuthorKey,
    departed: &Nickname,
    context: &HandlerCtx<'_>,
) -> NodeEvent {
    if let Goodbye::Signed(message) = goodbye
        && message.author == *departed
    {
        return NodeEvent::Presence {
            message: Box::new(message.authored()),
            peer: key,
            synthetic: false,
        };
    }
    let left = Message::new_left(context.mesh, departed).sign(context.identity);
    NodeEvent::Presence {
        message: Box::new(left.authored()),
        peer: key,
        synthetic: true,
    }
}

/// End the pooled connection, the dial cooldown and the multihop origin of each endpoint that no
/// nickname binds. A graceful goodbye, unlike a silence timeout, drops the dial hint, and with it
/// the warm unicast connection, so a rejoin re-dials cold. The advertised links go too, or routes
/// keep running through a peer that said goodbye until its vector ages out.
async fn end_unbound_endpoints(state: &mut EventLoopState, endpoints: Vec<EndpointId>) {
    let unbound: Vec<_> = endpoints
        .into_iter()
        .filter(|endpoint_id| !state.endpoint_is_bound(*endpoint_id))
        .collect();
    for endpoint_id in unbound {
        state.unicast_pool.forget(endpoint_id).await;
        #[cfg(feature = "multihop")]
        if let Some(handle) = state.multihop.as_ref() {
            let _ = handle.remove_origin(habilis_network_iroh_multihop_transport::AppId::new(
                endpoint_id,
            ));
        }
    }
}

/// How the end of a session is told: by the `left` frame that the session signed, or by a newer run
/// of its member that replaced it.
pub(crate) enum Goodbye<'source> {
    Signed(&'source Verified),
    /// The newer session that replaced it, named by its author.
    Replaced(&'source Nickname),
    /// A session of another member under a nickname that a proof bound away from it. It said no goodbye, so its
    /// frames are not marked as stale, and a session that was shown ends with a `left` line (before the arrival
    /// of the member that proved the name). One that was never shown ends with none. The caller shows the member
    /// again, once, when it was shown already ([`show_again`]).
    Refused(&'source Nickname),
}

impl Goodbye<'_> {
    fn nickname(&self) -> &Nickname {
        match self {
            Self::Signed(message) => &message.author,
            Self::Replaced(nickname) | Self::Refused(nickname) => nickname,
        }
    }
}

/// End the session `key` in the roster, for a goodbye that it signed or for a newer run of its member.
/// The roster is keyed by author key, so this ends that key and no other: another key under the same
/// nickname stays a peer. Any key can sign a goodbye under any nickname, and the goodbye of a key that
/// is not in the roster removes nothing. True when it showed a `left` line for the session.
pub(crate) async fn end_session(
    key: AuthorKey,
    goodbye: Goodbye<'_>,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) -> bool {
    // A key says goodbye once per run. A second copy is a replay that a peer still held.
    if state.key_said_goodbye(key) {
        return false;
    }
    // A session that lost its nickname said no goodbye, and no other node drops its frames: a peer that
    // holds them would resend them to this node at every digest round while the holder keeps the name.
    if !matches!(goodbye, Goodbye::Refused(_)) {
        state.drop_departed_presence(&key);
    }
    // The roster is keyed by author key, so a goodbye ends that key and no other: another key
    // under the same nickname stays a peer. Any key can sign a goodbye under any nickname, and
    // the goodbye of a key that is not in the roster removes nothing. It is kept apart from
    // the goodbyes of peers, so a flood of them cannot evict those. A key that outlived the
    // quiet TTL is still in the roster: it keeps its name and its dial hint.
    let was_peer = state.peers.contains(&key)
        || state.quiet.contains(&key)
        || state.clock_evidence.lapsed_quiet.contains(&key);
    if !was_peer {
        state.note_stranger_left(key);
        // A `PeerInfo` can bind a hint before the roster admits its key, and the hint of a
        // key that said goodbye must not stay routable.
        let stranger_hints = state.forget_hints_of(key);
        // The same `PeerInfo` can have left an endpoint that the roster never admitted, retained
        // for the key: it goes too, with the state of an endpoint that nothing else binds, and with its
        // pooled connection and cooldown (`end_unbound_endpoints` keeps the shared-endpoint check).
        let retained = state.release_refused_endpoint(&key);
        let hinted = stranger_hints.iter().map(|hint| hint.id);
        end_unbound_endpoints(state, hinted.chain(retained).collect()).await;
        return false;
    }
    // A session that lost its nickname to another member did not say goodbye: it is only taken out of the
    // roster, so its later frames go through the admission again (refused while the other member holds the
    // name, admitted when that member is gone). A goodbye marks every later frame of the key stale for good.
    if !matches!(goodbye, Goodbye::Refused(_)) {
        state.note_left(key);
    }
    let was_surfaced = state.surfaced.contains(&key);
    // The roster knows the key by the nickname it recorded, and a goodbye can name any
    // nickname. `forget_key` drops the record, so read it first.
    let recorded = state.names.get(&key);
    let departed = recorded.unwrap_or(goodbye.nickname()).clone();
    // A key that renamed left one endpoint for each nickname it used, and it can have proved an
    // endpoint without owning a hint, when another key held its nickname. Each one is torn
    // down, unless a nickname still binds it. `forget_key` drops the trust, so read it first.
    let proved = state.proven_endpoints.trusted(&key);
    let left_hints = state.forget_key(key);
    let hinted = left_hints.iter().map(|hint| hint.id);
    let left_endpoints: Vec<_> = hinted.chain(proved).collect();
    end_unbound_endpoints(state, left_endpoints).await;
    // Only announce a departure for a peer whose arrival we
    // surfaced — keeps the join-horizon view symmetric. A `left`
    // for a peer known only through pre-join backlog (or one we
    // already showed going quiet) is dropped. A session that a proof of another member ended is shown
    // leaving like any other: every `joined` that was shown gets its `left`.
    if was_surfaced {
        context
            .sink
            .emit(departure(&goodbye, key, &departed, context));
        tracing::info!(target: "habilis_network::lifecycle", nickname = %departed, "peer left");
    }
    state.write_peer_count();
    // A departure is a flush edge: the frames to the key that left are gone from the buffer
    // (`forget_key`), and the rest go now.
    if state.standing.contains(&Standing::Meshed) && !state.pending_outbound.is_empty() {
        gossip::flush_pending(state, context, "peer left").await;
    }
    // App cleanup last, with the roster already consistent. The app hears of every key that
    // leaves, whoever else holds its nickname. Not gated on `surfaceable`: the key was in the
    // roster, so a goodbye ends it whatever the clock of its sender says. The join horizon
    // hides a line from the user, and it does not hide a fact from the app.
    app.on_peer_left(&key, &departed, state, context).await;
    was_surfaced
}

/// Show the `joined` of the session `key` again, if it was shown. It is called once after the sessions that its
/// proof ended got their `left` lines: the member that proved the name can have been shown before, and then no
/// `joined` of it follows, so a reader that keys by nickname would take the name for gone. If it was not shown
/// yet, its own arrival comes next and shows it.
pub(crate) fn show_again(
    key: AuthorKey,
    nickname: &Nickname,
    state: &EventLoopState,
    context: &HandlerCtx<'_>,
) {
    if state.surfaced.contains(&key) {
        context.sink.emit(rearrival(key, nickname, context));
    }
}

pub(crate) async fn handle_presence(
    event: PresenceEvent<'_>,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    context: &HandlerCtx<'_>,
) {
    let PresenceEvent {
        message,
        subtype,
        update,
        surfaceable,
    } = event;
    if subtype == PresenceSubtype::Alive {
        ask_for_proof(message, state, context).await;
        return;
    }
    if subtype == PresenceSubtype::Left {
        end_session(message.key(), Goodbye::Signed(message), state, app, context).await;
    } else if subtype == PresenceSubtype::Joined && !update.stale {
        // Every `joined` re-floods our `PeerInfo`, newcomer and rejoin
        // alike. A newcomer linked to the *rendezvous*, so no `NeighborUp`
        // fires on this loop to re-send it and our arrival flood predates
        // them; a rejoin across a beacon epoch may have lost it the same way
        // (both observed native↔browser in the mesh matrix: a roster entry
        // with no endpoint binding reads "unreachable" forever). Throttled
        // by `joined_refloods_peerinfo`.
        let now = Instant::now();
        if state.joined_refloods_peerinfo(update.joined_new, now) {
            gossip::broadcast_peer_info(state, context).await;
            state.last_sent_at = now;
        }
        // Suppress "has joined" when we already printed "came back" from the quiet check, or
        // when this `joined` predates our own join (relayed backlog). Gated on `surfaced`: a
        // synthetic arrival may have shown this peer already. A peer that is in the roster from
        // backlog, and not shown yet, is shown by its fresh `joined`: the roster entry is not an
        // arrival. A `joined` too old to prove presence does not put a peer in the roster, so it
        // shows none.
        let in_roster = state.peers.contains(&message.key());
        // A `joined` that carries no proof admitted the session unproven: ask for the proof now, and not
        // at its next alive frame, which is 30 s or more away. The retry clock is the one of the alive
        // asks, so a session is asked as often as before, and earlier.
        if message.joined_proof().is_none() {
            ask_for_proof(message, state, context).await;
        }
        if surfaceable && !update.returned && in_roster && state.surfaced.insert(message.key()) {
            state.clock_evidence.returned_unshown.remove(&message.key());
            state.write_peer_count();
            context.sink.emit(NodeEvent::Presence {
                message: Box::new(message.authored()),
                peer: message.key(),
                synthetic: false,
            });
            tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer joined (announced)");
        }
    }
}

/// The endpoint that the proof request for the session `key` (nickname `nickname`) would go to: none when the
/// session is not asked now (it holds a proof, or its retry clock holds), or when no address is known for it.
/// It signs nothing.
fn proof_ask_target(
    key: &AuthorKey,
    nickname: &Nickname,
    state: &EventLoopState,
) -> Option<EndpointId> {
    if !state.asks_for_session(key, nickname) {
        return None;
    }
    let target: Option<EndpointId> = state
        .address_of(key)
        .map(|address| address.id)
        .filter(|eid| Some(*eid) != state.rendezvous_id);
    if target.is_none() {
        tracing::debug!(target: "habilis_network::lifecycle", member = %nickname, "proof request skipped: no address");
    }
    target
}

/// Send the proof request for a session that has no proof here, to that member alone over a warm
/// path. The retry clock of the session starts only after a send that worked. With no warm path the ask
/// is deferred: it waits for a connection to the member ([`retry_deferred_asks`]), and the next alive
/// frame of the session asks again.
pub(crate) async fn ask_for_proof(
    alive: &Verified,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) {
    send_proof_ask(&alive.key(), &alive.author, state, context, None).await;
}

/// [`ask_for_proof`] for a session named by its key and its nickname.
///
/// `inbound` is the endpoint that just sent an authenticated unicast frame, if that is what set this ask off:
/// the session at that endpoint can be reached by a dial back, though it has no gossip link and no connection
/// of ours.
async fn send_proof_ask(
    key: &AuthorKey,
    nickname: &Nickname,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    inbound: Option<EndpointId>,
) {
    if !state.asks_for_session(key, nickname) {
        // it holds a proof now, or its clock holds: nothing waits
        state.proofs.undefer(key);
        return;
    }
    let Some(eid) = proof_ask_target(key, nickname, state) else {
        return;
    };
    // A path that can carry the request: a warm connection, a neighbour that the send dials in the
    // background, or an endpoint that just sent a unicast frame (the same dial). An address with none of
    // them costs a lookup, and no signature, however many frames come.
    let dials_back = inbound == Some(eid);
    let linked = state.linked_endpoints.contains(&eid);
    if !(linked || dials_back || state.unicast_pool.has_warm(eid).await) {
        tracing::debug!(target: "habilis_network::lifecycle", member = %nickname, "proof request skipped: no warm path");
        state.proofs.defer_ask(*key, nickname, Instant::now());
        return;
    }
    #[cfg(test)]
    state.note_ask_dial_address(eid);
    let request = state.proof_request_to(key, context.author, context.mesh);
    messages::log_out(&request);
    let sent = match request.serialize() {
        Ok(bytes) if dials_back => transport::send_dialing_back(eid, bytes, state).await,
        Ok(bytes) => transport::send_best_effort(eid, bytes, state).await,
        Err(_) => false,
    };
    if sent {
        let claimed = (!state.peers.contains(key)).then_some(nickname);
        state.note_proof_request_sent(key, claimed);
    } else {
        tracing::debug!(target: "habilis_network::lifecycle", member = %nickname, "proof request skipped: the send failed");
    }
}

/// What shows that a path to an endpoint is there, for the asks that wait for one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PathSign {
    /// The gossip link to the endpoint came up.
    LinkUp(EndpointId),
    /// A frame came from the endpoint on a unicast connection.
    Unicast(EndpointId),
}

impl PathSign {
    fn endpoint(self) -> EndpointId {
        match self {
            Self::LinkUp(endpoint) | Self::Unicast(endpoint) => endpoint,
        }
    }
}

/// Ask again the sessions whose ask was skipped for lack of a warm path. A gossip link that came up to
/// `arrived`, or a frame that arrived on a unicast connection from it, shows that a path to that endpoint
/// is there: only the sessions at that endpoint are tried. With none (the sweep tick), every waiting session is tried, and the ones that waited
/// too long are dropped. A node with nothing deferred pays one comparison. The retry clock of a session
/// still limits its asks, and a deferred session is tried once for each gap, so a flood of frames from
/// one endpoint signs no more than the clock allows.
pub(crate) async fn retry_deferred_asks(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    sign: Option<PathSign>,
) {
    if state.proofs.deferred_is_empty() {
        return;
    }
    if sign.is_none() {
        state.proofs.expire_deferred(Instant::now());
    }
    let inbound = match sign {
        Some(PathSign::Unicast(endpoint)) => Some(endpoint),
        Some(PathSign::LinkUp(_)) | None => None,
    };
    for (key, nickname) in state.deferred_asks_to_try(sign.map(PathSign::endpoint)) {
        send_proof_ask(&key, &nickname, state, context, inbound).await;
    }
}

#[cfg(test)]
mod ask_tests {

    use crate::protocol::identity::Identity;
    use crate::protocol::messages::Verified;
    use crate::protocol::{AuthorKey, MeshId, Message};
    use crate::testing::{endpoint_id, fresh_state, nick};
    use crate::util::clock::Instant;
    use iroh::EndpointAddr;

    /// A `joined` frame that carries no proof, as a session of a free nickname sends it.
    fn joined_of(session: &Identity, nickname: &str) -> Verified {
        Message::new_joined(&MeshId::from("test"), &nick(nickname)).sign(session)
    }

    /// A frame from endpoint X is a reason to try the deferred asks at X, and only those: the asks at another
    /// endpoint are not marked as tried by it, so the sweep tick still sends them at once.
    #[test]
    fn a_frame_from_one_endpoint_does_not_use_up_the_deferred_asks_of_another() {
        let (alice, bob) = (Identity::generate(), Identity::generate());
        let (at_x, at_y) = (endpoint_id(7), endpoint_id(8));
        let mut state = fresh_state();
        for (session, name, endpoint) in [(&alice, "alice", at_x), (&bob, "bob", at_y)] {
            state.peers.insert(session.author_key());
            state.names.insert(session.author_key(), nick(name));
            state.place_endpoint(
                session.author_key(),
                &nick(name),
                EndpointAddr::new(endpoint),
            );
            state
                .proofs
                .defer_ask(session.author_key(), &nick(name), Instant::now());
        }

        let from_x: Vec<AuthorKey> = state
            .deferred_asks_to_try(Some(at_x))
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        let sweep: Vec<AuthorKey> = state
            .deferred_asks_to_try(None)
            .into_iter()
            .map(|(key, _)| key)
            .collect();

        assert_eq!(
            from_x,
            vec![alice.author_key()],
            "a frame from X tries the ask at X"
        );
        assert_eq!(
            sweep,
            vec![bob.author_key()],
            "the ask at Y was not used up: the sweep sends it (and the one at X was just tried)"
        );
    }

    /// The ask has a target only when an address is known for the session; with none, nothing is
    /// planned and nothing is signed.
    #[test]
    fn an_admitted_session_with_no_proof_has_a_target_only_when_an_address_is_known() {
        let session = Identity::generate();
        let mut state = fresh_state();
        state.peers.insert(session.author_key());
        state.names.insert(session.author_key(), nick("alice"));

        assert!(
            super::proof_ask_target(&session.author_key(), &nick("alice"), &state).is_none(),
            "with no address the session has no target"
        );

        let endpoint = endpoint_id(7);
        state.place_endpoint(
            session.author_key(),
            &nick("alice"),
            EndpointAddr::new(endpoint),
        );
        assert_eq!(
            super::proof_ask_target(&session.author_key(), &nick("alice"), &state),
            Some(endpoint),
            "with an address the request goes to the endpoint of the session"
        );
    }

    /// The retry clock holds: once a request went out, the same `joined` frame sent again (a resend, a
    /// replay, a forged copy) asks for nothing inside the wait. One ask for each session and wait.
    #[test]
    fn the_same_joined_frame_fifty_times_makes_one_ask() {
        let session = Identity::generate();
        let frame = joined_of(&session, "alice");
        let mut state = fresh_state();
        state.peers.insert(session.author_key());
        state.names.insert(session.author_key(), nick("alice"));

        let mut asks = 0;
        for _ in 0..50 {
            if state.asks_for_proof(&frame) {
                asks += 1;
                state.note_proof_request_sent(&session.author_key(), None);
            }
        }

        assert_eq!(asks, 1, "fifty copies of one frame make one ask");
    }

    /// A session that proved its nickname is not asked.
    #[test]
    fn a_session_with_a_proof_is_not_asked() {
        let mesh = MeshId::from("test");
        let (session, member) = (Identity::generate(), Identity::generate());
        let frame = joined_of(&session, "alice");
        let mut state = fresh_state();
        state.peers.insert(session.author_key());
        state.names.insert(session.author_key(), nick("alice"));
        let proof = member.prove(&session.author_key(), "alice", mesh.as_ref(), 1);
        assert!(
            state
                .proofs
                .accept(&session.author_key(), &nick("alice"), &mesh, proof, |_| {
                    true
                }),
            "the proof is held"
        );

        assert!(
            !state.asks_for_proof(&frame),
            "a proven session is not asked"
        );
    }
}
