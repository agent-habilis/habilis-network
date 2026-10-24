//! The **lifecycle subsystem**: everything about a *peer's*
//! presence over time — heartbeat + membership transitions + the
//! join-horizon surfacing decisions (`joined` / `left` / `peer_return`
//! / `peer_timeout`). The pure gossip router calls [`observe`] for
//! every received message, then dispatches by kind into the
//! presence/msg handlers here. The gossip layer never touches the
//! roster directly — that separation is the layer split documented in
//! the Concept Glossary (AGENTS.md).

pub(crate) mod heartbeat;
pub(crate) mod membership;

use crate::daemon::ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::gossip::app::NodeApp;
use crate::gossip::event::NodeEvent;
use crate::protocol::identity::Identity;
use crate::protocol::message::Verified;
use crate::protocol::{MeshId, Message, MessageKind, PresenceSubtype};

use crate::gossip;
use crate::util::clock::Instant;

/// Developer log for the mesh-ready milestone. Mirrors the operator
/// `ready` event but on the lifecycle log target (stderr, opt-in via
/// `RUST_LOG`); the operator JSON/human event is unchanged.
///
/// Logs the derived **`TopicId`** (a one-way hash of the seed), never the full
/// mesh id. The id carries the seed and *is* the bearer credential, and this
/// log file is written under a shared path — logging the id would leak full
/// mesh membership to anyone who can read the file. The topic hash is enough
/// to correlate a run without exposing the secret.
pub(crate) fn log_ready(
    topic: iroh_gossip::proto::TopicId,
    name: &str,
    nickname: &str,
    network: &str,
) {
    tracing::info!(target: "habilis_network::lifecycle", ?topic, name, nickname, network, "mesh ready");
}

/// Developer log for graceful departure (mirrors the operator `left`).
pub(crate) fn log_leaving(name: &str) {
    tracing::info!(target: "habilis_network::lifecycle", name, "leaving mesh");
}

/// What [`observe`] computed for one received message: whether it is
/// past our join horizon (surfaceable) and how it changed the roster.
/// Returned to the gossip router, which needs both for the inbound-push
/// gate and the presence/msg dispatch.
pub(crate) struct Observed {
    pub surfaceable: bool,
    pub update: membership::MembershipUpdate,
}

/// Heartbeat + membership + surfacing + join-horizon for one received
/// message. Called by the gossip router *before* kind dispatch. All
/// membership/presentation side effects live here (lifecycle layer);
/// the gossip layer never touches the roster directly.
pub(crate) fn observe(
    message: &Verified,
    state: &mut EventLoopState,
    ctx: &HandlerCtx<'_>,
) -> Observed {
    let update = membership::compute_for(message, state);
    // Implicit heartbeat: any received message updates last_seen. Not a stale one: a copy of a
    // departed key's frame says nothing about whoever holds the nickname now.
    if !update.stale {
        match state.last_seen.get_mut(message.author.as_str()) {
            Some(seen) => *seen = Instant::now(),
            None => {
                state
                    .last_seen
                    .insert(message.author.clone(), Instant::now());
            }
        }
    }
    membership::apply(&update, &message.author, state);

    // Join horizon: the node still relays/logs everything (anti-entropy
    // keeps the mesh's set uniform), but a message stamped before we
    // joined is never *surfaced* to the operator/agent. Computed here
    // (not just before the inbound push) because the arrival-surfacing
    // decisions below need it too.
    let surfaceable = message.timestamp >= state.joined_at;

    if update.returned && surfaceable {
        state.surfaced.insert(message.author.clone());
        ctx.sink.emit(NodeEvent::PeerReturn {
            nickname: message.author.clone(),
        });
        tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer returned");
    }

    // Make `joined` as reliable as membership. A peer's own `joined`
    // presence is a one-shot broadcast that can be lost in the
    // convergence window; `PeerInfo` is re-sent on every `NeighborUp`
    // and flooded by receivers, so a peer first learned via *any*
    // non-presence message reliably surfaces a `joined` here. The
    // real `Presence::Joined` keeps its own emit + roster re-announce
    // in `handle_presence`; gating on `!Presence` avoids a double.
    //
    // Surfacing is gated on `surfaceable` + `surfaced`, NOT on
    // `joined_new`: `joined_new` (the roster concept) is consumed by
    // the *first* received message even when it is non-surfaceable
    // pre-join backlog, so keying off it would swallow the legitimate
    // arrival of a still-present peer whose first fresh message lands
    // after some old relayed one. `!surfaced.contains` keeps
    // this exactly-once instead.
    if surfaceable
        && !update.returned
        && !update.stale
        && !state.surfaced.contains(message.author.as_str())
        && !matches!(message.kind, MessageKind::Presence { .. })
    {
        state.surfaced.insert(message.author.clone());
        ctx.sink
            .emit(synthetic_arrival(ctx.mesh, ctx.identity, message));
        tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer joined");
    }

    Observed {
        surfaceable,
        update,
    }
}

/// The presence this node surfaces for a peer's first arrival. This node signs the
/// `joined` that reports it, so the proof names this node, and the nickname stays the
/// peer's. `peer` is the key of the frame that triggered it, which is the peer's own.
fn synthetic_arrival(mesh: &MeshId, identity: &Identity, triggering: &Verified) -> NodeEvent {
    let arrival = Message::new_joined(mesh, &triggering.author).sign(identity);
    NodeEvent::Presence {
        msg: Box::new(arrival.authored()),
        peer: triggering.key(),
        synthetic: true,
    }
}

/// A received `Presence` frame plus the roster delta [`membership::observe`]
/// already computed for it, passed to [`handle_presence`]. Constructed by
/// [`crate::gossip::recv::ingest`], across the `gossip`/`lifecycle` module
/// boundary — hence `pub(crate)` rather than module-private.
pub(crate) struct PresenceEvent<'message> {
    pub(crate) message: &'message Verified,
    pub(crate) subtype: PresenceSubtype,
    pub(crate) update: &'message membership::MembershipUpdate,
    pub(crate) surfaceable: bool,
}

pub(crate) async fn handle_presence(
    event: PresenceEvent<'_>,
    state: &mut EventLoopState,
    app: &mut dyn NodeApp,
    ctx: &HandlerCtx<'_>,
) {
    let PresenceEvent {
        message,
        subtype,
        update,
        surfaceable,
    } = event;
    if subtype == PresenceSubtype::Alive {
        return;
    }
    if subtype == PresenceSubtype::Left {
        // A key says goodbye once per run. A second copy is a replay that a peer still held, and
        // the nickname may belong to a new key by now: the replay must not take it away.
        if state.key_said_goodbye(message.key()) {
            return;
        }
        state.note_left(&message.author, message.key(), message.timestamp);
        state.drop_departed_presence(&message.key());
        if state.peers.remove(message.author.as_str()) {
            state.write_peer_count();
        }
        // A graceful goodbye, unlike a silence timeout, drops the dial hint —
        // and with it the warm unicast connection and any dial cooldown, so a
        // rejoin re-dials cold.
        if let Some(endpoint_id) = state.forget_peer_endpoint(message.author.as_str()) {
            state.unicast_pool.forget(endpoint_id.id).await;
            // Its advertised links go too, or routes keep running through a peer
            // that said goodbye until its vector ages out.
            #[cfg(feature = "multihop")]
            if let Some(handle) = state.multihop.as_ref() {
                handle.remove_origin(habilis_network_iroh_multihop_transport::AppId::new(
                    endpoint_id.id,
                ));
            }
        }
        state.quiet.remove(message.author.as_str());
        // Only announce a departure for a peer whose arrival we
        // surfaced — keeps the join-horizon view symmetric. A `left`
        // for a peer known only through pre-join backlog (or one we
        // already showed going quiet) is dropped.
        if state.surfaced.remove(message.author.as_str()) {
            ctx.sink.emit(NodeEvent::Presence {
                msg: Box::new(message.authored()),
                peer: message.key(),
                synthetic: false,
            });
            tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer left");
        }
        // App cleanup last, with the roster already consistent. Gated on
        // `surfaceable`: a relayed pre-join `Left` must never cancel live
        // work — the same join-horizon symmetry as the announcement above.
        if surfaceable {
            app.on_peer_left(&message.author, state, ctx).await;
        }
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
            gossip::broadcast_peer_info(state, ctx).await;
            state.last_sent_at = now;
        }
        if update.joined_new {
            // Re-announce so late joiners seed their roster. Retained locally: a
            // re-announce mints a fresh id, so without this each one becomes
            // another message we can never acknowledge and every peer re-sends to
            // us forever (see `gossip::recv::retain_own_broadcast`).
            let joined = Message::new_joined(ctx.mesh, ctx.author).sign(ctx.identity);
            gossip::broadcast_msg(ctx.sender, &joined).await;
            gossip::retain_own_broadcast(state, &joined);
            state.last_sent_at = Instant::now();
            // Suppress "has joined" when we already printed "came back"
            // from the quiet check, or when this `joined` predates
            // our own join (relayed backlog).
            if surfaceable && !update.returned {
                state.surfaced.insert(message.author.clone());
                ctx.sink.emit(NodeEvent::Presence {
                    msg: Box::new(message.authored()),
                    peer: message.key(),
                    synthetic: false,
                });
                tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer joined (announced)");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Identity, MeshId, Message, NodeEvent, synthetic_arrival};
    use crate::testing::nick;

    #[test]
    fn a_synthetic_presence_names_the_peer_apart_from_its_signer() {
        let mesh = MeshId::from("test");
        let node = Identity::generate();
        let peer = Identity::generate();
        let joined = Message::new_joined(&mesh, &nick("bob")).sign(&peer);
        let NodeEvent::Presence {
            msg,
            peer: key,
            synthetic,
        } = synthetic_arrival(&mesh, &node, &joined)
        else {
            panic!("a synthetic arrival is a presence");
        };
        assert!(synthetic, "this node minted it");
        assert_eq!(key, peer.author_key(), "the peer is the triggering signer");
        assert_eq!(msg.key(), node.author_key(), "the proof is this node's");
        assert_eq!(msg.author.as_str(), "bob", "the nickname stays the peer's");
    }
}

/// A key sends one `left` per run, so a second `left` from the same key is a replay: a copy
/// that a peer still held and re-sent. It must not touch the nickname, which a new key may
/// hold by then, and a stale frame of a departed key must not refresh that nickname's liveness.
#[cfg(all(test, feature = "host"))]
mod departed_tests {
    use habilis_network_test_tracing::test;
    use iroh_gossip::net::Gossip;

    use crate::daemon::ctx::HandlerCtx;
    use crate::daemon::state::EventLoopState;
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::event::SilentSink;
    use crate::lookup::{TransportOpts, build_peer_multihop};
    use crate::protocol::identity::Identity;
    use crate::protocol::mesh::LookupOpts;
    use crate::protocol::message::Authored;
    use crate::protocol::{MeshId, Message, PresenceSubtype, UnixSecs};
    use crate::testing::{endpoint_id, fresh_state, nick};
    use crate::transport::{MeshSender, PayloadPath};

    use super::{PresenceEvent, handle_presence, membership, observe};

    struct Inert;

    #[async_trait::async_trait]
    impl NodeApp for Inert {
        fn classify(&self, _message: &Authored) -> AppClass {
            AppClass::BEAT.union(AppClass::VALID)
        }

        async fn on_app_frame(
            &mut self,
            _frame: InboundApp<'_>,
            _state: &mut EventLoopState,
            _ctx: &HandlerCtx<'_>,
        ) -> bool {
            false
        }
    }

    /// One bound endpoint and a sender on a peerless topic: what a `HandlerCtx` needs.
    async fn endpoint_and_sender() -> (iroh::Endpoint, MeshSender) {
        let (endpoint, handle, _webrtc) = build_peer_multihop(
            &LookupOpts::loopback(),
            TransportOpts::default(),
            None,
            PayloadPath::DirectOnly,
        )
        .await
        .expect("a peer binds");
        handle.close().await;
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        (endpoint, MeshSender::new(gossip_sender))
    }

    #[test]
    async fn a_replayed_left_leaves_the_nickname_to_its_new_holder() {
        let (endpoint, sender) = endpoint_and_sender().await;
        let identity = Identity::generate();
        let our_pubkey = identity.author_key();
        let mesh = MeshId::from("test");
        let us = nick("us");
        let sink = SilentSink;
        let ctx = HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &us,
            identity: &identity,
            our_pubkey,
            max_peers: 16,
            rendezvous_id: endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let who = nick("swift-cedar");
        let first_run = Identity::generate();
        let left = Message::new_left(&mesh, &who).sign(&first_run);
        let mut state = fresh_state();
        let mut app = Inert;

        // The first run leaves.
        state.peers.insert(who.clone());
        let update = membership::compute_for(&left, &state);
        handle_presence(
            PresenceEvent {
                message: &left,
                subtype: PresenceSubtype::Left,
                update: &update,
                surfaceable: true,
            },
            &mut state,
            &mut app,
            &ctx,
        )
        .await;
        assert!(!state.peers.contains(who.as_str()), "the first run left");

        // A second run takes the nickname, then a copy of the first run's goodbye lands.
        state.peers.insert(who.clone());
        state.surfaced.insert(who.clone());
        let replay = membership::compute_for(&left, &state);
        handle_presence(
            PresenceEvent {
                message: &left,
                subtype: PresenceSubtype::Left,
                update: &replay,
                surfaceable: true,
            },
            &mut state,
            &mut app,
            &ctx,
        )
        .await;
        assert!(
            state.peers.contains(who.as_str()),
            "a replayed goodbye of the first run removed the second run"
        );
        assert!(
            state.surfaced.contains(who.as_str()),
            "a replayed goodbye of the first run un-surfaced the second run"
        );
        endpoint.close().await;
    }

    /// A departed key's `joined` frames serve nobody once it is gone, and the log never evicts a
    /// small author, so without this they stay resend subjects for the life of the node. Its chat
    /// stays: a node that missed it can still backfill it.
    #[test]
    async fn a_departed_keys_presence_leaves_the_log() {
        let (endpoint, sender) = endpoint_and_sender().await;
        let identity = Identity::generate();
        let our_pubkey = identity.author_key();
        let mesh = MeshId::from("test");
        let us = nick("us");
        let sink = SilentSink;
        let ctx = HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &us,
            identity: &identity,
            our_pubkey,
            max_peers: 16,
            rendezvous_id: endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let who = nick("swift-cedar");
        let departed = Identity::generate();
        let joined = Message::new_joined(&mesh, &who).sign(&departed);
        let chat = Message::new_app(
            &mesh,
            &who,
            crate::protocol::AppFrameParams::new(
                crate::protocol::AppTag::new("app_msg").expect("a valid app tag"),
                None,
                None,
                crate::protocol::MessageBody::from("kept"),
            ),
        )
        .sign(&departed);
        let mut state = fresh_state();
        state.peers.insert(who.clone());
        state.message_log.push(joined.clone());
        state.message_log.push(chat.clone());

        let left = Message::new_left(&mesh, &who).sign(&departed);
        let update = membership::compute_for(&left, &state);
        let mut app = Inert;
        handle_presence(
            PresenceEvent {
                message: &left,
                subtype: PresenceSubtype::Left,
                update: &update,
                surfaceable: true,
            },
            &mut state,
            &mut app,
            &ctx,
        )
        .await;
        assert!(
            !state.message_log.contains(&joined.dedup_key()),
            "the departed key's joined is still in the log"
        );
        assert!(
            state.message_log.contains(&chat.dedup_key()),
            "the departed key's chat left the log"
        );
        endpoint.close().await;
    }

    /// A copy of a goodbye reaches `observe` before `handle_presence`. If a later holder of the
    /// nickname has gone quiet, the copy must not read as that holder's return: it is a frame of a
    /// key that already said goodbye, and says nothing about whoever holds the nickname now.
    #[test]
    async fn a_replayed_left_does_not_return_a_quiet_holder() {
        let (endpoint, sender) = endpoint_and_sender().await;
        let identity = Identity::generate();
        let our_pubkey = identity.author_key();
        let mesh = MeshId::from("test");
        let us = nick("us");
        let sink = SilentSink;
        let ctx = HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &us,
            identity: &identity,
            our_pubkey,
            max_peers: 16,
            rendezvous_id: endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let who = nick("swift-cedar");
        let first_run = Identity::generate();
        let mut state = fresh_state();
        state.note_left(&who, first_run.author_key(), UnixSecs::from_secs(1_000));
        // A second run took the nickname and went quiet.
        state.quiet.insert(who.clone());

        let replay = Message::new_left(&mesh, &who).sign(&first_run);
        let observed = observe(&replay, &mut state, &ctx);
        assert!(observed.update.stale, "a copy of a goodbye is not stale");
        assert!(
            !state.peers.contains(who.as_str()),
            "a replayed goodbye of the first run returned the quiet second run"
        );
        assert!(
            state.quiet.contains(who.as_str()),
            "a replayed goodbye of the first run took the second run out of quiet"
        );
        assert!(
            !state.last_seen.contains_key(who.as_str()),
            "a replayed goodbye refreshed the nickname's liveness"
        );
        endpoint.close().await;
    }

    #[test]
    async fn a_stale_frame_of_a_departed_key_does_not_refresh_liveness() {
        let (endpoint, sender) = endpoint_and_sender().await;
        let identity = Identity::generate();
        let our_pubkey = identity.author_key();
        let mesh = MeshId::from("test");
        let us = nick("us");
        let sink = SilentSink;
        let ctx = HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &us,
            identity: &identity,
            our_pubkey,
            max_peers: 16,
            rendezvous_id: endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let who = nick("swift-cedar");
        let departed = Identity::generate();
        let mut state = fresh_state();
        state.note_left(&who, departed.author_key(), UnixSecs::from_secs(1_000));

        let replay = Message::new_joined(&mesh, &who).sign(&departed);
        let observed = observe(&replay, &mut state, &ctx);
        assert!(observed.update.stale);
        assert!(
            !state.last_seen.contains_key(who.as_str()),
            "a stale frame refreshed the nickname's liveness"
        );
        endpoint.close().await;
    }
}
