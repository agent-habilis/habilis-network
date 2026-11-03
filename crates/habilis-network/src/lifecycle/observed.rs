use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::gossip::event::NodeEvent;
use crate::protocol::identity::Identity;
use crate::protocol::messages::Verified;
use crate::protocol::{
    AuthorKey, MeshId, Message, MessageId, MessageKind, PresenceSubtype, UnixSecs,
};
use uuid::Uuid;

use super::{heartbeat, membership_update};

use crate::util::clock::Instant;

/// What [`observe`] computed for one received message: whether it is
/// past our join horizon (surfaceable) and how it changed the roster.
/// Returned to the gossip router, which needs both for the inbound-push
/// gate and the presence/msg dispatch.
#[derive(Debug, Clone)]
pub(crate) struct Observed {
    pub surfaceable: bool,
    pub update: membership_update::MembershipUpdate,
}

/// Heartbeat + membership + surfacing + join-horizon for one received
/// message. Called by the gossip router *before* kind dispatch. All
/// membership/presentation side effects live here (lifecycle layer);
/// the gossip layer never touches the roster directly.
pub(crate) fn observe(
    message: &Verified,
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
) -> Observed {
    let update = membership_update::compute_observed(message, state);
    if !update.stale {
        let proves = membership_update::proves_presence(&message.kind, message.timestamp);
        // The key of the newest frame that proved the peer alive holds the nickname. A frame
        // that proves presence but is older than the newest one is an unseen copy of a killed
        // run (a relay holds it): it holds nothing.
        // At an equal stamp (whole seconds) only the holder, or a nickname with no holder, keeps
        // the nickname: the stamp cannot tell which of two frames of one second came last.
        let holder = state.peer_keys.get(&message.author).copied();
        let newest_before: Option<UnixSecs> = state.peer_stamp.get(&message.author).copied();
        let ties_to_holder: bool = holder.is_none_or(|held| held == message.key());
        let is_newest = proves
            && newest_before.is_none_or(|newest| {
                message.timestamp > newest || (message.timestamp == newest && ties_to_holder)
            });
        // Only the holder, or a frame that takes the nickname, moves the last-heard mark. A copy of
        // a frame of a killed run must not keep the live run in the roster. A nickname with no
        // holder on record (a peer whose clock is far behind never proved presence) takes any key.
        let from_holder = is_newest || holder.is_none_or(|held| held == message.key());
        // A frame of a live kind from a peer that is in the roster refreshes it at any stamp: a
        // peer whose clock runs far behind still talks, and the sweep must not evict it. Only a
        // frame that proves presence does more (the holder of the nickname, the newest stamp).
        let known_and_live = state.peers.contains(message.author.as_str())
            && membership_update::is_live_kind(&message.kind);
        // Implicit heartbeat: a frame that proves presence updates last_seen. Not a stale one: a
        // copy of a departed key's frame says nothing about whoever holds the nickname now. Not a
        // replayed frame of a durable kind either: it would keep a dead peer from its eviction. A
        // peer that is new to us gets its first entry from any frame, or the sweep could never
        // evict it.
        let heard_now = Instant::now();
        match state.last_seen.get_mut(message.author.as_str()) {
            Some(seen) if from_holder && (proves || known_and_live) => {
                *seen = heard_now;
                state
                    .clock_evidence
                    .heard
                    .insert(message.author.clone(), heard_now);
            }
            Some(_) => {}
            None => {
                state.last_seen.insert(message.author.clone(), heard_now);
                state
                    .clock_evidence
                    .heard
                    .insert(message.author.clone(), heard_now);
            }
        }
        if proves {
            if is_newest {
                // The dial hint was made by the key that held the nickname. Another key that takes
                // it does not inherit the hint: a directed send would reach the old node.
                let lapsed = state.clock_evidence.lapsed_keys.remove(&message.author);
                let before = holder.or(lapsed);
                if before.is_some_and(|held| held != message.key()) {
                    state.forget_peer_endpoint(message.author.as_str());
                }
                state
                    .peer_keys
                    .insert(message.author.clone(), message.key());
            }
            // The newest stamp of the author, on its own clock: the test of a return compares two
            // stamps of one clock, so a skew between that clock and ours cancels.
            let newest = state
                .peer_stamp
                .entry(message.author.clone())
                .or_insert(message.timestamp);
            *newest = (*newest).max(message.timestamp);
            if membership_update::is_live_kind(&message.kind) {
                heartbeat::confirm_suspend(state, message.timestamp);
            }
            state
                .clock_evidence
                .step_back
                .remove(message.author.as_str());
        }
    }
    membership_update::apply(&update, &message.author, state);

    // Join horizon: the node still relays/logs everything (anti-entropy
    // keeps the mesh's set uniform), but a message stamped before we
    // joined is never *surfaced* to the operator/agent. Computed here
    // (not just before the inbound push) because the arrival-surfacing
    // decisions below need it too.
    let surfaceable = message.timestamp >= state.joined_at;
    // The arrival of a peer is a fact about the peer, not about the content of one frame. A peer
    // with a slow clock stamps its frames before our join, and it is shown once a second live
    // frame proves that it sends now. A message is still shown only when its own stamp is past
    // the join horizon (`surfaceable`).
    let sends_now = !update.stale
        && message.timestamp < state.joined_at
        && membership_update::note_live_run(message, state);
    let shown_peer = surfaceable || sends_now;

    // A peer that returns with frames stamped before our join is back in the roster, and shown
    // when a run of its frames proves that it sends now. It is shown as returned: the operator
    // read "timed out" for it.
    if update.returned && !shown_peer {
        state
            .clock_evidence
            .returned_unshown
            .insert(message.author.clone());
    }
    if update.returned && shown_peer {
        state
            .clock_evidence
            .returned_unshown
            .remove(&message.author);
        state.surfaced.insert(message.author.clone());
        state.write_peer_count();
        context.sink.emit(NodeEvent::PeerReturn {
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
    // In the roster: a durable frame (state, meta) of a peer we have not seen does not put the
    // peer there, and an arrival for it would be a peer that the rows and the count omit.
    let in_roster = state.peers.contains(message.author.as_str());
    if shown_peer
        && !update.returned
        && !update.stale
        && membership_update::proves_presence(&message.kind, message.timestamp)
        && in_roster
        && !state.surfaced.contains(message.author.as_str())
        // A real `joined` is surfaced by `handle_presence`, with its own id. Any other frame is
        // not, an `alive` too: a peer whose `joined` was lost arrives on its first live frame.
        && !matches!(
            message.kind,
            MessageKind::Presence {
                subtype: PresenceSubtype::Joined
            }
        )
    {
        state.surfaced.insert(message.author.clone());
        state.write_peer_count();
        if state
            .clock_evidence
            .returned_unshown
            .remove(&message.author)
        {
            context.sink.emit(NodeEvent::PeerReturn {
                nickname: message.author.clone(),
            });
            tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer returned");
        } else {
            context
                .sink
                .emit(synthetic_arrival(context.mesh, context.identity, message));
            tracing::info!(target: "habilis_network::lifecycle", nickname = %message.author, "peer joined");
        }
    }

    Observed {
        surfaceable,
        update,
    }
}

/// The presence this node surfaces for a peer's first arrival. This node signs the
/// `joined` that reports it, so the proof names this node, and the nickname stays the
/// peer's. `peer` is the key of the frame that triggered it, which is the peer's own.
///
/// The id comes from the key and the stamp of the triggering frame: copies of one arrival share
/// an id, and the next arrival of the same key (after the quiet TTL, when this node has forgotten
/// the peer) is triggered by a later frame and has another. A random id would make each call a
/// new fact that an app cannot fold into the first, and an id from the key alone would make a
/// second arrival look like a copy of the first, to an app that drops a repeated id.
pub(crate) fn synthetic_arrival(
    mesh: &MeshId,
    identity: &Identity,
    triggering: &Verified,
) -> NodeEvent {
    let mut arrival = Message::new_joined(mesh, &triggering.author);
    arrival.id = arrival_id(triggering.key(), triggering.timestamp);
    let arrival = arrival.sign(identity);
    NodeEvent::Presence {
        message: Box::new(arrival.authored()),
        peer: triggering.key(),
        synthetic: true,
    }
}

/// The 12 bytes at the start of a public key already differ for every key. The 4 low bytes of the
/// stamp follow them. 6 bits of the key bytes give way to the version and variant bits.
fn arrival_id(key: AuthorKey, stamp: UnixSecs) -> MessageId {
    let mut bytes = [0u8; 16];
    bytes[..12].copy_from_slice(&key.as_bytes()[..12]);
    let seconds = u32::try_from(stamp.as_secs().rem_euclid(i64::from(u32::MAX) + 1))
        .expect("a remainder below 2^32 fits a u32");
    bytes[12..].copy_from_slice(&seconds.to_be_bytes());
    // The version and variant bits of a UUID v4, as `MessageId` says.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    MessageId::try_new(&Uuid::from_bytes(bytes).to_string())
        .expect("a formatted UUID is a valid message id")
}

/// Tests for issue 75 (H1, H4, H7). Each test states the property that a correct engine has. They
/// were red on f7cd9bbc for the reason in their names (see the PR).
#[cfg(all(test, feature = "host"))]
mod churn_red {
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use iroh_gossip::net::Gossip;
    use iroh_gossip::proto;

    use super::{heartbeat, observe, synthetic_arrival};
    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::setup::LiveCount;
    use crate::daemon::state::{EventLoopState, LiveRun};
    use crate::gossip::antientropy;
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::event::{NodeEvent, NodeSink};
    use crate::lifecycle::heartbeat::{tick_alive, tick_sweep};
    use crate::lifecycle::{PresenceEvent, handle_presence, membership_update};
    use crate::lookup::{TransportOpts, build_peer_multihop};
    use crate::protocol::identity::Identity;
    use crate::protocol::meshes::LookupOpts;
    use crate::protocol::messages::Authored;
    use crate::protocol::{
        Channel, MeshId, Message, MessageBody, Nickname, PresenceSubtype, UnixSecs, Verified,
    };
    use crate::testing::{FrameClass, WireCounter, endpoint_id, fresh_state, nick};
    use crate::transport::{MeshSender, PayloadPath};
    use crate::util::clock::Instant;
    use crate::util::tuning::{QUIET_CAP, SEEN_IDS_CAP, alive_timeout};
    use crate::{gossip, protocol};

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

    /// Keeps one line per surfaced lifecycle event, so a test reads what the operator would see.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl Recorder {
        fn lines(&self) -> Vec<String> {
            self.0.lock().expect("the recorder lock").clone()
        }
    }

    impl NodeSink for Recorder {
        fn emit(&self, event: NodeEvent) {
            let line = match event {
                NodeEvent::PeerTimeout { nickname, .. } => format!("timeout {nickname}"),
                NodeEvent::PeerReturn { nickname } => format!("return {nickname}"),
                NodeEvent::Presence {
                    message, synthetic, ..
                } => format!(
                    "presence {} {:?} synthetic={synthetic} id={}",
                    message.author, message.kind, message.id
                ),
                NodeEvent::Ready { .. }
                | NodeEvent::Info(_)
                | NodeEvent::Error(_)
                | NodeEvent::Fork { .. }
                | NodeEvent::PingReport { .. }
                | NodeEvent::StateChanged { .. } => return,
            };
            self.0.lock().expect("the recorder lock").push(line);
        }
    }

    /// What a `HandlerCtx` borrows: one bound endpoint, a sender on a peerless topic, and a sink.
    struct Rig {
        endpoint: iroh::Endpoint,
        sender: MeshSender,
        mesh: MeshId,
        identity: Identity,
        us: Nickname,
        sink: Recorder,
    }

    impl Rig {
        async fn new() -> Self {
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
                .subscribe(proto::TopicId::from_bytes([7u8; 32]), vec![])
                .await
                .expect("subscribe to a peerless topic");
            let (gossip_sender, _receiver) = topic.split();
            Self {
                endpoint,
                sender: MeshSender::new(gossip_sender),
                mesh: MeshId::from("test"),
                identity: Identity::generate(),
                us: nick("us"),
                sink: Recorder::default(),
            }
        }

        fn context(&self) -> HandlerCtx<'_> {
            HandlerCtx {
                sender: &self.sender,
                endpoint: &self.endpoint,
                mesh: &self.mesh,
                author: &self.us,
                identity: &self.identity,
                our_pubkey: self.identity.author_key(),
                max_peers: 16,
                rendezvous_id: endpoint_id(9),
                external_msg_tx: None,
                sink: &self.sink,
            }
        }
    }

    fn chat(mesh: &MeshId, who: &Nickname, by: &Identity, at: UnixSecs) -> Verified {
        let mut message = Message::new_app(
            mesh,
            who,
            protocol::AppFrameParams::new(
                protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                None,
                None,
                MessageBody::from("hello"),
            ),
        );
        message.timestamp = at;
        message.sign(by)
    }

    fn alive(mesh: &MeshId, who: &Nickname, by: &Identity, at: UnixSecs) -> Verified {
        let mut message = Message::new_alive(mesh, who);
        message.timestamp = at;
        message.sign(by)
    }

    fn peer_info(mesh: &MeshId, who: &Nickname, by: &Identity, at: UnixSecs) -> Verified {
        let mut message = Message::new_peer_info(mesh, who, MessageBody::from("{}"));
        message.timestamp = at;
        message.sign(by)
    }

    fn channel_event(
        mesh: &MeshId,
        who: &Nickname,
        by: &Identity,
        at: UnixSecs,
        channel: Channel,
    ) -> Verified {
        let mut message = Message::new_channel_event(mesh, who, MessageBody::from("{}"), channel);
        message.timestamp = at;
        message.sign(by)
    }

    fn state_change(mesh: &MeshId, who: &Nickname, by: &Identity, at: UnixSecs) -> Verified {
        channel_event(mesh, who, by, at, Channel::State)
    }

    fn meta_change(mesh: &MeshId, who: &Nickname, by: &Identity, at: UnixSecs) -> Verified {
        channel_event(mesh, who, by, at, Channel::Meta)
    }

    fn channel_digest(
        mesh: &MeshId,
        who: &Nickname,
        by: &Identity,
        at: UnixSecs,
        channel: Channel,
    ) -> Verified {
        let mut message = Message::new_channel_digest(mesh, who, MessageBody::from("{}"), channel);
        message.timestamp = at;
        message.sign(by)
    }

    fn state_digest(mesh: &MeshId, who: &Nickname, by: &Identity, at: UnixSecs) -> Verified {
        channel_digest(mesh, who, by, at, Channel::State)
    }

    fn meta_digest(mesh: &MeshId, who: &Nickname, by: &Identity, at: UnixSecs) -> Verified {
        channel_digest(mesh, who, by, at, Channel::Meta)
    }

    /// The stamp of every frame that a peer sent before it died: far enough back that the dead
    /// peer had been silent for a full alive timeout when the sweep evicted it.
    fn long_ago() -> UnixSecs {
        UnixSecs::now() - alive_timeout() - Duration::from_secs(200)
    }

    /// One received frame, through the same gate and the same `observe` call as `ingest`.
    fn receive(frame: &Verified, state: &mut EventLoopState, context: &HandlerCtx<'_>) -> bool {
        if state.mark_seen(frame) {
            return false;
        }
        observe(frame, state, context);
        true
    }

    /// H1. A peer is killed by `SIGKILL`: it never sends `left`, so no guard of #34 covers its key. A frame
    /// that it sent while alive and that is not in the message log (a keepalive, a `PeerInfo`)
    /// dedups only through the `seen` set. When a busy room pushes it out of that set, a copy that
    /// a relay still holds is new again, and it revives the dead peer.
    async fn a_replayed_frame_must_not_revive_a_sigkilled_peer(
        make: fn(&MeshId, &Nickname, &Identity, UnixSecs) -> Verified,
    ) {
        let rig = Rig::new().await;
        let context = rig.context();
        let who = nick("swift-cedar");
        let victim = Identity::generate();
        let mut state = fresh_state();
        state.joined_at = long_ago() - Duration::from_secs(10);

        let hello = chat(&rig.mesh, &who, &victim, long_ago());
        let beat = make(&rig.mesh, &who, &victim, long_ago());
        assert!(
            receive(&hello, &mut state, &context),
            "the frame is new to the seen set"
        );
        assert!(
            receive(&beat, &mut state, &context),
            "the frame is new to the seen set"
        );
        assert!(state.surfaced.contains(who.as_str()), "the victim arrived");

        // SIGKILL: nothing more arrives. The sweep evicts the victim.
        let silent = Instant::now()
            .checked_sub(alive_timeout() + Duration::from_secs(10))
            .expect("the monotonic clock has run past the alive timeout since boot");
        state.last_seen.insert(who.clone(), silent);
        tick_sweep(&mut state, &rig.sink);
        assert!(state.quiet.contains(who.as_str()), "the victim is quiet");
        assert!(
            !state.key_said_goodbye(victim.author_key()),
            "a SIGKILL sends no left"
        );

        // A busy room: SEEN_IDS_CAP other frames push the beat out of the seen set.
        let talker = Identity::generate();
        let talker_nick = nick("busy-room");
        for _ in 0..SEEN_IDS_CAP {
            state.mark_seen(&alive(&rig.mesh, &talker_nick, &talker, UnixSecs::now()));
        }

        // A relay that still holds the beat sends it again.
        assert!(
            receive(&beat, &mut state, &context),
            "precondition: the seen set forgot the beat, so a copy is new again"
        );
        let lines = rig.sink.lines();
        assert!(
            !lines.iter().any(|line| line == "return swift-cedar"),
            "a replayed frame of a SIGKILLed peer revived it: {lines:?}"
        );
        rig.endpoint.close().await;
    }

    #[test]
    fn h1_a_replayed_alive_revives_a_sigkilled_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            a_replayed_frame_must_not_revive_a_sigkilled_peer(alive).await;
        });
    }

    #[test]
    fn h1_a_replayed_peer_info_revives_a_sigkilled_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            a_replayed_frame_must_not_revive_a_sigkilled_peer(peer_info).await;
        });
    }

    // The same hole for the kinds of the durable state: the engine never keeps them in the message
    // log, so after the seen set forgot them nothing stops a copy, and `returned` reads no kind.
    #[test]
    fn h1_a_replayed_state_change_revives_a_sigkilled_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            a_replayed_frame_must_not_revive_a_sigkilled_peer(state_change).await;
        });
    }

    #[test]
    fn h1_a_replayed_meta_change_revives_a_sigkilled_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            a_replayed_frame_must_not_revive_a_sigkilled_peer(meta_change).await;
        });
    }

    #[test]
    fn h1_a_replayed_state_digest_revives_a_sigkilled_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            a_replayed_frame_must_not_revive_a_sigkilled_peer(state_digest).await;
        });
    }

    #[test]
    fn h1_a_replayed_meta_digest_revives_a_sigkilled_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            a_replayed_frame_must_not_revive_a_sigkilled_peer(meta_digest).await;
        });
    }

    /// H4. The `joined` that a node mints for a peer's first frame gets a new id on every call, so
    /// the app cannot fold two of them into one. The same peer arrival must name the same id.
    #[test]
    fn h4_a_synthetic_joined_gets_a_new_id_each_time() {
        let node = Identity::generate();
        let peer = Identity::generate();
        let mesh = MeshId::from("test");
        let trigger = chat(&mesh, &nick("swift-cedar"), &peer, UnixSecs::now());
        let id_of = |event: NodeEvent| {
            let NodeEvent::Presence { message, .. } = event else {
                panic!("a synthetic arrival is a presence");
            };
            message.id.to_string()
        };
        let first = id_of(synthetic_arrival(&mesh, &node, &trigger));
        let second = id_of(synthetic_arrival(&mesh, &node, &trigger));
        assert_eq!(
            first, second,
            "two synthetic joined for one peer have two ids"
        );
    }

    /// H4. Each `joined_new` makes this node announce its own `joined` again, and retain it.
    /// Five peers that join make five new `joined` frames, each one a message that every other
    /// peer receives, and the cost of a burst of joiners grows with the square of the roster.
    #[test]
    fn h4_every_new_peer_makes_us_announce_again() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let mut state = fresh_state();
            let mut app = Inert;
            assert_eq!(state.message_log.len(), 0, "the log starts empty");
            for name in [
                "swift-cedar",
                "lost-heron",
                "calm-otter",
                "bold-finch",
                "wild-crane",
            ] {
                let who = nick(name);
                let joined = Message::new_joined(&rig.mesh, &who).sign(&Identity::generate());
                let observed = observe(&joined, &mut state, &context);
                handle_presence(
                    PresenceEvent {
                        message: &joined,
                        subtype: PresenceSubtype::Joined,
                        update: &observed.update,
                        surfaceable: observed.surfaceable,
                    },
                    &mut state,
                    &mut app,
                    &context,
                )
                .await;
            }
            let own_joined = state.message_log.len();
            assert!(
                own_joined <= 1,
                "five arrivals made {own_joined} new frames of ours (one re-announced joined each)"
            );
            rig.endpoint.close().await;
        });
    }

    /// H4, receive side. The same peer announces itself four times in one second, each frame with a
    /// new id and the same stamp (the re-announce of every new arrival did that). The operator
    /// sees one arrival.
    #[test]
    fn h4_four_joined_of_one_key_in_a_second_are_one_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let mut app = Inert;
            for _ in 0..4 {
                let mut joined = Message::new_joined(&rig.mesh, &who);
                joined.timestamp = UnixSecs::now();
                let joined = joined.sign(&peer);
                assert!(
                    !state.mark_seen(&joined),
                    "the frame is new to the seen set"
                );
                let observed = observe(&joined, &mut state, &context);
                handle_presence(
                    PresenceEvent {
                        message: &joined,
                        subtype: PresenceSubtype::Joined,
                        update: &observed.update,
                        surfaceable: observed.surfaceable,
                    },
                    &mut state,
                    &mut app,
                    &context,
                )
                .await;
            }
            let arrivals = arrival_ids(&rig, "swift-cedar").len();
            assert_eq!(
                arrivals, 1,
                "four joined of one key are {arrivals} arrivals"
            );
            rig.endpoint.close().await;
        });
    }

    /// Every frame this node put on the wire: the gossip broadcasts and the pooled unicast writes.
    fn sent_frames(rig: &Rig, state: &EventLoopState) -> Vec<Vec<u8>> {
        let mut frames = rig.sender.broadcast_frames();
        frames.extend(state.unicast_pool.sent_frames());
        frames
    }

    /// A data frame of `len` payload bytes, signed by this node.
    fn data_frame(rig: &Rig, len: usize) -> Verified {
        let mut message = Message::new_app(
            &rig.mesh,
            &rig.us,
            protocol::AppFrameParams::new(
                protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                None,
                None,
                MessageBody::from("x".repeat(len).as_str()),
            ),
        );
        message.timestamp = UnixSecs::now();
        message.sign(&rig.identity)
    }

    /// The wire cost of a join burst. Five peers join while this node sends five data frames of
    /// 512 bytes. Every frame this node broadcasts that is not data is metadata. The `joined`
    /// that a node announces again for each arrival, and the peer info that it floods again for
    /// each arrival, repeat a fact that every member already holds.
    #[test]
    fn wire_cost_of_a_5_peer_join_burst() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let mut state = fresh_state();
            let mut app = Inert;
            for name in [
                "swift-cedar",
                "lost-heron",
                "calm-otter",
                "bold-finch",
                "wild-crane",
            ] {
                let joined =
                    Message::new_joined(&rig.mesh, &nick(name)).sign(&Identity::generate());
                let observed = observe(&joined, &mut state, &context);
                handle_presence(
                    PresenceEvent {
                        message: &joined,
                        subtype: PresenceSubtype::Joined,
                        update: &observed.update,
                        surfaceable: observed.surfaceable,
                    },
                    &mut state,
                    &mut app,
                    &context,
                )
                .await;
            }
            for _ in 0..5 {
                gossip::broadcast_msg(&rig.sender, &data_frame(&rig, 512)).await;
            }
            let counter = WireCounter::of(&sent_frames(&rig, &state));
            eprintln!("WIRE join burst: {counter}");
            assert_eq!(
                counter.frames(FrameClass::Joined),
                0,
                "this node announced its own joined again for an arrival: {counter}"
            );
            // One peer info per arrival is what the code sends. A cut to one flood per window made
            // the lane pair test of the matrix (d11_gate_loopback) fail in 4 of 4 runs, so the
            // bound pins the cost of the code that passes the matrix.
            assert!(
                counter.frames(FrameClass::Announce) <= 5,
                "more than one peer info per arrival: {counter}"
            );
            assert!(
                counter.metadata_percent() <= 45,
                "the metadata share of a 5-peer join burst is too high: {counter}"
            );
            rig.endpoint.close().await;
        });
    }

    /// The wire cost of 60 s of idle. Nothing arrives and nothing is sent but the keepalive.
    #[test]
    fn wire_cost_of_60_idle_seconds() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let mut state = fresh_state();
            let mut since_send = 0u64;
            for _ in 0..60 {
                since_send += 1;
                state.last_sent_at = Instant::now()
                    .checked_sub(Duration::from_secs(since_send))
                    .expect("the monotonic clock has run past 60 s since boot");
                let before = rig.sender.broadcast_frames().len();
                tick_alive(&mut state, &rig.sender, &rig.mesh, &rig.us).await;
                if rig.sender.broadcast_frames().len() > before {
                    since_send = 0;
                }
            }
            let counter = WireCounter::of(&sent_frames(&rig, &state));
            eprintln!("WIRE idle 60 s: {counter}");
            assert_eq!(counter.frames(FrameClass::Data), 0, "idle sends no data");
            assert_eq!(
                counter.frames(FrameClass::Alive),
                2,
                "60 s of idle needs one keepalive per ALIVE_INTERVAL of 30 s: {counter}"
            );
            assert_eq!(
                counter.total_bytes(),
                counter.bytes(FrameClass::Alive),
                "idle sends nothing but keepalives: {counter}"
            );
            rig.endpoint.close().await;
        });
    }

    /// H4, the app view. The first frame of a peer is a meta change, which never adds the peer to
    /// the roster, so `observe` surfaces a synthetic arrival. The peer's own `joined` comes next,
    /// and it is a first sighting for the roster. The operator sees one arrival, not two.
    #[test]
    fn h4_a_synthetic_arrival_and_the_real_joined_are_one_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let mut app = Inert;
            let meta = meta_change(&rig.mesh, &who, &peer, UnixSecs::now());
            assert!(
                receive(&meta, &mut state, &context),
                "the frame is new to the seen set"
            );
            let mut joined = Message::new_joined(&rig.mesh, &who);
            joined.timestamp = UnixSecs::now();
            let joined = joined.sign(&peer);
            assert!(
                !state.mark_seen(&joined),
                "the frame is new to the seen set"
            );
            let observed = observe(&joined, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &joined,
                    subtype: PresenceSubtype::Joined,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut app,
                &context,
            )
            .await;
            let lines = rig.sink.lines();
            let arrivals = arrival_ids(&rig, "swift-cedar").len();
            assert_eq!(arrivals, 1, "one peer, {arrivals} arrivals: {lines:?}");
            rig.endpoint.close().await;
        });
    }

    /// A replay of an old durable frame (a relay or an anti-entropy answer re-sends it) does not
    /// move the last-heard mark of a peer, so it cannot keep a dead peer from its eviction.
    #[test]
    fn a_replayed_old_frame_does_not_keep_a_dead_peer_alive() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let hello = chat(&rig.mesh, &who, &peer, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            let silent = Instant::now()
                .checked_sub(Duration::from_secs(60))
                .expect("the monotonic clock has run past 60 s since boot");
            state.last_seen.insert(who.clone(), silent);

            for make in [state_change, meta_change, peer_info] {
                let old = make(&rig.mesh, &who, &peer, long_ago());
                assert!(
                    receive(&old, &mut state, &context),
                    "the frame is new to the seen set"
                );
            }
            let age = Instant::now().duration_since(state.last_seen[&who]);
            assert!(
                age >= Duration::from_secs(59),
                "a replay moved the last-heard mark to {age:?} ago"
            );
            rig.endpoint.close().await;
        });
    }

    /// A fresh frame of a durable kind does prove life: a peer that only changes its meta, or only
    /// floods its address, is alive, and it must neither be evicted nor stay quiet.
    #[test]
    fn a_fresh_durable_frame_keeps_a_peer_alive_and_returns_a_quiet_one() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_secs(300);
            let hello = chat(
                &rig.mesh,
                &who,
                &peer,
                UnixSecs::now() - Duration::from_secs(120),
            );
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            let silent = Instant::now()
                .checked_sub(Duration::from_secs(60))
                .expect("the monotonic clock has run past 60 s since boot");
            state.last_seen.insert(who.clone(), silent);
            let info = peer_info(
                &rig.mesh,
                &who,
                &peer,
                UnixSecs::now() - Duration::from_secs(80),
            );
            assert!(
                receive(&info, &mut state, &context),
                "the frame is new to the seen set"
            );
            let age = Instant::now().duration_since(state.last_seen[&who]);
            assert!(
                age < Duration::from_secs(5),
                "a fresh peer info did not count as a sign of life: {age:?} ago"
            );

            let gone_quiet = Instant::now()
                .checked_sub(alive_timeout() + Duration::from_secs(10))
                .expect("the monotonic clock has run past the alive timeout since boot");
            state.last_seen.insert(who.clone(), gone_quiet);
            tick_sweep(&mut state, &rig.sink);
            assert!(state.quiet.contains(who.as_str()), "the peer is quiet");
            let change = meta_change(&rig.mesh, &who, &peer, UnixSecs::now());
            assert!(
                receive(&change, &mut state, &context),
                "the frame is new to the seen set"
            );
            let lines = rig.sink.lines();
            assert!(
                lines.iter().any(|line| line == "return swift-cedar"),
                "a fresh meta change did not return the quiet peer: {lines:?}"
            );
            rig.endpoint.close().await;
        });
    }

    /// An hour after a peer went quiet it is no longer known. A relay then re-sends an old frame
    /// of that peer. A durable frame stamped long ago is no arrival, even when the stamp lies after
    /// our own join; a fresh one is.
    #[test]
    fn a_replay_after_the_quiet_ttl_is_no_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let old = UnixSecs::now() - Duration::from_hours(2);
            for make in [peer_info, state_digest, meta_digest, state_change] {
                let replay = make(&rig.mesh, &who, &peer, old);
                assert!(
                    receive(&replay, &mut state, &context),
                    "the frame is new to the seen set"
                );
            }
            let lines = rig.sink.lines();
            assert!(
                lines.is_empty() && !state.peers.contains(who.as_str()),
                "an old durable frame made an arrival: {lines:?}"
            );

            let fresh = peer_info(&rig.mesh, &who, &peer, UnixSecs::now());
            assert!(
                receive(&fresh, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                state.peers.contains(who.as_str()) && !rig.sink.lines().is_empty(),
                "a fresh peer info is an arrival"
            );
            rig.endpoint.close().await;
        });
    }

    /// The same replay with a frame of a live kind. The relay holds an old `alive`, app message,
    /// ping, pong or `joined` of a peer that died long ago, and the quiet TTL has passed, so
    /// nothing remembers the peer. The stamp is 2 h old: older than any clock skew that this node
    /// accepts. It is no arrival.
    #[test]
    fn a_replayed_live_frame_after_the_quiet_ttl_is_no_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let old = UnixSecs::now() - Duration::from_hours(2);
            let probe = Message::new_ping(&rig.mesh, &who);
            let sign_at = |mut message: Message| {
                message.timestamp = old;
                message.sign(&peer)
            };
            let replays = [
                ("alive", alive(&rig.mesh, &who, &peer, old)),
                ("app", chat(&rig.mesh, &who, &peer, old)),
                ("joined", sign_at(Message::new_joined(&rig.mesh, &who))),
                ("ping", sign_at(probe.clone())),
                (
                    "pong",
                    sign_at(Message::new_pong(
                        &rig.mesh,
                        &who,
                        nick("calm-fern"),
                        &probe.id,
                    )),
                ),
            ];
            for (name, replay) in &replays {
                assert!(
                    receive(replay, &mut state, &context),
                    "the {name} frame is new to the seen set"
                );
                let lines = rig.sink.lines();
                assert!(
                    lines.is_empty() && !state.peers.contains(who.as_str()),
                    "an old {name} frame made an arrival: {lines:?}"
                );
            }
            rig.endpoint.close().await;
        });
    }

    /// The live count follows the arrivals that were shown: a peer known only from a frame older
    /// than our join is not counted, and the same peer is counted when its next live frame
    /// arrives.
    #[test]
    fn the_live_count_follows_the_shown_arrivals() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let live = LiveCount::default();
            state.live_count = Some(live.clone());
            state.joined_at = UnixSecs::now();

            let backlog = chat(
                &rig.mesh,
                &who,
                &peer,
                state.joined_at - Duration::from_secs(600),
            );
            assert!(
                receive(&backlog, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert_eq!(
                live.load(Ordering::Relaxed),
                1,
                "a pre-join backlog frame must not count the peer: this node only"
            );

            let fresh = chat(&rig.mesh, &who, &peer, UnixSecs::now());
            assert!(
                receive(&fresh, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert_eq!(
                live.load(Ordering::Relaxed),
                2,
                "the peer is shown, so it counts with this node"
            );
            rig.endpoint.close().await;
        });
    }

    /// The roster and the count agree: a peer known only from a frame older than our join is in
    /// neither, because the app skills list the rows of the roster and a user can pick a row as the
    /// target of a task. The same peer is in both once its arrival is shown.
    #[test]
    fn the_roster_and_the_count_agree_on_a_pre_join_ghost() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now();
            let listed = |held: &EventLoopState| {
                held.roster_snapshot()
                    .peers
                    .iter()
                    .any(|entry| entry.nickname == who)
            };

            let backlog = chat(
                &rig.mesh,
                &who,
                &peer,
                state.joined_at - Duration::from_secs(600),
            );
            assert!(
                receive(&backlog, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                !listed(&state),
                "a pre-join ghost is a row of the roster: {:?}",
                state.roster_snapshot().peers
            );
            let snapshot = state.roster_snapshot();
            assert_eq!(
                snapshot.peers.len() + 1,
                snapshot.count,
                "the rows of the roster and the count disagree: {:?}",
                snapshot.peers
            );

            let fresh = chat(&rig.mesh, &who, &peer, UnixSecs::now());
            assert!(
                receive(&fresh, &mut state, &context),
                "the frame is new to the seen set"
            );
            let shown = state.roster_snapshot();
            assert!(listed(&state), "a shown peer is a row of the roster");
            assert_eq!(
                shown.peers.len() + 1,
                shown.count,
                "the rows of the roster and the count disagree: {:?}",
                shown.peers
            );
            rig.endpoint.close().await;
        });
    }

    /// The undercount bound. A live peer is known first from old frames that arrive as pre-join
    /// backlog, so it is in the roster and not shown. It then sends a fresh `joined`, and its next
    /// `alive` (at most one alive interval later) shows it and counts it.
    #[test]
    fn a_live_peer_known_from_backlog_is_counted_within_one_alive_interval() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let mut app = Inert;
            let live = LiveCount::default();
            state.live_count = Some(live.clone());
            state.joined_at = UnixSecs::now();

            let backlog = chat(
                &rig.mesh,
                &who,
                &peer,
                state.joined_at - Duration::from_secs(600),
            );
            assert!(
                receive(&backlog, &mut state, &context),
                "the frame is new to the seen set"
            );
            let mut joined = Message::new_joined(&rig.mesh, &who);
            joined.timestamp = UnixSecs::now();
            let joined = joined.sign(&peer);
            assert!(
                !state.mark_seen(&joined),
                "the frame is new to the seen set"
            );
            let observed = observe(&joined, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &joined,
                    subtype: PresenceSubtype::Joined,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut app,
                &context,
            )
            .await;

            let beat = alive(&rig.mesh, &who, &peer, UnixSecs::now());
            assert!(
                receive(&beat, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert_eq!(
                live.load(Ordering::Relaxed),
                2,
                "the live peer is not counted after its alive: {:?}",
                rig.sink.lines()
            );
            rig.endpoint.close().await;
        });
    }

    /// A peer whose clock runs more than the quiet TTL behind stamps every frame outside the window
    /// in which a live kind proves presence for a stranger. A peer that is already in the roster
    /// and shown must stay: each live frame of it refreshes its last-heard mark, so the sweep does
    /// not evict a peer that is talking.
    #[test]
    fn a_shown_peer_with_a_clock_2_h_behind_stays_in_the_roster() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);

            let first = chat(
                &rig.mesh,
                &who,
                &peer,
                UnixSecs::now() - Duration::from_secs(100),
            );
            assert!(
                receive(&first, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(state.surfaced.contains(who.as_str()), "the peer is shown");
            let silent = Instant::now()
                .checked_sub(Duration::from_secs(80))
                .expect("the monotonic clock has run past 80 s since boot");
            state.last_seen.insert(who.clone(), silent);

            let slow = alive(
                &rig.mesh,
                &who,
                &peer,
                UnixSecs::now() - Duration::from_hours(2),
            );
            assert!(
                receive(&slow, &mut state, &context),
                "the frame is new to the seen set"
            );
            let age = Instant::now().duration_since(state.last_seen[&who]);
            assert!(
                age < Duration::from_secs(5),
                "a live frame of a shown peer did not refresh it: heard {age:?} ago"
            );
            rig.endpoint.close().await;
        });
    }

    /// The skew tests on the real path. The newest stamp of a peer is recorded by `observe`, the
    /// peer goes quiet in the sweep, a copy of its last frame is stale, and its next frame returns
    /// it. The clock of the peer runs 120 s ahead of ours, or 120 s behind, or a few seconds off.
    #[test]
    fn a_skewed_clock_changes_nothing_on_the_real_path() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let clocks = [
                ("swift-cedar", true, 120),
                ("lost-heron", false, 120),
                ("calm-otter", true, 5),
                ("brave-lynx", false, 5),
            ];
            for (name, ahead, secs) in clocks {
                let who = nick(name);
                let peer = Identity::generate();
                let mut state = fresh_state();
                state.joined_at = UnixSecs::now() - Duration::from_hours(3);
                let skew = Duration::from_secs(secs);
                let on_its_clock = |offset: Duration| {
                    let ours = UnixSecs::now() - offset;
                    if ahead { ours + skew } else { ours - skew }
                };

                let last = alive(
                    &rig.mesh,
                    &who,
                    &peer,
                    on_its_clock(Duration::from_secs(100)),
                );
                assert!(
                    receive(&last, &mut state, &context),
                    "the frame is new to the seen set"
                );
                assert_eq!(
                    state.peer_stamp.get(who.as_str()),
                    Some(&last.timestamp),
                    "{name}: observe did not record the newest stamp"
                );
                let gone_quiet = Instant::now()
                    .checked_sub(alive_timeout() + Duration::from_secs(10))
                    .expect("the monotonic clock has run past the alive timeout since boot");
                state.last_seen.insert(who.clone(), gone_quiet);
                tick_sweep(&mut state, &rig.sink);
                assert!(
                    state.quiet.contains(who.as_str()),
                    "{name}: the peer is quiet"
                );

                let replay = membership_update::compute_for(&last, &state);
                assert!(
                    replay.stale && !replay.returned,
                    "{name}: a copy of the last frame returned the peer: {replay:?}"
                );
                let next = alive(&rig.mesh, &who, &peer, on_its_clock(Duration::ZERO));
                assert!(
                    receive(&next, &mut state, &context),
                    "the frame is new to the seen set"
                );
                let lines = rig.sink.lines();
                let wanted = format!("return {name}");
                assert!(
                    lines.contains(&wanted),
                    "{name}: the next frame did not return the peer: {lines:?}"
                );
            }
            rig.endpoint.close().await;
        });
    }

    /// The join horizon and a slow clock. A peer whose clock runs behind our join stamps its frames
    /// before `joined_at`. A backlog frame looks the same, so the first frames show nothing. The
    /// third live frame of the same key, each 30 s after the one before on both clocks, proves
    /// that the peer is sending now, and it shows and counts the peer.
    #[test]
    fn a_peer_with_a_clock_behind_our_join_is_counted() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let live = LiveCount::default();
            state.live_count = Some(live.clone());
            state.joined_at = UnixSecs::now();

            let first = alive(
                &rig.mesh,
                &who,
                &peer,
                UnixSecs::now() - Duration::from_secs(90),
            );
            assert!(
                receive(&first, &mut state, &context),
                "the frame is new to the seen set"
            );
            heard_ago(&mut state, &who, Duration::from_secs(30));
            let beat = alive(
                &rig.mesh,
                &who,
                &peer,
                UnixSecs::now() - Duration::from_secs(60),
            );
            assert!(
                receive(&beat, &mut state, &context),
                "the frame is new to the seen set"
            );
            heard_ago(&mut state, &who, Duration::from_secs(30));
            let third = alive(
                &rig.mesh,
                &who,
                &peer,
                UnixSecs::now() - Duration::from_secs(30),
            );
            assert!(
                receive(&third, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert_eq!(
                live.load(Ordering::Relaxed),
                2,
                "a live peer whose clock is 60 s behind our join is not counted"
            );
            rig.endpoint.close().await;
        });
    }

    /// The join horizon and a return. A quiet peer returns with frames stamped before our join:
    /// the third live frame shows it, so the returned peer is in the roster and counted.
    #[test]
    fn a_return_stamped_before_our_join_is_counted() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let live = LiveCount::default();
            state.live_count = Some(live.clone());
            state.quiet.insert(who.clone());
            state.joined_at = UnixSecs::now();

            let first = alive(
                &rig.mesh,
                &who,
                &peer,
                UnixSecs::now() - Duration::from_secs(90),
            );
            assert!(
                receive(&first, &mut state, &context),
                "the frame is new to the seen set"
            );
            heard_ago(&mut state, &who, Duration::from_secs(30));
            let back = alive(
                &rig.mesh,
                &who,
                &peer,
                UnixSecs::now() - Duration::from_secs(60),
            );
            assert!(
                receive(&back, &mut state, &context),
                "the frame is new to the seen set"
            );
            heard_ago(&mut state, &who, Duration::from_secs(30));
            let third = alive(
                &rig.mesh,
                &who,
                &peer,
                UnixSecs::now() - Duration::from_secs(30),
            );
            assert!(
                receive(&third, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(state.peers.contains(who.as_str()), "the peer is back");
            assert_eq!(
                live.load(Ordering::Relaxed),
                2,
                "a peer that returned with a frame stamped before our join is not counted"
            );
            rig.endpoint.close().await;
        });
    }

    /// A backlog burst is no arrival. Many old live frames of one key that reach us in the same
    /// moment, whatever their stamps, do not show the peer: it would be a ghost.
    #[test]
    fn a_burst_of_old_live_frames_is_no_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let live = LiveCount::default();
            state.live_count = Some(live.clone());
            state.joined_at = UnixSecs::now();

            for step in 0..12 {
                let stamp =
                    state.joined_at - Duration::from_mins(15) + Duration::from_secs(30 * step);
                let frame = if step % 2 == 0 {
                    alive(&rig.mesh, &who, &peer, stamp)
                } else {
                    chat(&rig.mesh, &who, &peer, stamp)
                };
                assert!(
                    receive(&frame, &mut state, &context),
                    "the frame is new to the seen set"
                );
            }
            assert!(
                !state.surfaced.contains(who.as_str()),
                "a burst of old frames showed a ghost: {:?}",
                rig.sink.lines()
            );
            assert_eq!(
                live.load(Ordering::Relaxed),
                1,
                "a burst of old frames counted a ghost"
            );
            rig.endpoint.close().await;
        });
    }

    /// Frames of one key that come 5 s apart on both clocks are a slow replay, not a peer that
    /// sends now: the spacing is 15 s. Each frame is compared with the one before it, so frames
    /// that come close together never add up.
    #[test]
    fn old_live_frames_5_secs_apart_are_no_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let live = LiveCount::default();
            state.live_count = Some(live.clone());
            state.joined_at = UnixSecs::now();

            for step in 0..8 {
                let stamp =
                    state.joined_at - Duration::from_secs(600) + Duration::from_secs(5 * step);
                let frame = alive(&rig.mesh, &who, &peer, stamp);
                assert!(
                    receive(&frame, &mut state, &context),
                    "the frame is new to the seen set"
                );
                heard_ago(&mut state, &who, Duration::from_secs(5));
            }
            assert!(
                !state.surfaced.contains(who.as_str()),
                "frames 5 s apart showed a ghost: {:?}",
                rig.sink.lines()
            );
            assert_eq!(
                live.load(Ordering::Relaxed),
                1,
                "frames 5 s apart counted a ghost"
            );
            rig.endpoint.close().await;
        });
    }

    /// Frames of two keys under one nickname are not a stream of one peer, so the second key does
    /// not use the record of the first.
    #[test]
    fn old_live_frames_of_two_keys_are_no_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now();

            let first = alive(
                &rig.mesh,
                &who,
                &Identity::generate(),
                state.joined_at - Duration::from_secs(90),
            );
            assert!(
                receive(&first, &mut state, &context),
                "the frame is new to the seen set"
            );
            heard_ago(&mut state, &who, Duration::from_secs(30));
            let second = alive(
                &rig.mesh,
                &who,
                &Identity::generate(),
                state.joined_at - Duration::from_secs(60),
            );
            assert!(
                receive(&second, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                !state.surfaced.contains(who.as_str()),
                "two keys under one nickname showed a ghost: {:?}",
                rig.sink.lines()
            );
            rig.endpoint.close().await;
        });
    }

    /// Two replayed live frames of a peer that has stopped, stamped 15 s apart and delivered 15 s
    /// apart, are the least that the old rule took for a peer that sends now. Two frames cannot
    /// tell a paced replay from a stream, so they show nothing.
    #[test]
    fn two_old_live_frames_15_secs_apart_are_no_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let live = LiveCount::default();
            state.live_count = Some(live.clone());
            state.joined_at = UnixSecs::now();

            let first = alive(
                &rig.mesh,
                &who,
                &peer,
                state.joined_at - Duration::from_secs(600),
            );
            assert!(
                receive(&first, &mut state, &context),
                "the frame is new to the seen set"
            );
            heard_ago(&mut state, &who, Duration::from_secs(15));
            let second = alive(
                &rig.mesh,
                &who,
                &peer,
                state.joined_at - Duration::from_secs(585),
            );
            assert!(
                receive(&second, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                !state.surfaced.contains(who.as_str()),
                "two replayed frames 15 s apart showed a ghost: {:?}",
                rig.sink.lines()
            );
            assert_eq!(
                live.load(Ordering::Relaxed),
                1,
                "two replayed frames 15 s apart counted a ghost"
            );
            rig.endpoint.close().await;
        });
    }

    /// The stamps of a live peer advance as fast as our clock. Frames whose stamps are 60 s apart
    /// and that reach us 15 s apart are an old stream sent faster than it was made.
    #[test]
    fn old_live_frames_whose_stamps_outrun_our_clock_are_no_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let live = LiveCount::default();
            state.live_count = Some(live.clone());
            state.joined_at = UnixSecs::now();

            for step in 0..4 {
                let stamp =
                    state.joined_at - Duration::from_mins(15) + Duration::from_secs(60 * step);
                let frame = alive(&rig.mesh, &who, &peer, stamp);
                assert!(
                    receive(&frame, &mut state, &context),
                    "the frame is new to the seen set"
                );
                heard_ago(&mut state, &who, Duration::from_secs(15));
            }
            assert!(
                !state.surfaced.contains(who.as_str()),
                "stamps that outrun our clock showed a ghost: {:?}",
                rig.sink.lines()
            );
            rig.endpoint.close().await;
        });
    }

    /// A new run of a nickname whose clock is behind the goodbye of the old run is not a replay.
    /// Its frames are stale until three of them, each 30 s after the one before on both clocks,
    /// show that the run sends now. Then it is in the roster.
    #[test]
    fn a_replacement_run_with_a_slow_clock_after_a_goodbye_reaches_the_roster() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let old_run = Identity::generate();
            let new_run = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let hello = chat(&rig.mesh, &who, &old_run, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            say_goodbye(&old_run, &who, &rig, &mut state, &mut Inert).await;
            assert!(
                !state.peers.contains(who.as_str()),
                "the goodbye did not remove the peer"
            );

            for step in 0..3 {
                let frame = alive(
                    &rig.mesh,
                    &who,
                    &new_run,
                    UnixSecs::now() - Duration::from_secs(300 - 30 * step),
                );
                assert!(
                    receive(&frame, &mut state, &context),
                    "the frame is new to the seen set"
                );
                heard_ago(&mut state, &who, Duration::from_secs(30));
            }
            assert!(
                state.peers.contains(who.as_str()),
                "a new run with a clock 5 min behind the old goodbye stays out of the roster"
            );
            rig.endpoint.close().await;
        });
    }

    /// A replay of a killed run after a goodbye must stay stale when it comes as a stream that
    /// does not follow our clock: three frames delivered in one burst.
    #[test]
    fn a_burst_of_frames_of_a_killed_run_after_a_goodbye_is_no_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let live_run = Identity::generate();
            let killed_run = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let hello = chat(&rig.mesh, &who, &live_run, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            say_goodbye(&live_run, &who, &rig, &mut state, &mut Inert).await;

            for step in 0..6 {
                let frame = alive(
                    &rig.mesh,
                    &who,
                    &killed_run,
                    UnixSecs::now() - Duration::from_secs(600 - 30 * step),
                );
                assert!(
                    receive(&frame, &mut state, &context),
                    "the frame is new to the seen set"
                );
            }
            assert!(
                !state.peers.contains(who.as_str()),
                "a burst of frames of a killed run put a gone peer back in the roster"
            );
            rig.endpoint.close().await;
        });
    }

    /// A quiet peer whose clock is behind our join returns. Its return is a return, whatever the
    /// frame that proves it: the operator read "timed out" and must read "returned", not a new
    /// "joined".
    #[test]
    fn a_quiet_peer_with_a_slow_clock_is_shown_as_returned_not_joined() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            state.quiet.insert(who.clone());
            state.joined_at = UnixSecs::now();

            for step in 0..3 {
                let frame = alive(
                    &rig.mesh,
                    &who,
                    &peer,
                    UnixSecs::now() - Duration::from_secs(90 - 30 * step),
                );
                assert!(
                    receive(&frame, &mut state, &context),
                    "the frame is new to the seen set"
                );
                heard_ago(&mut state, &who, Duration::from_secs(30));
            }
            let lines = rig.sink.lines();
            assert!(
                lines.iter().any(|line| line == "return swift-cedar"),
                "no return was shown: {lines:?}"
            );
            assert!(
                !lines.iter().any(|line| line.starts_with("presence")),
                "a returned peer was shown as a new arrival: {lines:?}"
            );
            rig.endpoint.close().await;
        });
    }

    /// The goodbye of the live run and a frame of an older run stamped in the same second: the
    /// stamp cannot say which came first, so the frame is a replay. A new run proves itself by a
    /// run of frames, not by one stamp.
    #[test]
    fn an_older_run_frame_in_the_second_of_a_goodbye_is_no_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let live_run = Identity::generate();
            let killed_run = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let hello = chat(&rig.mesh, &who, &live_run, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            say_goodbye(&live_run, &who, &rig, &mut state, &mut Inert).await;
            let said = state.clock_evidence.goodbye_stamp[&who];

            let relayed = alive(&rig.mesh, &who, &killed_run, said);
            assert!(
                receive(&relayed, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                !state.peers.contains(who.as_str()),
                "a frame of an older run in the second of the goodbye put a gone peer back"
            );
            rig.endpoint.close().await;
        });
    }

    /// The run of a replacement is kept across the sweep: the sweep runs every 10 s, and the
    /// nickname of a goodbye is in no roster set, so a sweep that drops its run restarts the
    /// count at each pass and the run never completes.
    #[test]
    fn a_replacement_run_survives_the_sweep() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let old_run = Identity::generate();
            let new_run = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let hello = chat(&rig.mesh, &who, &old_run, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            say_goodbye(&old_run, &who, &rig, &mut state, &mut Inert).await;

            for step in 0..3 {
                let frame = alive(
                    &rig.mesh,
                    &who,
                    &new_run,
                    UnixSecs::now() - Duration::from_secs(300 - 30 * step),
                );
                assert!(
                    receive(&frame, &mut state, &context),
                    "the frame is new to the seen set"
                );
                heard_ago(&mut state, &who, Duration::from_secs(30));
                tick_sweep(&mut state, &rig.sink);
            }
            assert!(
                state.peers.contains(who.as_str()),
                "the sweep dropped the run of a replacement"
            );
            rig.endpoint.close().await;
        });
    }

    /// A signed `Left` of any key must not remove a roster peer that has no recorded holder. The
    /// peer stays until its own silence or its own goodbye.
    #[test]
    fn a_left_with_no_recorded_holder_removes_no_roster_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let who = nick("swift-cedar");
            let mut state = fresh_state();
            state.peers.insert(who.clone());
            state.surfaced.insert(who.clone());

            say_goodbye(&Identity::generate(), &who, &rig, &mut state, &mut Inert).await;

            assert!(
                state.peers.contains(who.as_str()),
                "a goodbye of a stranger key removed a peer that has no holder"
            );
            rig.endpoint.close().await;
        });
    }

    /// Two frames of one second under two keys are not told apart by the stamp. The holder keeps
    /// the nickname, so its own goodbye still removes the peer.
    #[test]
    fn an_equal_second_frame_of_another_key_does_not_take_the_holder() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let holder = Identity::generate();
            let other = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let stamp = UnixSecs::now();
            let first = alive(&rig.mesh, &who, &holder, stamp);
            assert!(
                receive(&first, &mut state, &context),
                "the frame is new to the seen set"
            );
            let copy = chat(&rig.mesh, &who, &other, stamp);
            assert!(
                receive(&copy, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert_eq!(
                state.peer_keys.get(who.as_str()),
                Some(&holder.author_key()),
                "a frame of the same second under another key took the nickname"
            );
            say_goodbye(&holder, &who, &rig, &mut state, &mut Inert).await;
            assert!(
                !state.peers.contains(who.as_str()),
                "the goodbye of the holder did not remove the peer"
            );
            rig.endpoint.close().await;
        });
    }

    /// A peer comes back with the same key after the quiet TTL: it keeps the dial hint. Another
    /// key under the same nickname does not inherit it, or a directed send would go to the node
    /// of the old holder.
    #[test]
    fn a_dial_hint_goes_with_the_key_that_made_it() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let holder = Identity::generate();
            let stranger = Identity::generate();
            let endpoint = iroh::SecretKey::from_bytes(&[3; 32]).public();
            for returns_as in [&holder, &stranger] {
                let mut state = fresh_state();
                state.joined_at = UnixSecs::now() - Duration::from_hours(3);
                let hello = alive(&rig.mesh, &who, &holder, UnixSecs::now());
                assert!(
                    receive(&hello, &mut state, &context),
                    "the frame is new to the seen set"
                );
                state
                    .peer_endpoints
                    .insert(who.clone(), iroh::EndpointAddr::new(endpoint));
                state.last_seen.insert(
                    who.clone(),
                    Instant::now()
                        .checked_sub(alive_timeout() + Duration::from_secs(5))
                        .expect("the monotonic clock has run past the alive timeout since boot"),
                );
                tick_sweep(&mut state, &rig.sink);
                state.quiet_since.insert(
                    who.clone(),
                    Instant::now()
                        .checked_sub(Duration::from_hours(2))
                        .expect("the monotonic clock has run past 2 h since boot"),
                );
                tick_sweep(&mut state, &rig.sink);
                assert!(
                    state.peer_endpoints.contains_key(who.as_str()),
                    "the hint did not outlive the quiet TTL"
                );

                let back = alive(
                    &rig.mesh,
                    &who,
                    returns_as,
                    UnixSecs::now() + Duration::from_secs(1),
                );
                assert!(
                    receive(&back, &mut state, &context),
                    "the frame is new to the seen set"
                );
                let kept = state.peer_endpoints.contains_key(who.as_str());
                let same_key = returns_as.author_key() == holder.author_key();
                assert_eq!(
                    kept, same_key,
                    "the dial hint after a return (same key: {same_key}) is wrong"
                );
            }
            rig.endpoint.close().await;
        });
    }

    /// The same holds inside the quiet window: another key that takes the nickname of a quiet
    /// peer does not inherit its dial hint.
    #[test]
    fn a_quiet_peers_dial_hint_does_not_go_to_another_key() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let holder = Identity::generate();
            let stranger = Identity::generate();
            let endpoint = iroh::SecretKey::from_bytes(&[3; 32]).public();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let hello = alive(&rig.mesh, &who, &holder, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            state
                .peer_endpoints
                .insert(who.clone(), iroh::EndpointAddr::new(endpoint));
            state.last_seen.insert(
                who.clone(),
                Instant::now()
                    .checked_sub(alive_timeout() + Duration::from_secs(5))
                    .expect("the monotonic clock has run past the alive timeout since boot"),
            );
            tick_sweep(&mut state, &rig.sink);
            assert!(state.quiet.contains(who.as_str()), "the peer is quiet");

            let back = alive(
                &rig.mesh,
                &who,
                &stranger,
                UnixSecs::now() + Duration::from_secs(1),
            );
            assert!(
                receive(&back, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                !state.peer_endpoints.contains_key(who.as_str()),
                "another key inherited the dial hint of a quiet peer"
            );
            rig.endpoint.close().await;
        });
    }

    /// The receive path confirms a noted suspend: a live frame that reaches `observe` with a stamp
    /// near our wall clock vouches for it, and the next sweep removes the quiet peer. Without the
    /// call in `observe`, nothing but a direct call of `confirm_suspend` would age it.
    #[test]
    fn a_live_frame_on_the_receive_path_confirms_a_suspend() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let half_hour_ago = Instant::now()
                .checked_sub(Duration::from_mins(30))
                .expect("the monotonic clock has run past 30 min since boot");
            state.quiet.insert(nick("lost-heron"));
            state.quiet_since.insert(nick("lost-heron"), half_hour_ago);
            heartbeat::note_suspend(&mut state, Duration::from_mins(40));

            let live = alive(
                &rig.mesh,
                &nick("swift-cedar"),
                &Identity::generate(),
                UnixSecs::now(),
            );
            assert!(
                receive(&live, &mut state, &context),
                "the frame is new to the seen set"
            );
            tick_sweep(&mut state, &rig.sink);

            assert!(
                !state.quiet.contains("lost-heron"),
                "a live frame on the receive path did not vouch for the suspend"
            );
            rig.endpoint.close().await;
        });
    }

    /// The records of the join horizon and of the goodbyes stay bounded: the sweep drops the
    /// record of a nickname that left the roster and a goodbye older than the quiet TTL, and the
    /// goodbyes never pass `QUIET_CAP`.
    #[test]
    fn the_sweep_prunes_the_pre_join_record_and_the_old_goodbyes() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let kept = nick("kept-peer");
            let gone = nick("gone-peer");
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now();
            state.peers.insert(kept.clone());
            let frame = alive(
                &rig.mesh,
                &kept,
                &Identity::generate(),
                state.joined_at - Duration::from_secs(60),
            );
            let record = LiveRun {
                key: frame.key(),
                last: frame.timestamp,
                at: Instant::now(),
                count: 1,
            };
            state.clock_evidence.live_run.insert(kept.clone(), record);
            state.clock_evidence.live_run.insert(gone.clone(), record);
            for who in [&kept, &gone] {
                state
                    .clock_evidence
                    .heard
                    .insert(who.clone(), Instant::now());
                state.clock_evidence.returned_unshown.insert(who.clone());
            }
            state.note_goodbye_stamp(&gone, UnixSecs::now() - Duration::from_hours(2));
            state.note_goodbye_stamp(&kept, UnixSecs::now());

            tick_sweep(&mut state, &rig.sink);
            let pre_join_names: Vec<&Nickname> = state.clock_evidence.live_run.keys().collect();
            let goodbye_names: Vec<&Nickname> = state.clock_evidence.goodbye_stamp.keys().collect();
            assert!(
                state.clock_evidence.live_run.contains_key(&kept)
                    && !state.clock_evidence.live_run.contains_key(&gone),
                "the pre-join record does not follow the roster: {pre_join_names:?}"
            );
            assert!(
                state.clock_evidence.goodbye_stamp.contains_key(&kept)
                    && !state.clock_evidence.goodbye_stamp.contains_key(&gone),
                "the sweep kept a goodbye older than the quiet TTL: {goodbye_names:?}"
            );
            assert!(
                state.clock_evidence.heard.contains_key(&kept)
                    && !state.clock_evidence.heard.contains_key(&gone)
                    && state.clock_evidence.returned_unshown.contains(&kept)
                    && !state.clock_evidence.returned_unshown.contains(&gone),
                "the heard marks and the unshown returns do not follow the roster"
            );

            for index in 0..(QUIET_CAP + 20) {
                state.note_goodbye_stamp(&nick(&format!("peer-{index}")), UnixSecs::now());
            }
            assert!(
                state.clock_evidence.goodbye_stamp.len() <= QUIET_CAP,
                "the goodbye stamps passed the cap: {}",
                state.clock_evidence.goodbye_stamp.len()
            );
            rig.endpoint.close().await;
        });
    }

    /// `live_nicknames` lists every peer that is in the roster and not quiet, shown or not. A
    /// quiet peer and a peer that left are not in it. The roster rows list shown peers only, so
    /// a reader of the rows alone takes a live peer that is not shown yet for an absent one.
    #[test]
    fn live_nicknames_lists_every_live_peer_shown_or_not() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now();
            let shown = nick("shown-peer");
            let hidden = nick("hidden-peer");
            let quiet = nick("quiet-peer");
            let left = nick("left-peer");
            let left_run = Identity::generate();

            let fresh = alive(&rig.mesh, &shown, &Identity::generate(), UnixSecs::now());
            let backlog = alive(
                &rig.mesh,
                &hidden,
                &Identity::generate(),
                state.joined_at - Duration::from_secs(600),
            );
            let gone = alive(&rig.mesh, &left, &left_run, UnixSecs::now());
            for frame in [&fresh, &backlog, &gone] {
                assert!(
                    receive(frame, &mut state, &context),
                    "the frame is new to the seen set"
                );
            }
            say_goodbye(&left_run, &left, &rig, &mut state, &mut Inert).await;
            state.quiet.insert(quiet);

            assert!(
                state.surfaced.contains(shown.as_str())
                    && !state.surfaced.contains(hidden.as_str()),
                "the setup needs one shown peer and one hidden peer"
            );
            let live = state.live_nicknames();
            let mut names: Vec<String> = live.map(ToString::to_string).collect();
            names.sort();
            assert_eq!(
                names,
                vec!["hidden-peer".to_owned(), "shown-peer".to_owned()],
                "the live nicknames are not the peers of the roster that are not quiet"
            );
            rig.endpoint.close().await;
        });
    }

    /// An app that records which peers it was told have left.
    #[derive(Default)]
    struct Leaves(Vec<String>);

    #[async_trait::async_trait]
    impl NodeApp for Leaves {
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

        async fn on_peer_left(
            &mut self,
            nickname: &Nickname,
            _state: &mut EventLoopState,
            _context: &HandlerCtx<'_>,
        ) {
            self.0.push(nickname.to_string());
        }
    }

    /// A goodbye from a key, for a nickname that has no roster entry and no recorded holder,
    /// authorizes no clean-up: any key can sign a goodbye under any nickname. The goodbye of the
    /// holder of a nickname that we know still cleans up.
    #[test]
    fn a_goodbye_for_a_nickname_with_no_holder_cleans_up_nothing() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let holder = Identity::generate();
            let mut state = fresh_state();
            let mut app = Leaves::default();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);

            say_goodbye(&Identity::generate(), &who, &rig, &mut state, &mut app).await;
            assert!(
                app.0.is_empty(),
                "a goodbye for a nickname with no holder cleaned up the app: {:?}",
                app.0
            );

            let hello = chat(&rig.mesh, &who, &holder, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            say_goodbye(&holder, &who, &rig, &mut state, &mut app).await;
            assert_eq!(
                app.0,
                vec!["swift-cedar".to_owned()],
                "the goodbye of the holder did not clean up the app"
            );
            rig.endpoint.close().await;
        });
    }

    /// A durable frame (state or meta) of a nickname that we have not seen does not put the
    /// nickname in the roster, so it must not show an arrival either: the arrival would be a
    /// peer that the count and the rows leave out. The next live frame of the peer shows it.
    #[test]
    fn a_state_or_meta_frame_of_an_unseen_peer_shows_no_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);

            for (name, make) in [
                (
                    "state-peer",
                    state_change as fn(&MeshId, &Nickname, &Identity, UnixSecs) -> Verified,
                ),
                ("meta-peer", meta_change),
            ] {
                let who = nick(name);
                let peer = Identity::generate();
                let durable = make(&rig.mesh, &who, &peer, UnixSecs::now());
                assert!(
                    receive(&durable, &mut state, &context),
                    "the frame is new to the seen set"
                );
                let shown = state.surfaced.contains(who.as_str());
                let in_roster = state.peers.contains(who.as_str());
                assert!(
                    !shown,
                    "{name}: a durable frame of an unseen peer showed an arrival"
                );
                let arrival = format!("presence {name} ");
                let lines = rig.sink.lines();
                let emitted = lines.iter().any(|line| line.starts_with(&arrival));
                assert!(
                    !emitted,
                    "{name}: a durable frame of an unseen peer emitted an arrival: {lines:?}"
                );
                assert_eq!(
                    shown,
                    in_roster,
                    "{name}: the arrival and the roster disagree: {:?}",
                    rig.sink.lines()
                );
                assert_eq!(
                    state.member_count(),
                    1 + state.surfaced.len(),
                    "{name}: a shown arrival is not counted"
                );

                let beat = alive(&rig.mesh, &who, &peer, UnixSecs::now());
                assert!(
                    receive(&beat, &mut state, &context),
                    "the frame is new to the seen set"
                );
                assert!(
                    state.surfaced.contains(who.as_str()) && state.peers.contains(who.as_str()),
                    "{name}: the live frame did not show the peer"
                );
            }
            rig.endpoint.close().await;
        });
    }

    /// A quiet peer that returns leaves `quiet_since` with the quiet set. The entry is older than
    /// the quiet TTL when the sweep runs before the next one drops it, and the sweep reads such
    /// an entry as a lapsed peer: the returned peer would take a place in the bounded set of
    /// lapsed names and push the dial hint of another peer out.
    #[test]
    fn a_returned_peer_is_not_read_as_lapsed() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            state.quiet.insert(who.clone());
            let long_gone = Instant::now()
                .checked_sub(heartbeat::QUIET_TTL + Duration::from_secs(60))
                .expect("the monotonic clock has run past the quiet TTL since boot");
            state.quiet_since.insert(who.clone(), long_gone);
            state.peer_keys.insert(who.clone(), peer.author_key());
            state
                .peer_stamp
                .insert(who.clone(), UnixSecs::now() - Duration::from_hours(2));

            let back = alive(&rig.mesh, &who, &peer, UnixSecs::now());
            assert!(
                receive(&back, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                state.peers.contains(who.as_str()) && !state.quiet.contains(who.as_str()),
                "the peer did not return"
            );
            tick_sweep(&mut state, &rig.sink);

            assert!(
                !state.quiet_since.contains_key(who.as_str()),
                "a returned peer kept its quiet recency"
            );
            assert!(
                !state.clock_evidence.lapsed_quiet.contains(who.as_str()),
                "a returned peer was read as lapsed"
            );
            rig.endpoint.close().await;
        });
    }

    /// The same for a quiet peer that says goodbye: it is gone, not lapsed.
    #[test]
    fn a_quiet_peer_that_said_goodbye_is_not_read_as_lapsed() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            state.quiet.insert(who.clone());
            let long_gone = Instant::now()
                .checked_sub(heartbeat::QUIET_TTL + Duration::from_secs(60))
                .expect("the monotonic clock has run past the quiet TTL since boot");
            state.quiet_since.insert(who.clone(), long_gone);
            state.peer_keys.insert(who.clone(), peer.author_key());

            say_goodbye(&peer, &who, &rig, &mut state, &mut Inert).await;
            tick_sweep(&mut state, &rig.sink);

            assert!(
                !state.clock_evidence.lapsed_quiet.contains(who.as_str()),
                "a peer that said goodbye was read as lapsed"
            );
            rig.endpoint.close().await;
        });
    }

    /// A clock that stepped back puts the goodbye of a run before its own newest frame. The
    /// goodbye guards against replays, so the next run needs no other ceiling: a `joined` of a
    /// new key after the goodbye holds the nickname, and its own goodbye then ends it.
    #[test]
    fn a_joined_after_a_goodbye_of_a_stepped_back_clock_holds_the_nickname() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let old_run = Identity::generate();
            let new_run = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let now = UnixSecs::now();
            let beat = alive(&rig.mesh, &who, &old_run, now);
            assert!(
                receive(&beat, &mut state, &context),
                "the frame is new to the seen set"
            );

            let mut bye = Message::new_left(&rig.mesh, &who);
            bye.timestamp = now - Duration::from_secs(5);
            let bye = bye.sign(&old_run);
            assert!(!state.mark_seen(&bye), "the frame is new to the seen set");
            let observed = observe(&bye, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &bye,
                    subtype: PresenceSubtype::Left,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut Inert,
                &context,
            )
            .await;
            assert!(
                !state.peers.contains(who.as_str()),
                "the goodbye ended the run"
            );

            let mut hello = Message::new_joined(&rig.mesh, &who);
            hello.timestamp = now - Duration::from_secs(2);
            let hello = hello.sign(&new_run);
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );

            assert!(
                state.peers.contains(who.as_str()),
                "the new run is in the roster"
            );
            assert_eq!(
                state.peer_keys.get(who.as_str()),
                Some(&new_run.author_key()),
                "a peer in the roster has no holder: its own goodbye would remove nothing"
            );
            say_goodbye(&new_run, &who, &rig, &mut state, &mut Inert).await;
            assert!(
                !state.peers.contains(who.as_str()),
                "the goodbye of the replacement run did not remove the peer"
            );
            rig.endpoint.close().await;
        });
    }

    /// A frame of a killed run, copied by a relay, must not keep the live run in the roster: the
    /// last-heard mark of a nickname moves only for frames of the key that holds it. If it moved
    /// for any key, a relay that replays old frames of the dead run would hold a silent peer.
    #[test]
    fn a_frame_of_a_killed_run_does_not_refresh_the_live_run() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let live_run = Identity::generate();
            let killed_run = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);

            let hello = chat(&rig.mesh, &who, &live_run, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            let heard = Instant::now()
                .checked_sub(Duration::from_secs(60))
                .expect("the monotonic clock has run past 60 s since boot");
            state.last_seen.insert(who.clone(), heard);

            let relayed = alive(
                &rig.mesh,
                &who,
                &killed_run,
                UnixSecs::now() - Duration::from_mins(10),
            );
            assert!(
                receive(&relayed, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert_eq!(
                state.last_seen.get(who.as_str()),
                Some(&heard),
                "a replayed frame of the killed run moved the last-heard mark of the live run"
            );

            let beat = alive(&rig.mesh, &who, &live_run, UnixSecs::now());
            assert!(
                receive(&beat, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                state
                    .last_seen
                    .get(who.as_str())
                    .is_some_and(|seen| *seen > heard),
                "a frame of the live run did not move its last-heard mark"
            );
            rig.endpoint.close().await;
        });
    }

    /// A real `joined` that follows pre-join backlog of the same peer shows the peer at once. The
    /// peer is in the roster already (the backlog put it there), so the `joined` is not a first
    /// contact, and it must still be the arrival that the user sees.
    #[test]
    fn a_fresh_joined_shows_a_peer_known_from_backlog() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            let live = LiveCount::default();
            state.live_count = Some(live.clone());
            state.joined_at = UnixSecs::now();

            let backlog = chat(
                &rig.mesh,
                &who,
                &peer,
                state.joined_at - Duration::from_secs(600),
            );
            assert!(
                receive(&backlog, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                state.peers.contains(who.as_str()) && !state.surfaced.contains(who.as_str()),
                "the setup needs a peer that is known and not shown"
            );

            let mut joined = Message::new_joined(&rig.mesh, &who);
            joined.timestamp = UnixSecs::now();
            let joined = joined.sign(&peer);
            assert!(
                !state.mark_seen(&joined),
                "the frame is new to the seen set"
            );
            let observed = observe(&joined, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &joined,
                    subtype: PresenceSubtype::Joined,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut Inert,
                &context,
            )
            .await;
            assert_eq!(
                live.load(Ordering::Relaxed),
                2,
                "a fresh joined did not show the peer: {:?}",
                rig.sink.lines()
            );
            assert_eq!(
                arrival_ids(&rig, "swift-cedar").len(),
                1,
                "the peer was not shown exactly once: {:?}",
                rig.sink.lines()
            );
            rig.endpoint.close().await;
        });
    }

    /// The ids of the arrivals this node surfaced for `who`, in order.
    fn arrival_ids(rig: &Rig, who: &str) -> Vec<String> {
        let prefix = format!("presence {who} ");
        let lines = rig.sink.lines();
        let own = lines.iter().filter(|line| line.starts_with(&prefix));
        let ids = own.filter_map(|line| line.split("id=").nth(1));
        ids.map(str::to_owned).collect()
    }

    /// The app drops a frame whose (key, id) it saw lately. A key that this node forgot (it went
    /// quiet and the quiet TTL passed) and that speaks again is a second arrival, and it must not
    /// have the id of the first.
    #[test]
    fn h4_a_second_arrival_of_one_key_has_its_own_id() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);

            let first = chat(
                &rig.mesh,
                &who,
                &peer,
                UnixSecs::now() - Duration::from_secs(100),
            );
            assert!(
                receive(&first, &mut state, &context),
                "the frame is new to the seen set"
            );
            let gone_quiet = Instant::now()
                .checked_sub(alive_timeout() + Duration::from_secs(10))
                .expect("the monotonic clock has run past the alive timeout since boot");
            state.last_seen.insert(who.clone(), gone_quiet);
            tick_sweep(&mut state, &rig.sink);
            assert!(state.quiet.contains(who.as_str()), "the peer is quiet");
            let long_gone = Instant::now()
                .checked_sub(Duration::from_hours(2))
                .expect("the monotonic clock has run past 2 h since boot");
            state.quiet_since.insert(who.clone(), long_gone);
            tick_sweep(&mut state, &rig.sink);
            assert!(!state.quiet.contains(who.as_str()), "the quiet TTL passed");

            let again = chat(&rig.mesh, &who, &peer, UnixSecs::now());
            assert!(
                receive(&again, &mut state, &context),
                "the frame is new to the seen set"
            );
            let ids = arrival_ids(&rig, "swift-cedar");
            assert_eq!(ids.len(), 2, "two arrivals: {:?}", rig.sink.lines());
            assert_ne!(ids[0], ids[1], "the second arrival has the id of the first");
            rig.endpoint.close().await;
        });
    }

    /// A new peer whose clock runs 2 min behind: its first frame is a peer info stamped older than
    /// the alive timeout, which proves nothing, so it is no arrival. Its next live frame (an
    /// alive, at most 30 s later) is.
    #[test]
    fn a_new_peer_with_a_slow_clock_arrives_on_its_first_live_frame() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let peer = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(1);
            let slow = UnixSecs::now() - Duration::from_secs(120);

            let info = peer_info(&rig.mesh, &who, &peer, slow);
            assert!(
                receive(&info, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                arrival_ids(&rig, "swift-cedar").is_empty(),
                "a peer info stamped 2 min ago made an arrival"
            );

            let beat = alive(&rig.mesh, &who, &peer, slow);
            assert!(
                receive(&beat, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert_eq!(
                arrival_ids(&rig, "swift-cedar").len(),
                1,
                "the alive of the slow peer is its arrival: {:?}",
                rig.sink.lines()
            );
            rig.endpoint.close().await;
        });
    }

    /// H7. The roster is keyed by nickname. Two live keys with one nickname share one entry, so
    /// the live count is too low.
    #[test]
    #[ignore = "open: the roster is keyed by nickname, so two live keys share one entry"]
    fn h7_two_live_keys_with_one_nickname_count_once() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let mut state = fresh_state();
            let first = chat(&rig.mesh, &who, &Identity::generate(), UnixSecs::now());
            let second = chat(&rig.mesh, &who, &Identity::generate(), UnixSecs::now());
            assert!(
                receive(&first, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                receive(&second, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert_eq!(
                state.peers.len(),
                2,
                "two live keys are one roster entry: {:?}",
                state.peers
            );
            rig.endpoint.close().await;
        });
    }

    /// H7. The first run of a nickname dies and its `left` is delayed. A second run took the
    /// nickname in the meantime. The first `left` of the old key (not a replay) removes the new
    /// run from the roster, and un-surfaces it.
    #[test]
    fn h7_a_late_left_of_the_old_run_removes_the_new_run() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let old_run = Identity::generate();
            let new_run = Identity::generate();
            let mut state = fresh_state();
            let mut app = Inert;
            assert!(
                receive(
                    &chat(
                        &rig.mesh,
                        &who,
                        &old_run,
                        UnixSecs::now() - Duration::from_secs(2)
                    ),
                    &mut state,
                    &context
                ),
                "the frame is new to the seen set"
            );
            assert!(
                receive(
                    &chat(&rig.mesh, &who, &new_run, UnixSecs::now()),
                    &mut state,
                    &context
                ),
                "the frame is new to the seen set"
            );

            let left = Message::new_left(&rig.mesh, &who).sign(&old_run);
            assert!(!state.mark_seen(&left), "the frame is new to the seen set");
            let observed = observe(&left, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut app,
                &context,
            )
            .await;
            assert!(
                state.peers.contains(who.as_str()),
                "the late left of the old run removed the new run from the roster"
            );
            assert!(
                state.surfaced.contains(who.as_str()),
                "the late left of the old run un-surfaced the new run"
            );
            rig.endpoint.close().await;
        });
    }

    /// A live frame of a peer in the roster refreshes it at any stamp, but only a frame that
    /// proves presence changes who holds the nickname. An old frame of a killed run, re-sent by a
    /// relay, must not make the dead key the holder: the `left` of the live run would then be read
    /// as the goodbye of an older run and ignored.
    #[test]
    fn an_old_frame_of_a_killed_run_does_not_take_the_nickname() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let killed_run = Identity::generate();
            let live_run = Identity::generate();
            let mut state = fresh_state();
            let mut app = Inert;
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let hello = chat(&rig.mesh, &who, &live_run, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            let relayed = alive(
                &rig.mesh,
                &who,
                &killed_run,
                UnixSecs::now() - Duration::from_hours(2),
            );
            assert!(
                receive(&relayed, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert_eq!(
                state.peer_keys.get(who.as_str()),
                Some(&live_run.author_key()),
                "an old frame of the killed run took the nickname"
            );

            let left = Message::new_left(&rig.mesh, &who).sign(&live_run);
            assert!(!state.mark_seen(&left), "the frame is new to the seen set");
            let observed = observe(&left, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut app,
                &context,
            )
            .await;
            assert!(
                !state.peers.contains(who.as_str()),
                "the goodbye of the live run was ignored: the peer stays until the alive timeout"
            );
            rig.endpoint.close().await;
        });
    }

    /// Move the arrival of the last pre-join live frame of `who` back by `ago` on our clock, as
    /// if it had come that long ago. The tests cannot wait for the spacing.
    fn heard_ago(state: &mut EventLoopState, who: &Nickname, ago: Duration) {
        if let Some(frame) = state.clock_evidence.live_run.get_mut(who) {
            frame.at = Instant::now()
                .checked_sub(ago)
                .expect("the monotonic clock has run past the spacing since boot");
        }
    }

    /// The goodbye of `by`, through the same `observe` and `handle_presence` calls as the router.
    async fn say_goodbye(
        by: &Identity,
        who: &Nickname,
        rig: &Rig,
        state: &mut EventLoopState,
        app: &mut dyn NodeApp,
    ) {
        let context = rig.context();
        let left = Message::new_left(&rig.mesh, who).sign(by);
        assert!(!state.mark_seen(&left), "the frame is new to the seen set");
        let observed = observe(&left, state, &context);
        handle_presence(
            PresenceEvent {
                message: &left,
                subtype: PresenceSubtype::Left,
                update: &observed.update,
                surfaceable: observed.surfaceable,
            },
            state,
            app,
            &context,
        )
        .await;
    }

    /// An unseen frame of a killed run that is younger than the quiet TTL still proves presence,
    /// so the age of the frame cannot be what keeps it from the nickname. The live run holds the
    /// nickname because its frame is the newest one, whatever the age of the other frame.
    #[test]
    fn a_recent_frame_of_a_killed_run_does_not_take_the_nickname() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let killed_run = Identity::generate();
            let live_run = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let hello = chat(&rig.mesh, &who, &live_run, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            let relayed = alive(
                &rig.mesh,
                &who,
                &killed_run,
                UnixSecs::now() - Duration::from_mins(10),
            );
            assert!(
                receive(&relayed, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert_eq!(
                state.peer_keys.get(who.as_str()),
                Some(&live_run.author_key()),
                "a 10 min old frame of the killed run took the nickname"
            );

            say_goodbye(&live_run, &who, &rig, &mut state, &mut Inert).await;
            assert!(
                !state.peers.contains(who.as_str()),
                "the goodbye of the live run was ignored: the peer stays until the alive timeout"
            );
            rig.endpoint.close().await;
        });
    }

    /// After the goodbye of the live run, a frame of a killed run that is younger than the quiet
    /// TTL and older than the goodbye is no arrival: the user would read "has joined" for a peer
    /// that is gone.
    #[test]
    fn a_recent_frame_of_a_killed_run_after_a_goodbye_is_no_arrival() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let who = nick("swift-cedar");
            let killed_run = Identity::generate();
            let live_run = Identity::generate();
            let mut state = fresh_state();
            state.joined_at = UnixSecs::now() - Duration::from_hours(3);
            let hello = chat(&rig.mesh, &who, &live_run, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            say_goodbye(&live_run, &who, &rig, &mut state, &mut Inert).await;
            assert!(
                !state.peers.contains(who.as_str()),
                "the goodbye did not remove the peer"
            );
            let shown = arrival_ids(&rig, "swift-cedar").len();

            let relayed = alive(
                &rig.mesh,
                &who,
                &killed_run,
                UnixSecs::now() - Duration::from_mins(10),
            );
            assert!(
                receive(&relayed, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert_eq!(
                arrival_ids(&rig, "swift-cedar").len(),
                shown,
                "a replayed frame of a killed run made a new arrival: {:?}",
                rig.sink.lines()
            );
            assert!(
                !state.peers.contains(who.as_str()),
                "a replayed frame of a killed run put a gone peer back in the roster"
            );

            // A new run that starts after the goodbye is an arrival.
            let next_run = Identity::generate();
            let fresh = alive(
                &rig.mesh,
                &who,
                &next_run,
                UnixSecs::now() + Duration::from_secs(2),
            );
            assert!(
                receive(&fresh, &mut state, &context),
                "the frame is new to the seen set"
            );
            assert!(
                state.peers.contains(who.as_str()),
                "a new run after the goodbye is not in the roster"
            );
            rig.endpoint.close().await;
        });
    }

    /// The id of a synthetic arrival is a UUID v4 by its bits, as `MessageId` says. It stays the
    /// same for one key and one stamp, and it differs for another key or another stamp.
    #[test]
    fn the_arrival_id_is_a_uuid_v4_and_stable_per_key_and_stamp() {
        let mesh = MeshId::from("test");
        let who = nick("swift-cedar");
        let node = Identity::generate();
        let peer = Identity::generate();
        let stamp = UnixSecs::now();
        let id_of = |by: &Identity, at: UnixSecs| {
            let frame = alive(&mesh, &who, by, at);
            let NodeEvent::Presence { message, .. } = synthetic_arrival(&mesh, &node, &frame)
            else {
                panic!("the arrival is not a presence event");
            };
            message.id.to_string()
        };
        let id = id_of(&peer, stamp);
        let parsed = uuid::Uuid::parse_str(&id).expect("the id is a UUID");
        assert_eq!(
            parsed.get_version_num(),
            4,
            "the arrival id is not a UUID v4: {id}"
        );
        assert_eq!(
            parsed.get_variant(),
            uuid::Variant::RFC4122,
            "the arrival id has no RFC 4122 variant: {id}"
        );
        assert_eq!(
            id,
            id_of(&peer, stamp),
            "the id changes for one key and stamp"
        );
        assert_ne!(
            id,
            id_of(&peer, stamp + Duration::from_secs(1)),
            "another stamp gives the same id"
        );
        assert_ne!(
            id,
            id_of(&Identity::generate(), stamp),
            "another key gives the same id"
        );
    }

    /// H7. A goodbye is kept by nickname with the resolution of one second. A new run that starts
    /// in the second of the goodbye of the old run is stale from its first frame, although it is
    /// another key.
    #[test]
    fn h7_a_restart_in_the_second_of_a_goodbye_is_stale() {
        let mesh = MeshId::from("test");
        let who = nick("swift-cedar");
        let old_run = Identity::generate();
        let new_run = Identity::generate();
        let at = UnixSecs::now();
        let mut state = fresh_state();
        state.note_left(old_run.author_key());

        let mut joined = Message::new_joined(&mesh, &who);
        joined.timestamp = at;
        let joined = joined.sign(&new_run);
        let update = membership_update::compute_for(&joined, &state);
        assert!(
            !update.stale && update.joined_new,
            "the first frame of a new key in the second of the old goodbye is stale: {update:?}"
        );
    }

    /// H1, route A, in one process. A late joiner sends a meta digest with no heads. A node that
    /// holds the signed change of a dead peer answers it with that frame (the answer is
    /// `handle_state_digest`, which serves the frames of any author). The frame reaches a live
    /// node that has the dead peer in `quiet` and whose seen set forgot the frame. The live node
    /// must not report the dead peer as back.
    #[test]
    fn h1_route_a_a_late_joiners_digest_revives_a_sigkilled_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let rig = Rig::new().await;
            let context = rig.context();
            let dead = nick("swift-cedar");

            // The dead peer wrote one meta change, signed with its key.
            let writer = fresh_state();
            let seed = *writer.identity.public().as_bytes();
            let merged = writer
                .doc(Channel::Meta)
                .build_change(&serde_json::json!({ "status": "busy" }), &seed)
                .expect("a JSON object merges");
            let change = merged.expect("a non-empty merge yields a change");
            let (wire, _plain) = writer
                .doc(Channel::Meta)
                .compose_wire_body(&change, None)
                .expect("compose the wire body");
            let mut change_frame =
                Message::new_channel_event(&rig.mesh, &dead, wire, Channel::Meta);
            change_frame.timestamp = long_ago();
            let change_frame = change_frame.sign(&writer.identity);

            // The live node saw the peer alive and its change, then the peer was killed by `SIGKILL`.
            let mut live = fresh_state();
            live.joined_at = long_ago() - Duration::from_secs(10);
            let hello = chat(&rig.mesh, &dead, &writer.identity, long_ago());
            assert!(
                receive(&hello, &mut live, &context),
                "the frame is new to the seen set"
            );
            assert!(
                receive(&change_frame, &mut live, &context),
                "the frame is new to the seen set"
            );
            let silent = Instant::now()
                .checked_sub(alive_timeout() + Duration::from_secs(10))
                .expect("the monotonic clock has run past the alive timeout since boot");
            live.last_seen.insert(dead.clone(), silent);
            tick_sweep(&mut live, &rig.sink);
            assert!(live.quiet.contains(dead.as_str()), "the peer is quiet");
            let talker = Identity::generate();
            for _ in 0..SEEN_IDS_CAP {
                live.mark_seen(&alive(
                    &rig.mesh,
                    &nick("busy-room"),
                    &talker,
                    UnixSecs::now(),
                ));
            }

            // Another node holds the change of the dead peer and gets a digest from a late joiner.
            let mut holder = fresh_state();
            let _ = holder.doc_mut(Channel::Meta).ingest(&change_frame);
            assert!(
                holder
                    .doc(Channel::Meta)
                    .changes_since(&[], 10)
                    .any(|frame| frame.key() == victim_key(&writer)),
                "precondition: the holder has the change of the dead peer"
            );
            let joiner = Identity::generate();
            let digest = Message::new_channel_digest(
                &rig.mesh,
                &nick("late-joiner"),
                MessageBody::from(r#"{"heads":[]}"#),
                Channel::Meta,
            )
            .sign(&joiner);
            let answered =
                antientropy::handle_state_digest(Channel::Meta, &digest, &mut holder, &context)
                    .await;
            assert!(
                answered.broadcast + answered.unicast > 0,
                "precondition: the holder answers the digest with the frame of the dead peer"
            );

            // The answer reaches the live node.
            for frame in holder.doc(Channel::Meta).changes_since(&[], 10) {
                receive(&frame, &mut live, &context);
            }
            let lines = rig.sink.lines();
            assert!(
                !lines.iter().any(|line| line == "return swift-cedar"),
                "a late joiner digest made a live node report the dead peer as back: {lines:?}"
            );
            rig.endpoint.close().await;
        });
    }

    fn victim_key(writer: &EventLoopState) -> protocol::AuthorKey {
        writer.identity.author_key()
    }
}
