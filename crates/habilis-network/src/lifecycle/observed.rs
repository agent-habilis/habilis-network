use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::EventLoopState;
use crate::gossip::event::NodeEvent;
use crate::protocol::identity::Identity;
use crate::protocol::messages::Verified;
use crate::protocol::{
    AuthorKey, MeshId, Message, MessageId, MessageKind, PresenceSubtype, UnixSecs,
};
use uuid::Uuid;

use super::membership_update;

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
    let update = membership_update::compute_for(message, state);
    // Implicit heartbeat: a frame that proves presence updates last_seen. Not a stale one: a copy of
    // a departed key's frame says nothing about whoever holds the nickname now. Not a replayed
    // frame of a durable kind either: it would keep a dead peer from its eviction. A peer that is
    // new to us gets its first entry from any frame, or the sweep could never evict it.
    if !update.stale {
        let proves = membership_update::proves_presence(&message.kind, message.timestamp);
        match state.last_seen.get_mut(message.author.as_str()) {
            Some(seen) if proves => *seen = Instant::now(),
            Some(_) => {}
            None => {
                state
                    .last_seen
                    .insert(message.author.clone(), Instant::now());
            }
        }
        // The holder of a nickname is the last key that proved it was alive under that name.
        if proves {
            state
                .peer_keys
                .insert(message.author.clone(), message.key());
        }
    }
    membership_update::apply(&update, &message.author, state);

    // Join horizon: the node still relays/logs everything (anti-entropy
    // keeps the mesh's set uniform), but a message stamped before we
    // joined is never *surfaced* to the operator/agent. Computed here
    // (not just before the inbound push) because the arrival-surfacing
    // decisions below need it too.
    let surfaceable = message.timestamp >= state.joined_at;

    if update.returned && surfaceable {
        state.surfaced.insert(message.author.clone());
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
    if surfaceable
        && !update.returned
        && !update.stale
        && membership_update::proves_presence(&message.kind, message.timestamp)
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
        context
            .sink
            .emit(synthetic_arrival(context.mesh, context.identity, message));
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
/// stamp follow them.
fn arrival_id(key: AuthorKey, stamp: UnixSecs) -> MessageId {
    let mut bytes = [0u8; 16];
    bytes[..12].copy_from_slice(&key.as_bytes()[..12]);
    let seconds = u32::try_from(stamp.as_secs().rem_euclid(i64::from(u32::MAX) + 1))
        .expect("a remainder below 2^32 fits a u32");
    bytes[12..].copy_from_slice(&seconds.to_be_bytes());
    MessageId::try_new(&Uuid::from_bytes(bytes).to_string())
        .expect("a formatted UUID is a valid message id")
}

/// Tests for issue 75 (H1, H4, H7). Each test states the property that a correct engine has. They
/// were red on f7cd9bbc for the reason in their names (see the PR).
#[cfg(all(test, feature = "host"))]
mod churn_red {
    use std::sync::Mutex;
    use std::time::Duration;

    use iroh_gossip::net::Gossip;
    use iroh_gossip::proto;

    use super::{observe, synthetic_arrival};
    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::EventLoopState;
    use crate::gossip::antientropy::handle_state_digest;
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::broadcast_msg;
    use crate::gossip::event::{NodeEvent, NodeSink};
    use crate::lifecycle::heartbeat::{tick_alive, tick_sweep};
    use crate::lifecycle::{PresenceEvent, handle_presence, membership_update};
    use crate::lookup::{TransportOpts, build_peer_multihop};
    use crate::protocol;
    use crate::protocol::identity::Identity;
    use crate::protocol::meshes::LookupOpts;
    use crate::protocol::messages::Authored;
    use crate::protocol::{
        Channel, MeshId, Message, MessageBody, Nickname, PresenceSubtype, UnixSecs, Verified,
    };
    use crate::testing::{FrameClass, WireCounter, endpoint_id, fresh_state, nick};
    use crate::transport::{MeshSender, PayloadPath};
    use crate::util::clock::Instant;
    use crate::util::tuning::{SEEN_IDS_CAP, alive_timeout};

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
                assert!(!state.mark_seen(&joined));
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
            let arrivals = rig
                .sink
                .lines()
                .iter()
                .filter(|line| line.starts_with("presence swift-cedar"))
                .count();
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
                broadcast_msg(&rig.sender, &data_frame(&rig, 512)).await;
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
            let arrivals = lines
                .iter()
                .filter(|line| line.starts_with("presence swift-cedar"))
                .count();
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
            let hello = chat(&rig.mesh, &who, &peer, UnixSecs::now());
            assert!(
                receive(&hello, &mut state, &context),
                "the frame is new to the seen set"
            );
            let silent = Instant::now()
                .checked_sub(Duration::from_secs(60))
                .expect("the monotonic clock has run past 60 s since boot");
            state.last_seen.insert(who.clone(), silent);
            let info = peer_info(&rig.mesh, &who, &peer, UnixSecs::now());
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
            assert!(
                rig.sink
                    .lines()
                    .iter()
                    .any(|line| line == "return swift-cedar"),
                "a fresh meta change did not return the quiet peer: {:?}",
                rig.sink.lines()
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
            assert!(
                rig.sink.lines().is_empty() && !state.peers.contains(who.as_str()),
                "an old durable frame made an arrival: {:?}",
                rig.sink.lines()
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
    #[ignore = "open: a live kind proves presence at any stamp. The rule: a live kind proves presence only if stamped within QUIET_TTL. Three pinned tests stamp a live frame with 0 and would need UnixSecs::now()"]
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
                assert!(
                    rig.sink.lines().is_empty() && !state.peers.contains(who.as_str()),
                    "an old {name} frame made an arrival: {:?}",
                    rig.sink.lines()
                );
            }
            rig.endpoint.close().await;
        });
    }

    /// The ids of the arrivals this node surfaced for `who`, in order.
    fn arrival_ids(rig: &Rig, who: &str) -> Vec<String> {
        rig.sink
            .lines()
            .iter()
            .filter(|line| line.starts_with(&format!("presence {who} ")))
            .filter_map(|line| line.split("id=").nth(1).map(str::to_owned))
            .collect()
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
                    &chat(&rig.mesh, &who, &old_run, UnixSecs::now()),
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
            assert!(!state.mark_seen(&left));
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

    /// H7. A goodbye is kept by nickname with the resolution of one second. A new run that starts
    /// in the second of the goodbye of the old run is stale from its first frame, although it is
    /// another key.
    #[test]
    fn h7_a_restart_in_the_second_of_a_goodbye_is_stale() {
        let mesh = MeshId::from("test");
        let who = nick("swift-cedar");
        let old_run = Identity::generate();
        let new_run = Identity::generate();
        let at = UnixSecs::from(1_000);
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
            let change = writer
                .doc(Channel::Meta)
                .build_change(&serde_json::json!({ "status": "busy" }), &seed)
                .expect("a JSON object merges")
                .expect("a non-empty merge yields a change");
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
            let answered = handle_state_digest(Channel::Meta, &digest, &mut holder, &context).await;
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
