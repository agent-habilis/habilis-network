//! The **lifecycle subsystem**: everything about a *peer's*
//! presence over time — heartbeat + membership transitions + the
//! join-horizon surfacing decisions (`joined` / `left` / `peer_return`
//! / `peer_timeout`). The pure gossip router calls [`observe`] for
//! every received message, then dispatches by kind into the
//! presence/msg handlers here. The gossip layer never touches the
//! roster directly — that separation is the layer split documented in
//! the Concept Glossary (AGENTS.md).

#[cfg(test)]
mod churn_red;
#[cfg(all(test, feature = "host"))]
mod churn_wire;
pub(crate) mod heartbeat;
mod logs;
pub(crate) mod membership_update;
mod observed;
mod presence_event;
pub(crate) use logs::{log_leaving, log_ready};
pub(crate) use observed::{Observed, observe};
pub(crate) use presence_event::{
    Goodbye, PresenceEvent, ask_for_proof, end_session, handle_presence, retry_deferred_asks,
};

#[cfg(test)]
mod tests {
    use super::observed;
    use crate::gossip::event::NodeEvent;
    use crate::protocol::identity::Identity;
    use crate::protocol::{MeshId, Message};
    use crate::testing;

    #[test]
    fn a_synthetic_presence_names_the_peer_apart_from_its_signer() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = MeshId::from("test");
        let node = Identity::generate();
        let peer = Identity::generate();
        let joined = Message::new_joined(&mesh, &testing::nick("bob")).sign(&peer);
        let NodeEvent::Presence {
            message,
            peer: key,
            synthetic,
        } = observed::synthetic_arrival(&mesh, &node, &joined)
        else {
            panic!("a synthetic arrival is a presence");
        };
        assert!(synthetic, "this node minted it");
        assert_eq!(key, peer.author_key(), "the peer is the triggering signer");
        assert_eq!(message.key(), node.author_key(), "the proof is this node's");
        assert_eq!(
            message.author.as_str(),
            "bob",
            "the nickname stays the peer's"
        );
    }
}

/// A key sends one `left` per run, so a second `left` from the same key is a replay: a copy
/// that a peer still held and re-sent. It must not touch the nickname, which a new key may
/// hold by then, and a stale frame of a departed key must not refresh that nickname's liveness.
#[cfg(all(test, feature = "host"))]
mod departed_tests {
    use iroh_gossip::net::Gossip;

    use crate::daemon::handler_ctx::HandlerCtx;
    use crate::daemon::state::{DirectState, EventLoopState, Standing};
    use crate::gossip::app::{AppClass, InboundApp, NodeApp};
    use crate::gossip::event::{CountingSink, NodeEvent, NodeSink, SilentSink};
    use crate::lookup::{TransportOpts, build_peer_multihop};
    use crate::protocol::identity::Identity;
    use crate::protocol::meshes::LookupOpts;
    use crate::protocol::messages::{Authored, sole_addressee};
    use crate::protocol::{AuthorKey, MeshId, Message, MessageKind, PresenceSubtype};
    use crate::testing::{endpoint_id, fresh_state, nick};
    use crate::transport::{MeshSender, PayloadPath};
    use crate::util::tuning::QUIET_CAP;
    use std::sync::Mutex;

    use super::{PresenceEvent, handle_presence, membership_update, observe};

    use crate::protocol;
    use iroh_gossip::proto;
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
            .subscribe(proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        (endpoint, MeshSender::new(gossip_sender))
    }

    /// A key that is not in the roster can keep a retained endpoint (its `PeerInfo` came before its
    /// admission). Its goodbye must release that endpoint, or a directed send could still route to it.
    #[test]
    fn the_goodbye_of_a_stranger_releases_its_retained_endpoint() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            let stranger = Identity::generate();
            let left = Message::new_left(&mesh, &nick("stranger")).sign(&stranger);
            let mut state = fresh_state();
            let mut app = Inert;
            state.retain_refused_endpoint(
                stranger.author_key(),
                iroh::EndpointAddr::new(endpoint_id(70)),
            );
            let update = membership_update::compute_for(&left, &state);

            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &update,
                    surfaceable: true,
                },
                &mut state,
                &mut app,
                &context,
            )
            .await;

            assert!(
                !state.refused_endpoints.contains_key(&stranger.author_key()),
                "a directed send could still route to the endpoint of a key that said goodbye"
            );
            endpoint.close().await;
        });
    }

    #[test]
    fn a_replayed_left_leaves_the_nickname_to_its_new_holder() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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

            // The first run leaves. Its key is a peer of the roster.
            let first_key = first_run.author_key();
            state.names.insert(first_key, who.clone());
            state.peers.insert(first_key);
            let update = membership_update::compute_for(&left, &state);
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &update,
                    surfaceable: true,
                },
                &mut state,
                &mut app,
                &context,
            )
            .await;
            assert!(!state.peers.contains(&first_key), "the first run left");

            // A second run takes the nickname, then a copy of the first run's goodbye lands.
            let second_key = Identity::generate().author_key();
            state.names.insert(second_key, who.clone());
            state.peers.insert(second_key);
            state.surfaced.insert(second_key);
            let replay = membership_update::compute_for(&left, &state);
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &replay,
                    surfaceable: true,
                },
                &mut state,
                &mut app,
                &context,
            )
            .await;
            assert!(
                state.peers.contains(&second_key),
                "a replayed goodbye of the first run removed the second run"
            );
            assert!(
                state.surfaced.contains(&second_key),
                "a replayed goodbye of the first run un-surfaced the second run"
            );
            endpoint.close().await;
        });
    }

    /// The goodbye of a peer that we showed is shown as a departure: the surfaced mark is read
    /// before the key is forgotten, or the departure is never announced.
    #[test]
    fn a_surfaced_peer_that_says_goodbye_is_shown_leaving() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = CountingSink::new();
            let context = HandlerCtx {
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
            let leaver = Identity::generate();
            let mut state = fresh_state();
            state.names.insert(leaver.author_key(), who.clone());
            state.peers.insert(leaver.author_key());
            state.surfaced.insert(leaver.author_key());
            let left = Message::new_left(&mesh, &who).sign(&leaver);
            let update = membership_update::compute_for(&left, &state);
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &update,
                    surfaceable: true,
                },
                &mut state,
                &mut Inert,
                &context,
            )
            .await;
            assert_eq!(
                sink.count(),
                1,
                "the departure of a shown peer is not shown"
            );
            endpoint.close().await;
        });
    }

    /// Any key can sign a goodbye. A flood of goodbyes from keys that were never peers must not
    /// push the tombstone of a real leaver out of the set, or a copy of its frames would bring it
    /// back as an arrival. The goodbye of a stranger is still a replay the second time.
    #[test]
    fn a_flood_of_unknown_goodbyes_keeps_the_tombstone_of_a_departed_peer() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            let leaver = Identity::generate();
            let mut state = fresh_state();
            state.names.insert(leaver.author_key(), who.clone());
            state.peers.insert(leaver.author_key());
            let mut stranger = Identity::generate();
            for round in 0..=QUIET_CAP {
                let (key, name) = if round == 0 {
                    (&leaver, who.clone())
                } else {
                    stranger = Identity::generate();
                    (&stranger, nick("passer-by"))
                };
                let left = Message::new_left(&mesh, &name).sign(key);
                let update = membership_update::compute_for(&left, &state);
                handle_presence(
                    PresenceEvent {
                        message: &left,
                        subtype: PresenceSubtype::Left,
                        update: &update,
                        surfaceable: true,
                    },
                    &mut state,
                    &mut Inert,
                    &context,
                )
                .await;
            }
            assert!(
                state.key_said_goodbye(leaver.author_key()),
                "a flood of unknown goodbyes evicted the tombstone of a departed peer"
            );
            assert!(
                state.key_said_goodbye(stranger.author_key()),
                "the latest unknown goodbye is not a replay the second time"
            );
            endpoint.close().await;
        });
    }

    /// Records the key and the nickname of each departure that the engine reports to the app.
    struct Recorder(Vec<(AuthorKey, protocol::Nickname)>);

    #[async_trait::async_trait]
    impl NodeApp for Recorder {
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
            key: &AuthorKey,
            nickname: &protocol::Nickname,
            _state: &mut EventLoopState,
            _ctx: &HandlerCtx<'_>,
        ) {
            self.0.push((*key, nickname.clone()));
        }
    }

    /// A goodbye removes the roster entry of its key, which the roster knows under the nickname
    /// it recorded for that key. The app hears of that peer, not of whatever nickname the frame
    /// names: a `Left` can carry any nickname.
    #[test]
    fn the_app_hears_the_recorded_nickname_of_the_key_that_left() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            let run = Identity::generate();
            let recorded = nick("swift-cedar");
            let mut state = fresh_state();
            state.names.insert(run.author_key(), recorded.clone());
            state.peers.insert(run.author_key());

            // The frame names another nickname than the one the roster holds for the key.
            let left = Message::new_left(&mesh, &nick("lost-heron")).sign(&run);
            let update = membership_update::compute_for(&left, &state);
            let mut app = Recorder(Vec::new());
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &update,
                    surfaceable: true,
                },
                &mut state,
                &mut app,
                &context,
            )
            .await;

            assert_eq!(
                app.0,
                vec![(run.author_key(), recorded)],
                "the app was told of a nickname that the departed key did not hold"
            );
            endpoint.close().await;
        });
    }

    /// One departure that the engine surfaces to the operator: the nickname of the `left` frame,
    /// the key of the peer that departed, and whether this node minted the frame.
    #[derive(Debug, PartialEq, Eq)]
    struct Departure {
        nickname: protocol::Nickname,
        peer: AuthorKey,
        synthetic: bool,
    }

    /// Keeps each departure that the engine surfaces to the operator.
    #[derive(Default)]
    struct DepartureSink(Mutex<Vec<Departure>>);

    impl NodeSink for DepartureSink {
        fn emit(&self, event: NodeEvent) {
            if let NodeEvent::Presence {
                message,
                peer,
                synthetic,
            } = event
                && matches!(
                    message.kind,
                    MessageKind::Presence {
                        subtype: PresenceSubtype::Left
                    }
                )
            {
                self.0.lock().expect("the sink lock").push(Departure {
                    nickname: message.author.clone(),
                    peer,
                    synthetic,
                });
            }
        }
    }

    /// The app reads the whole roster, so it holds state for a peer that is not shown yet. The
    /// goodbye of such a peer, stamped after our join, reaches the hook, and shows no `left`.
    #[test]
    fn the_app_hears_the_goodbye_of_a_peer_that_was_never_shown() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = DepartureSink::default();
            let context = HandlerCtx {
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
            let run = Identity::generate();
            let hidden = nick("swift-cedar");
            let mut state = fresh_state();
            state.names.insert(run.author_key(), hidden.clone());
            state.peers.insert(run.author_key());

            let left = Message::new_left(&mesh, &hidden).sign(&run);
            let observed = observe(&left, &mut state, &context);
            let mut app = Recorder(Vec::new());
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

            assert_eq!(
                app.0,
                vec![(run.author_key(), hidden)],
                "the app never heard that a peer it read from the roster left"
            );
            assert!(
                sink.0.lock().expect("the sink lock").is_empty(),
                "a departure was shown for a peer whose arrival was not shown"
            );
            endpoint.close().await;
        });
    }

    /// The whole path of a goodbye, `observe` first. A `Left` can name any nickname, so neither
    /// `observe` nor the departure may take the nickname of the key from the frame: the app and the
    /// operator hear of the peer that the roster removed.
    #[test]
    fn a_goodbye_that_names_another_nickname_ends_the_key_under_its_recorded_nickname() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = DepartureSink::default();
            let context = HandlerCtx {
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
            let run = Identity::generate();
            let recorded = nick("swift-cedar");
            let mut state = fresh_state();
            state.names.insert(run.author_key(), recorded.clone());
            state.peers.insert(run.author_key());
            state.surfaced.insert(run.author_key());

            let left = Message::new_left(&mesh, &nick("lost-heron")).sign(&run);
            let observed = observe(&left, &mut state, &context);
            let mut app = Recorder(Vec::new());
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

            assert_eq!(
                app.0,
                vec![(run.author_key(), recorded.clone())],
                "the app was told of a nickname that the departed key did not hold"
            );
            let expected = Departure {
                nickname: recorded,
                peer: run.author_key(),
                synthetic: true,
            };
            assert_eq!(
                *sink.0.lock().expect("the sink lock"),
                vec![expected],
                "the operator was told of a nickname that the departed key did not hold, or not as a departure this node minted"
            );
            endpoint.close().await;
        });
    }

    /// The app tracks peers by key, so it hears of every key that leaves, also when another key
    /// still holds the nickname of the departed key: the twin that stays does not make the state
    /// of the leaver valid.
    #[test]
    fn the_app_hears_of_each_key_that_leaves_also_when_another_key_holds_its_nickname() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            let first_run = Identity::generate();
            let second_key = Identity::generate().author_key();
            let shared = nick("swift-cedar");
            let mut state = fresh_state();
            for key in [first_run.author_key(), second_key] {
                state.names.insert(key, shared.clone());
                state.peers.insert(key);
            }

            let left = Message::new_left(&mesh, &nick("lost-heron")).sign(&first_run);
            let update = membership_update::compute_for(&left, &state);
            let mut app = Recorder(Vec::new());
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &update,
                    surfaceable: true,
                },
                &mut state,
                &mut app,
                &context,
            )
            .await;

            assert_eq!(
                app.0,
                vec![(first_run.author_key(), shared)],
                "the app must hear once of the key that left, though the second key holds its nickname"
            );
            endpoint.close().await;
        });
    }

    /// A key that outlived the quiet TTL keeps its name and its dial hint, because it can return
    /// without a `PeerInfo`. It is still a peer of the roster, so its goodbye ends it like the
    /// goodbye of a quiet peer: the hint, the dial address and the name go, and a directed send
    /// no longer reaches its node.
    #[test]
    fn the_goodbye_of_a_key_that_outlived_the_quiet_ttl_removes_its_dial_hint() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            let lapsed = Identity::generate();
            let recorded = nick("swift-cedar");
            let address = iroh::EndpointAddr::new(endpoint_id(4));
            let mut state = fresh_state();
            state.names.insert(lapsed.author_key(), recorded.clone());
            state
                .clock_evidence
                .lapsed_quiet
                .insert(lapsed.author_key());
            state.unicast_pool.note_addr(&address);
            state.bind_peer_endpoint(lapsed.author_key(), recorded.clone(), address);

            let left = Message::new_left(&mesh, &recorded).sign(&lapsed);
            let observed = observe(&left, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut Recorder(Vec::new()),
                &context,
            )
            .await;

            assert!(
                !state.peer_endpoints.contains_key(&recorded),
                "the dial hint of a departed key survived its goodbye"
            );
            assert!(
                !state.unicast_pool.has_addr(endpoint_id(4)),
                "the dial address of a departed key survived its goodbye"
            );
            assert!(
                !state.names.contains_key(&lapsed.author_key())
                    && !state
                        .clock_evidence
                        .lapsed_quiet
                        .contains(&lapsed.author_key()),
                "a departed key stayed in the roster's memory"
            );
            endpoint.close().await;
        });
    }

    /// A `PeerInfo` can bind a dial hint before the roster admits its key. If that key says
    /// goodbye first, it is no peer, and its hint must go with it: the hint stays routable
    /// otherwise.
    #[test]
    fn the_goodbye_of_a_key_outside_the_roster_removes_the_dial_hints_it_owns() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            let stranger = Identity::generate();
            let other = Identity::generate();
            let (strangers_endpoint, others_endpoint) = (endpoint_id(44), endpoint_id(45));
            let mut state = fresh_state();
            state.bind_peer_endpoint(
                stranger.author_key(),
                nick("swift-cedar"),
                iroh::EndpointAddr::new(strangers_endpoint),
            );
            state.bind_peer_endpoint(
                other.author_key(),
                nick("calm-otter"),
                iroh::EndpointAddr::new(others_endpoint),
            );
            assert!(
                !state.peers.contains(&stranger.author_key()),
                "the key is outside the roster"
            );

            let left = Message::new_left(&mesh, &nick("swift-cedar")).sign(&stranger);
            let observed = observe(&left, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut Recorder(Vec::new()),
                &context,
            )
            .await;

            assert!(
                !state.endpoint_is_bound(strangers_endpoint),
                "the dial hint of the stranger survived its goodbye"
            );
            assert!(
                state.endpoint_is_bound(others_endpoint),
                "the goodbye of the stranger removed the hint of another key"
            );
            endpoint.close().await;
        });
    }

    /// A directed frame to one of two live keys that use a nickname waits in the buffer. The
    /// goodbye of the other key is a flush edge, so the frame goes at once, not at the next
    /// unrelated event, and the goodbye does not drop the frame of the key that stays.
    #[test]
    fn the_goodbye_of_the_other_key_of_a_nickname_flushes_the_frames_that_waited() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            let (first, second) = (Identity::generate(), Identity::generate());
            let (twin, survivor_endpoint) = (nick("twin"), endpoint_id(46));
            let mut state = fresh_state();
            state.standing.insert(Standing::Meshed);
            for run in [&first, &second] {
                state.names.insert(run.author_key(), twin.clone());
                state.peers.insert(run.author_key());
            }
            state.bind_peer_endpoint(
                first.author_key(),
                twin.clone(),
                iroh::EndpointAddr::new(survivor_endpoint),
            );
            state.direct.insert(survivor_endpoint, DirectState::Direct);
            assert!(
                state.nickname_is_ambiguous(&twin),
                "two live keys use the nickname"
            );
            let frame = Message::new_pong(
                &mesh,
                &us,
                first.author_key(),
                &protocol::MessageId::random(),
            )
            .sign(&identity);
            let bytes = frame.serialize().expect("serialize");
            assert!(
                state.pending_outbound.push((frame, bytes)),
                "the frame waits in the buffer"
            );

            let left = Message::new_left(&mesh, &nick("twin")).sign(&second);
            let observed = observe(&left, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut Recorder(Vec::new()),
                &context,
            )
            .await;

            assert!(
                state.pending_outbound.is_empty(),
                "the frame still waits after the goodbye of the other key"
            );
            endpoint.close().await;
        });
    }

    /// The goodbye of a key ends the wait of the directed frames that are buffered for it: nothing
    /// can deliver them, and the buffer would requeue them until it is full. The frames for the
    /// other key of the same nickname, and the broadcasts, stay.
    #[test]
    fn a_goodbye_drops_the_buffered_frames_addressed_to_the_key_that_left() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            let (first, second) = (Identity::generate(), Identity::generate());
            let twin = nick("twin");
            let mut state = fresh_state();
            state.standing.remove(&Standing::Meshed);
            for run in [&first, &second] {
                state.names.insert(run.author_key(), twin.clone());
                state.peers.insert(run.author_key());
            }
            for to in [first.author_key(), second.author_key()] {
                let frame = Message::new_pong(&mesh, &us, to, &protocol::MessageId::random())
                    .sign(&identity);
                let bytes = frame.serialize().expect("serialize");
                assert!(state.pending_outbound.push((frame, bytes)), "room");
            }

            let left = Message::new_left(&mesh, &twin).sign(&second);
            let observed = observe(&left, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut Recorder(Vec::new()),
                &context,
            )
            .await;

            let waiting = state.pending_outbound.take();
            let recipients: Vec<AuthorKey> = waiting
                .iter()
                .filter_map(|(frame, _)| sole_addressee(&frame.kind).copied())
                .collect();
            assert_eq!(
                recipients,
                [first.author_key()],
                "the buffer must keep only the frame of the key that stayed"
            );
            endpoint.close().await;
        });
    }

    /// A key can prove an endpoint and own no dial hint: its nickname was held by another key when
    /// its `PeerInfo` came. Its goodbye still ends the pooled connection and the dial cooldown of
    /// the endpoint that it proved.
    #[test]
    fn the_goodbye_of_a_key_that_proved_an_endpoint_and_owns_no_hint_ends_its_pool_state() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            let rival = Identity::generate();
            let proved = endpoint_id(43);
            let mut state = fresh_state();
            state.peers.insert(rival.author_key());
            state.names.insert(rival.author_key(), nick("swift-cedar"));
            state.proven_endpoints.trust(rival.author_key(), proved);
            state.unicast_pool.note_dial_failure(proved).await;
            assert!(
                !state.endpoint_is_bound(proved),
                "no nickname binds the endpoint, so the key owns no hint"
            );

            let left = Message::new_left(&mesh, &nick("swift-cedar")).sign(&rival);
            let observed = observe(&left, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut Recorder(Vec::new()),
                &context,
            )
            .await;

            assert!(
                !state.unicast_pool.is_cooling(proved).await,
                "the cooldown of the proved endpoint survived the goodbye"
            );
            endpoint.close().await;
        });
    }

    /// A key that renamed owns a dial hint under each nickname it used, and each hint names an
    /// endpoint. Its goodbye ends the pooled connection and the dial cooldown of every one of
    /// them, not only of the endpoint of its current nickname.
    #[test]
    fn the_goodbye_of_a_key_that_renamed_ends_the_pool_state_of_each_endpoint_it_used() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            let renamed = Identity::generate();
            let (old_endpoint, new_endpoint) = (endpoint_id(41), endpoint_id(42));
            let mut state = fresh_state();
            state.peers.insert(renamed.author_key());
            state
                .names
                .insert(renamed.author_key(), nick("swift-cedar"));
            state.bind_peer_endpoint(
                renamed.author_key(),
                nick("swift-cedar"),
                iroh::EndpointAddr::new(old_endpoint),
            );
            state.names.insert(renamed.author_key(), nick("calm-otter"));
            state.bind_peer_endpoint(
                renamed.author_key(),
                nick("calm-otter"),
                iroh::EndpointAddr::new(new_endpoint),
            );
            for used in [old_endpoint, new_endpoint] {
                state.unicast_pool.note_dial_failure(used).await;
            }

            let left = Message::new_left(&mesh, &nick("calm-otter")).sign(&renamed);
            let observed = observe(&left, &mut state, &context);
            handle_presence(
                PresenceEvent {
                    message: &left,
                    subtype: PresenceSubtype::Left,
                    update: &observed.update,
                    surfaceable: observed.surfaceable,
                },
                &mut state,
                &mut Recorder(Vec::new()),
                &context,
            )
            .await;

            assert!(
                !state.unicast_pool.is_cooling(new_endpoint).await,
                "the cooldown of the current endpoint survived the goodbye"
            );
            assert!(
                !state.unicast_pool.is_cooling(old_endpoint).await,
                "the cooldown of an endpoint of a previous nickname survived the goodbye"
            );
            endpoint.close().await;
        });
    }

    /// A departed key's `joined` frames serve nobody once it is gone, and the log never evicts a
    /// small author, so without this they stay resend subjects for the life of the node. Its chat
    /// stays: a node that missed it can still backfill it.
    #[test]
    fn a_departed_keys_presence_leaves_the_log() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
                protocol::AppFrameParams::new(
                    protocol::AppTag::try_new("app_msg").expect("a valid app tag"),
                    None,
                    None,
                    protocol::MessageBody::from("kept"),
                ),
            )
            .sign(&departed);
            let mut state = fresh_state();
            state.names.insert(departed.author_key(), who.clone());
            state.peers.insert(departed.author_key());
            state.message_log.push(joined.clone());
            state.message_log.push(chat.clone());

            let left = Message::new_left(&mesh, &who).sign(&departed);
            let update = membership_update::compute_for(&left, &state);
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
                &context,
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
        });
    }

    /// A copy of a goodbye reaches `observe` before `handle_presence`. If a later holder of the
    /// nickname has gone quiet, the copy must not read as that holder's return: it is a frame of a
    /// key that already said goodbye, and says nothing about whoever holds the nickname now.
    #[test]
    fn a_replayed_left_does_not_return_a_quiet_holder() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            state.note_left(first_run.author_key());
            // A second run took the nickname and went quiet.
            let second_key = Identity::generate().author_key();
            state.names.insert(second_key, who.clone());
            state.quiet.insert(second_key);

            let replay = Message::new_left(&mesh, &who).sign(&first_run);
            let observed = observe(&replay, &mut state, &context);
            assert!(observed.update.stale, "a copy of a goodbye is not stale");
            assert!(
                !state.peers.contains(&second_key),
                "a replayed goodbye of the first run returned the quiet second run"
            );
            assert!(
                state.quiet.contains(&second_key),
                "a replayed goodbye of the first run took the second run out of quiet"
            );
            assert!(
                !state.last_seen.contains_key(&second_key)
                    && !state.last_seen.contains_key(&first_run.author_key()),
                "a replayed goodbye refreshed the liveness of a key"
            );
            endpoint.close().await;
        });
    }

    #[test]
    fn a_stale_frame_of_a_departed_key_does_not_refresh_liveness() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let (endpoint, sender) = endpoint_and_sender().await;
            let identity = Identity::generate();
            let our_pubkey = identity.author_key();
            let mesh = MeshId::from("test");
            let us = nick("us");
            let sink = SilentSink;
            let context = HandlerCtx {
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
            state.note_left(departed.author_key());

            let replay = Message::new_joined(&mesh, &who).sign(&departed);
            let observed = observe(&replay, &mut state, &context);
            assert!(
                observed.update.stale,
                "a stale frame of a departed key is stale"
            );
            assert!(
                !state.last_seen.contains_key(&departed.author_key()),
                "a stale frame refreshed the liveness of the departed key"
            );
            endpoint.close().await;
        });
    }
}
