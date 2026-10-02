//! Two real habilis-network nodes, one loopback mesh, one rollback match.
//!
//! Everything above this is exercised against fakes; this is the only test
//! that puts the whole stack together — real mesh formation, real
//! `send_app` unicast, real `on_app_frame` — and shows a match actually
//! being played over it.
//!
//! `LookupOpts::loopback()` makes zero external network calls (no relay, no
//! mDNS, no DHT; peers find each other on a seed-derived loopback port
//! ladder), so this runs offline and in CI.

#![cfg(feature = "host")]

use std::time::Duration;

use habilis_network::embed::SilentSink;
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{LookupOpts, Nickname};
use habilis_network::runtime::{Node, SetupKind, SetupParams, derive_topic_mesh_with, setup_mesh};
use serde::{Deserialize, Serialize};

use habilis_network_netplay::{
    Config, Event, Lobby, MeshTransport, P2PSession, Request, RollbackDriver, RollbackError,
    SessionState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
struct Input(i32);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct State {
    value: i64,
    frame: i32,
}

#[derive(Debug)]
struct Game;

impl Config for Game {
    type Input = Input;
    type State = State;
    // The peer's signed public key. Never the nickname — the protocol
    // treats those as cosmetic and non-unique.
    type Address = String;
}

/// One player: a node, its transport, and the state its requests drive.
struct Player {
    node: Node<RollbackDriver<Game>>,
    transport: Option<MeshTransport<Game>>,
    lobby: Option<Lobby>,
    session: Option<P2PSession<Game, MeshTransport<Game>>>,
    state: State,
    nick: String,
    desynced: bool,
}

async fn spawn(topic: &str, nick: &str) -> Player {
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    let author = Nickname::new(nick).expect("valid nickname");
    let kind = SetupKind::Topic {
        mesh,
        topic_string: topic.to_owned(),
    };
    let config = setup_mesh(
        kind,
        SetupParams {
            author,
            max_peers: 16,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts::default(),
            runtime_base: None,
            state_file: None,
            sink: std::sync::Arc::new(SilentSink),
            multihop: false,
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");

    let (driver, pending) = RollbackDriver::<Game>::new();
    let node: Node<RollbackDriver<Game>> = Node::spawn(config, driver, None, false);
    let transport = pending.connect(node.sender());

    Player {
        node,
        transport: Some(transport),
        lobby: None,
        session: None,
        state: State::default(),
        nick: nick.to_owned(),
        desynced: false,
    }
}

impl Player {
    fn checksum(state: &State) -> u128 {
        u128::from(state.value.cast_unsigned()) ^ (u128::from(state.frame.cast_unsigned()) << 64)
    }

    fn handle(&mut self, request: Request<Game>) {
        match request {
            Request::SaveState { cell, frame } => {
                cell.save(frame, self.state.clone(), Some(Self::checksum(&self.state)));
            }
            Request::LoadState { cell } => {
                self.state = cell.load().expect("the session only loads frames it saved");
            }
            Request::AdvanceFrame { inputs } => {
                let sum: i64 = inputs.iter().map(|(input, _)| i64::from(input.0)).sum();
                self.state.value += sum;
                self.state.frame += 1;
            }
        }
    }

    /// Announce ourselves and fold in whatever has arrived.
    ///
    /// `tick` throttles the announcement to the cadence a real consumer
    /// uses (`examples/light-cycles` sends one every 10 frames). Announcing
    /// on *every* pass is not merely wasteful: at one per 10ms each one
    /// fans out a `send_app` per roster member through the node's session
    /// channel, and the event loop spends its time draining that instead of
    /// running the maintenance arms underneath it — including the reclaim
    /// tick that re-grafts a dropped rendezvous link. The mesh then forms
    /// late or not at all, which is a flake in the test rig rather than
    /// anything a consumer would hit.
    fn pump_lobby(&mut self, tick: usize) {
        let Some(transport) = &self.transport else {
            return;
        };
        // The lobby cannot exist until the event loop has told us who we are.
        if self.lobby.is_none() {
            let Some(pubkey) = transport.local_pubkey() else {
                return;
            };
            self.lobby = Some(Lobby::new(pubkey, self.nick.clone()));
        }
        let lobby = self.lobby.as_mut().expect("just ensured");
        for (pubkey, raw) in transport.drain_lobby() {
            lobby.on_message(&pubkey, &raw, tick as u64);
        }
        if tick.is_multiple_of(10) {
            transport.broadcast_lobby(&lobby.presence());
        }
    }

    /// Once the lobby has agreed a match, build the session.
    fn start_session_if_agreed(&mut self) {
        if self.session.is_some() {
            return;
        }
        let (Some(lobby), Some(_)) = (&self.lobby, &self.transport) else {
            return;
        };
        let Some(agreed) = lobby.started() else {
            return;
        };
        let players = agreed.players.clone();
        let local_handle = agreed.local_handle;
        let session_id = agreed.session_id;
        let transport = self.transport.take().expect("checked above");
        self.session = Some(
            P2PSession::new(
                players,
                local_handle,
                transport,
                8,
                2,
                // Scoped to this match, so a straggler from a previous one
                // cannot be mistaken for live input.
                u32::try_from(session_id & 0xFFFF_FFFF).unwrap_or(1),
            )
            .expect("the handle came from our own player list"),
        );
    }

    /// One frame of the real loop.
    fn tick(&mut self, tick: usize) {
        let Some(session) = &mut self.session else {
            return;
        };
        session.poll_remote_peers();
        for event in session.drain_events() {
            if matches!(event, Event::Desync { .. }) {
                self.desynced = true;
            }
        }
        if session.state() != SessionState::Running {
            return;
        }
        let value = i32::try_from(tick % 5).expect("small");
        if session.add_local_input(Input(value)).is_err() {
            return;
        }
        let requests = match session.advance_frame() {
            Ok(requests) => requests,
            // Normal: the peer is behind, or we are yielding pace.
            Err(RollbackError::PredictionLimit) => return,
            Err(other) => panic!("unexpected session error: {other}"),
        };
        for request in requests {
            self.handle(request);
        }
        self.session
            .as_mut()
            .expect("the session cannot vanish mid-tick")
            .publish_checksum();
    }
}

/// Polls `condition` until true or `timeout` elapses, pumping both players.
async fn drive(
    players: &mut [Player],
    timeout: Duration,
    mut condition: impl FnMut(&[Player]) -> bool,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut tick = 0;
    loop {
        for player in players.iter_mut() {
            player.pump_lobby(tick);
            player.start_session_if_agreed();
            player.tick(tick);
        }
        tick += 1;
        if condition(players) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_peers_play_a_match_over_a_loopback_mesh() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let topic = format!("habilis-network-netplay-loopback-{}", std::process::id());
    let mut players = vec![spawn(&topic, "alice").await, spawn(&topic, "bob").await];

    // 1. The mesh forms and both peers see each other in the lobby.
    let met = drive(&mut players, Duration::from_secs(30), |players| {
        players.iter().all(|player| {
            player
                .lobby
                .as_ref()
                .is_some_and(|lobby| lobby.present().len() >= 2)
        })
    })
    .await;
    assert!(met, "the two peers never found each other in the lobby");

    // 2. One of them starts the match. The other adopts it off the wire.
    let start = players[0]
        .lobby
        .as_mut()
        .expect("alice has a lobby")
        .propose()
        .expect("two distinct players are present");
    players[0]
        .transport
        .as_ref()
        .expect("alice still holds her transport")
        .broadcast_lobby(&start);

    // 3. Both build a session and complete the rollback handshake.
    let running = drive(&mut players, Duration::from_secs(30), |players| {
        players.iter().all(|player| {
            player
                .session
                .as_ref()
                .is_some_and(|session| session.state() == SessionState::Running)
        })
    })
    .await;
    assert!(running, "the rollback handshake never completed");

    // 4. And they actually play.
    let played = drive(&mut players, Duration::from_secs(30), |players| {
        players.iter().all(|player| player.state.frame >= 30)
    })
    .await;
    assert!(
        played,
        "frames did not advance: {:?}",
        players
            .iter()
            .map(|player| player.state.frame)
            .collect::<Vec<_>>()
    );

    // The claim under test: both peers, having exchanged only inputs,
    // independently agree on the state — and say so via checksums.
    assert!(
        players.iter().all(|player| !player.desynced),
        "a peer reported a checksum mismatch"
    );

    let frames: Vec<i32> = players.iter().map(|player| player.state.frame).collect();
    let lowest = *frames.iter().min().expect("two players");
    let highest = *frames.iter().max().expect("two players");
    assert!(
        highest - lowest <= 16,
        "peers drifted apart instead of pacing together: {frames:?}"
    );

    // Leave, rather than letting the runtime drop these mid-flight.
    // `iroh-gossip`'s actor loop `expect`s on its `JoinSet`, so a task
    // cancelled by runtime shutdown panics ("connection task panicked")
    // and fails an otherwise passing test.
    for player in players {
        player.node.leave().await.expect("leave the mesh cleanly");
    }
}
