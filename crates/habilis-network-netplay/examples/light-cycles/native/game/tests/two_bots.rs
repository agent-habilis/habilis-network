//! The highest-value test in this example: two independent bots on a
//! loopback-only mesh (no internet, no relay — `LookupOpts::loopback()`
//! makes zero external network calls, so this runs offline and in CI)
//! play a whole match against each other and independently derive the
//! same outcome, having exchanged nothing but per-tick inputs.
//!
//! That is the central claim of the example — GGPO-style rollback over a
//! habilis-network mesh, no authoritative peer, no state on the wire — checked
//! end-to-end rather than just in the simulation (`sim.rs`'s own tests
//! cover that half, and `sync_test.rs` covers determinism).

use std::time::Duration;

use habilis_network::embed::SilentSink;
use habilis_network::net::TransportOpts;
use habilis_network::protocol::{LookupOpts, Nickname};
use habilis_network::runtime::{Node, SetupKind, SetupParams, derive_topic_mesh_with, setup_mesh};
use habilis_network_netplay::RollbackDriver;

use light_cycles_native::app::{Game, LightCycles};
use light_cycles_native::grid::{Dir, TICK_MS};
use light_cycles_native::sim::{Outcome, World};

struct Bot {
    node: Node<RollbackDriver<LightCycles>>,
    game: Game,
}

async fn spawn_bot(topic: &str, nick: &str) -> Bot {
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::loopback()).expect("derive a loopback mesh");
    let author = Nickname::new(nick).expect("valid nickname");
    let kind = SetupKind::Topic {
        mesh,
        topic_string: topic.to_string(),
    };

    let config = setup_mesh(
        kind,
        SetupParams {
            author,
            max_peers: 16,
            max_sessions: 0,
            endpoint: None,
            protocols: Vec::new(),
            transports: TransportOpts::default(),
            runtime_base: None,
            state_file: None,
            sink: std::sync::Arc::new(SilentSink),
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        },
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");

    let (driver, pending) = RollbackDriver::<LightCycles>::new();
    let node: Node<RollbackDriver<LightCycles>> = Node::spawn(config, driver, None, false);
    let game = Game::new(
        pending.connect(node.sender()),
        topic.to_string(),
        nick.to_string(),
    );

    Bot { node, game }
}

/// Ticks both bots at the real frame rate until `condition` holds or
/// `timeout` elapses. Steering is scripted off the tick count so the two
/// bots drive differently and actually collide.
async fn drive(
    bots: &mut [Bot],
    timeout: Duration,
    mut condition: impl FnMut(&[Bot]) -> bool,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut tick: usize = 0;
    loop {
        for (index, bot) in bots.iter_mut().enumerate() {
            if tick.is_multiple_of(17) {
                let turns = [Dir::Up, Dir::Right, Dir::Down, Dir::Left];
                bot.game.steer(turns[(tick / 17 + index * 2) % turns.len()]);
            }
            bot.game.tick();
        }
        tick += 1;
        if condition(bots) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(u64::from(TICK_MS))).await;
    }
}

/// What one bot showed of the first match when it was last decided.
#[derive(Debug, Clone)]
struct FirstMatch {
    outcome: Outcome,
    tick: u16,
    positions: Vec<(i16, i16)>,
}

fn positions(world: &World) -> Vec<(i16, i16)> {
    world
        .cycles
        .iter()
        .map(|cycle| (cycle.x, cycle.y))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn two_bots_play_a_match_and_agree_on_its_outcome() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let topic = format!("light-cycles-two-bots-test-{}", std::process::id());
    let mut bots = vec![
        spawn_bot(&topic, "alice").await,
        spawn_bot(&topic, "bob").await,
    ];

    // The mesh forms, the lobby agrees a match, and both bots build a
    // session for it. Nobody negotiates the roster: the lobby fixes it.
    let started = drive(&mut bots, Duration::from_secs(30), |bots| {
        bots.iter().all(|bot| bot.game.snapshot().roster.len() == 2)
    })
    .await;
    assert!(started, "the two bots never started a match together");

    let rosters: Vec<Vec<String>> = bots
        .iter()
        .map(|bot| {
            bot.game
                .snapshot()
                .roster
                .into_iter()
                .map(|(pubkey, _)| pubkey)
                .collect()
        })
        .collect();
    assert_eq!(
        rosters[0], rosters[1],
        "handles are positional, so a roster that differs by order is a \
         silent desync waiting to happen"
    );

    // Each bot's view of the first match is recorded rather than read at the
    // end: the proposer starts a rematch a grace period after its own match
    // is decided, which resets both worlds, and a slow peer can confirm the
    // ending after that. A slot holds the latest decided frame of match 1,
    // is cleared when a rollback puts match 1 back in play, and freezes once
    // the bot moves on.
    let mut first_match: Vec<Option<FirstMatch>> = vec![None; bots.len()];

    // They play it out. Two cycles turning across a small arena decide
    // well inside the tick cap. Wait for agreement, not the first decided
    // frame: a bot can reach an ending on a predicted input, and the
    // rollback that corrects it waits for the real input to arrive. The
    // timeout is longer than the round cap (`ROUND_MAX_TICKS` at `TICK_MS`,
    // 90 s), so a round that runs to the cap ends as a draw, not a timeout.
    let agreed = drive(&mut bots, Duration::from_secs(100), |bots| {
        for (slot, bot) in first_match.iter_mut().zip(bots) {
            let snapshot = bot.game.snapshot();
            if snapshot.match_number != 1 {
                continue;
            }
            let outcome = bot.game.outcome();
            *slot = (outcome != Outcome::InProgress).then(|| FirstMatch {
                outcome,
                tick: snapshot.world.tick,
                positions: positions(&snapshot.world),
            });
        }
        let first = first_match[0].as_ref().map(|seen| seen.outcome);
        first.is_some()
            && first_match
                .iter()
                .all(|seen| seen.as_ref().map(|seen| seen.outcome) == first)
    })
    .await;
    assert!(
        agreed,
        "the two bots never agreed on who won: {first_match:?}"
    );

    // A match that ends before it starts would satisfy every assertion
    // above vacuously, so pin down that one was actually simulated.
    for seen in first_match.iter().flatten() {
        assert!(
            seen.tick > 5,
            "the match decided at tick {} — too early to have been played",
            seen.tick
        );
    }

    assert!(
        bots.iter().all(|bot| !bot.game.snapshot().desynced),
        "a bot reported a state checksum that disagreed with its peer's"
    );

    // And then they play another one. This is the lobby's epoch doing its
    // job: the second match's id is not ordered below the first's, so the
    // tie-break alone would have refused it and the two would have sat on
    // a finished game forever.
    let first_arena = first_match[0]
        .as_ref()
        .map(|seen| seen.positions.clone())
        .unwrap_or_default();

    let rematched = drive(&mut bots, Duration::from_secs(30), |bots| {
        bots.iter().all(|bot| bot.game.snapshot().match_number == 2)
    })
    .await;
    assert!(
        rematched,
        "no rematch was agreed: {:?}",
        bots.iter()
            .map(|bot| bot.game.snapshot().match_number)
            .collect::<Vec<_>>()
    );
    assert_ne!(
        positions(&bots[0].game.snapshot().world),
        first_arena,
        "a rematch reusing the previous arena means the session id was \
         reused, and with it the magic that rejects stale packets"
    );

    // Leave, rather than letting the runtime drop these mid-flight.
    // `iroh-gossip`'s actor loop `expect`s on its `JoinSet`, so a task
    // cancelled by runtime shutdown panics and fails a passing test.
    for bot in bots {
        bot.node.leave().await.expect("leave the mesh cleanly");
    }
}
