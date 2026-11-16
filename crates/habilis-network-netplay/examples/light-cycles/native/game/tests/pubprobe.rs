//! The public twin of `two_bots.rs`: two independent bots on a **public**
//! mesh (`LookupOpts::public_preset()`: mDNS, the DHT and the public relay
//! ladder) play a whole match against each other and independently derive
//! the same outcome, having exchanged nothing but per-tick inputs.
//!
//! Ignored by default: it needs the public relay ladder and a network where
//! two endpoints on one host can hole-punch each other, and on a shared CI
//! runner the session handshake never completes. Run it by hand with
//! `cargo test --test pubprobe -- --ignored`.
//!
//! That is the central claim of the example — GGPO-style rollback over a
//! habilis-network mesh, no authoritative peer, no state on the wire — checked
//! end-to-end rather than just in the simulation (`sim.rs`'s own tests
//! cover that half, and `sync_test.rs` covers determinism).

use std::time::Duration;

use habilis_network::embed::SilentSink;
use habilis_network::protocol::{LookupOpts, Nickname};
use habilis_network::runtime::{
    Node, SetupKind, SetupParams, SignalHandling, derive_topic_mesh_with, setup_mesh,
};
use habilis_network_netplay::RollbackDriver;

use light_cycles_native::dir::Dir;
use light_cycles_native::game::Game;
use light_cycles_native::light_cycles::LightCycles;
use light_cycles_native::outcome::Outcome;

use std::{process, thread};
use tokio::time::{self, Instant};
struct Bot {
    node: Node<RollbackDriver<LightCycles>>,
    game: Game,
}

async fn spawn_bot(topic: &str, nick: &str) -> Bot {
    let mesh =
        derive_topic_mesh_with(topic, LookupOpts::public_preset()).expect("derive a loopback mesh");
    let author = Nickname::try_new(nick).expect("valid nickname");
    let kind = SetupKind::Topic {
        mesh,
        topic_string: topic.to_string(),
    };

    let config = setup_mesh(
        kind,
        SetupParams::new(author.clone(), SilentSink::default()).max_peers(16),
    )
    .await
    .expect("setup_mesh on a loopback mesh must not touch the network");

    let (driver, pending): (RollbackDriver<LightCycles>, _) = RollbackDriver::new();
    let node: Node<RollbackDriver<LightCycles>> =
        Node::spawn(config, driver, None, SignalHandling::Leave);
    let game = Game::new(pending.connect(node.sender()), topic.to_string(), author);

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
    let deadline = Instant::now() + timeout;
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
        if Instant::now() >= deadline {
            return false;
        }
        time::sleep(Duration::from_millis(10)).await;
    }
}

#[test]
#[ignore = "needs the public relay ladder and a hole-punchable network; run with --ignored"]
fn public_path_probe() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run_multi_thread(
        guard,
        thread::available_parallelism().map_or(1, usize::from),
        async {
            let topic = format!("light-cycles-two-bots-test-{}", process::id());

            let mut bots = vec![
                spawn_bot(&topic, "alice").await,
                spawn_bot(&topic, "bob").await,
            ];

            // The mesh forms, the lobby agrees a match, and both bots build a
            // session for it. Nobody negotiates the roster: the lobby fixes it.
            // Both bots claim the beacon after two probe rounds (~23s), and the first
            // rival re-check (~12s later) is what merges the two halves.
            let started = drive(&mut bots, Duration::from_secs(60), |bots| {
                let roster = |bot: &Bot| bot.game.snapshot().roster.len();
                bots.iter().all(|bot| roster(bot) == 2)
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

            // They play it out. Two cycles turning across a small arena decide
            // well inside the tick cap. Wait for agreement, not the first decided
            // frame: a bot can reach an ending on a predicted input, and the
            // rollback that corrects it waits for the real input to arrive.
            let agreed = drive(&mut bots, Duration::from_secs(60), |bots| {
                let first = bots[0].game.outcome();
                first != Outcome::InProgress && bots.iter().all(|bot| bot.game.outcome() == first)
            })
            .await;
            let snapshots: Vec<_> = bots.iter().map(|bot| bot.game.snapshot()).collect();
            let pairs = bots.iter().zip(&snapshots);
            let outcomes: Vec<_> = pairs
                .map(|(bot, snapshot)| (bot.game.outcome(), snapshot.world.tick))
                .collect();
            assert!(agreed, "the two bots never agreed on who won: {outcomes:?}");

            // A match that ends before it starts would satisfy every assertion
            // above vacuously, so pin down that one was actually simulated.
            for bot in &bots {
                let snapshot = bot.game.snapshot();
                assert!(
                    snapshot.world.tick > 5,
                    "the match decided at tick {} — too early to have been played",
                    snapshot.world.tick
                );
                assert_eq!(
                    snapshot.match_number, 1,
                    "the public probe reads match number one"
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
            let spawns = |bots: &[Bot]| -> Vec<(i16, i16)> {
                let world = bots[0].game.snapshot().world;
                world
                    .cycles
                    .iter()
                    .map(|cycle| (cycle.x, cycle.y))
                    .collect()
            };
            let first_arena = spawns(&bots);

            let rematched = drive(&mut bots, Duration::from_secs(30), |bots| {
                bots.iter().all(|bot| bot.game.snapshot().match_number == 2)
            })
            .await;
            let matches: Vec<_> = bots
                .iter()
                .map(|bot| bot.game.snapshot().match_number)
                .collect();
            assert!(rematched, "no rematch was agreed: {matches:?}");
            assert_ne!(
                spawns(&bots),
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
        },
    );
}
