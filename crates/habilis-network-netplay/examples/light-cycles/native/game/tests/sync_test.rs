//! Runs the light-cycles simulation under `SyncTestSession`.
//!
//! This is the check every consumer of `habilis-network-netplay` is told to run,
//! applied to this example. It forces a rollback on every frame and
//! compares the state checksum before and after re-simulating, so any
//! dependence on something other than `(state, inputs)` — a clock, a
//! hashed-collection iteration order, an accumulator that is not part of
//! the saved state — shows up here rather than as a desync between two
//! real players.
//!
//! It is also what would have caught the bug this example used to have:
//! the arena was laid out from a *live* estimate of who was present, so
//! two peers could derive different spawns for the same round and diverge
//! immediately. The roster is now fixed by the lobby before a match
//! starts.

use habilis_network_netplay::{Request, RollbackError, SyncTestSession};

use light_cycles_native::app::LightCycles;
use light_cycles_native::grid::{Dir, Input};
use light_cycles_native::round::RoundDescriptor;
use light_cycles_native::sim::{self, World};

/// Drives the simulation from the session's requests, exactly as the real
/// client does.
struct Runner {
    world: World,
}

impl Runner {
    fn handle(&mut self, request: Request<LightCycles>) {
        match request {
            Request::SaveState { cell, frame } => {
                let checksum = self.world.checksum();
                cell.save(frame, self.world.clone(), Some(checksum));
            }
            Request::LoadState { cell } => {
                self.world = cell.load().expect("the session only loads frames it saved");
            }
            Request::AdvanceFrame { inputs } => {
                let inputs: Vec<Input> = inputs.iter().map(|(input, _)| *input).collect();
                sim::step(&mut self.world, &inputs);
            }
        }
    }
}

/// A steering script that varies per player and per frame, so the run
/// exercises turning, refused reversals and collisions rather than two
/// cycles coasting in a straight line.
fn steer(player: usize, frame: usize) -> Input {
    const TURNS: [Dir; 4] = [Dir::Up, Dir::Right, Dir::Down, Dir::Left];
    if frame % 7 == player % 7 {
        Input {
            steer: Some(TURNS[(frame / 7 + player) % TURNS.len()]),
        }
    } else {
        Input::default()
    }
}

#[test]
fn the_simulation_survives_a_rollback_on_every_frame() {
    const PLAYERS: usize = 4;

    let roster: Vec<String> = (0..PLAYERS).map(|i| format!("player-{i}")).collect();
    let descriptor = RoundDescriptor::derive(0xfeed_1234_5678_9abc, roster);
    let mut runner = Runner {
        world: World::spawn(&descriptor),
    };

    let mut session = SyncTestSession::<LightCycles>::new(PLAYERS, 4);
    for frame in 0..400 {
        for player in 0..PLAYERS {
            session
                .add_input(player, steer(player, frame))
                .expect("a fresh input for every player, every frame");
        }
        match session.advance_frame() {
            Ok(requests) => {
                for request in requests {
                    runner.handle(request);
                }
            }
            // The one error a sync test raises is the thing it is looking
            // for; surface it rather than treating it as pacing.
            Err(RollbackError::Desync {
                frame,
                local,
                remote,
            }) => {
                panic!(
                    "the light-cycles simulation is not deterministic: \
                     re-simulating frame {frame} produced {remote:#x}, not {local:#x}"
                );
            }
            Err(other) => panic!("unexpected session error: {other}"),
        }
    }

    assert!(
        runner.world.tick > 0,
        "the run has to actually simulate something for the check to mean anything"
    );
}
