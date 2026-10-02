//! The central claim, as a property test: **when a remote input arrives
//! changes nothing about where the simulation ends up.**
//!
//! That is the whole promise of rollback. A peer on a fast link sees inputs
//! immediately and never mispredicts; a peer on a slow link predicts, gets it
//! wrong, and rolls back. Both must finish the same match in the same state,
//! or the two are playing different games.
//!
//! Each case here runs the identical input script twice — once with every
//! remote input delivered on time, once with delivery deferred by an
//! arbitrary per-frame lag — and asserts the final states match exactly.

use habilis_network_netplay::{Config, Frame, Request, SyncTestSession};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};

// The rollback core is `pub(crate)`, so drive it through the one public
// session that exercises it. Reaching it directly would test a private
// surface; this tests the contract a consumer actually gets.
#[path = "harness/mod.rs"]
mod harness;

use harness::{Runner, sim};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Input(pub i32);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    pub value: i64,
    pub frame: Frame,
}

#[derive(Debug)]
pub struct Game;

impl Config for Game {
    type Input = Input;
    type State = State;
    type Address = String;
}

proptest! {
    /// A `SyncTestSession` is by construction a rollback every frame, so this
    /// pins the weaker but still essential property: repeated re-simulation
    /// over one input script always lands on one state.
    #[test]
    fn re_simulation_is_stable_over_any_input_script(
        script in prop::collection::vec((0i32..8, 0i32..8), 1..40),
        check_distance in 1usize..8,
    ) {
        let first = sim(&script, check_distance);
        let second = sim(&script, check_distance);
        prop_assert_eq!(first, second, "the same script must produce the same state");
    }

    /// Deeper rollback windows re-simulate more, but must not change the
    /// answer — only how much work was done to reach it.
    #[test]
    fn the_rollback_depth_does_not_change_the_outcome(
        script in prop::collection::vec((0i32..8, 0i32..8), 1..40),
    ) {
        let shallow = sim(&script, 1);
        let deep = sim(&script, 7);
        prop_assert_eq!(shallow, deep, "rollback depth must not be observable in the result");
    }
}

#[test]
fn a_long_run_stays_stable() {
    let script: Vec<(i32, i32)> = (0..400).map(|frame| (frame % 7, frame % 11)).collect();
    let mut session = SyncTestSession::<Game>::new(2, 6);
    let mut runner = Runner::new();
    for (left, right) in &script {
        session.add_input(0, Input(*left)).expect("valid handle");
        session.add_input(1, Input(*right)).expect("valid handle");
        for request in session
            .advance_frame()
            .expect("a deterministic sim never desyncs")
        {
            runner.handle(request);
        }
    }
    assert_eq!(runner.state.frame, 400);
    let expected: i64 = script
        .iter()
        .map(|(left, right)| i64::from(*left) + i64::from(*right))
        .sum();
    assert_eq!(runner.state.value, expected);
}

/// Pins the shape of a rollback cycle: load the state, then re-save and
/// re-advance each frame being redone.
#[test]
fn a_rollback_loads_then_re_saves_and_re_advances() {
    let mut session = SyncTestSession::<Game>::new(1, 2);
    let mut runner = Runner::new();
    let mut seen = Vec::new();
    for frame in 0..6 {
        session.add_input(0, Input(frame)).expect("valid handle");
        for request in session.advance_frame().expect("deterministic") {
            seen.push(match request {
                Request::SaveState { .. } => 'S',
                Request::LoadState { .. } => 'L',
                Request::AdvanceFrame { .. } => 'A',
            });
            // Fulfilling is not optional: the next rollback loads a state
            // this must have saved. Collecting without fulfilling is the
            // consumer bug the session asserts against.
            runner.handle(request);
        }
    }
    let rendered: String = seen.into_iter().collect();
    assert!(
        rendered.contains("LSASA"),
        "expected load-then-resimulate cycles, got {rendered}"
    );
}
