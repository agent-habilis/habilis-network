//! `SyncTestSession` against the public API: it must pass a deterministic
//! simulation and *fail* a nondeterministic one.
//!
//! The second half matters as much as the first. A determinism checker that
//! never fails is worse than no checker, because a green run reads as
//! evidence of correctness.

use habilis_network_netplay::{Config, Request, RollbackError, SyncTestSession};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
struct Input(i32);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct State {
    value: i64,
    frame: i32,
}

struct Game;

impl Config for Game {
    type Input = Input;
    type State = State;
    type Address = String;
}

/// Applies requests. `drift` is added to every advance, which makes the
/// simulation depend on how many times it has run rather than only on its
/// inputs — exactly the bug `SyncTestSession` exists to find.
struct Runner {
    state: State,
    drift: i64,
    drift_step: i64,
    /// How many `AdvanceFrame` requests were fulfilled. Exceeds the frame
    /// count precisely because rollbacks re-simulate.
    advances: usize,
}

impl Runner {
    fn deterministic() -> Self {
        Self {
            state: State::default(),
            drift: 0,
            drift_step: 0,
            advances: 0,
        }
    }

    fn nondeterministic() -> Self {
        Self {
            drift_step: 1,
            ..Self::deterministic()
        }
    }

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
                self.drift += self.drift_step;
                self.state.value += sum + self.drift;
                self.state.frame += 1;
                self.advances += 1;
            }
        }
    }
}

/// Runs `frames` frames, returning the first error the session reports.
fn run(runner: &mut Runner, frames: i32) -> Result<(), RollbackError> {
    let mut session = SyncTestSession::<Game>::new(2, 4);
    for frame in 0..frames {
        session.add_input(0, Input(frame % 3))?;
        session.add_input(1, Input(frame % 5))?;
        for request in session.advance_frame()? {
            runner.handle(request);
        }
    }
    Ok(())
}

#[test]
fn a_deterministic_simulation_passes() {
    let mut runner = Runner::deterministic();
    run(&mut runner, 60).expect("a deterministic simulation must not report a desync");
    assert_eq!(runner.state.frame, 60, "ends where it should");
    // The point of the session: it did far more work than 60 frames, because
    // it re-simulated the last 4 every frame. If this ever equals 60 the
    // rollback path is not being exercised and the check proves nothing.
    assert!(
        runner.advances > 200,
        "expected repeated re-simulation, saw only {} advances",
        runner.advances
    );
}

#[test]
fn a_nondeterministic_simulation_is_caught() {
    let mut runner = Runner::nondeterministic();
    let error = run(&mut runner, 60).expect_err("the drift must be detected");
    assert!(
        matches!(error, RollbackError::Desync { .. }),
        "expected a desync, got {error:?}"
    );
}

#[test]
fn a_missing_input_is_reported_rather_than_silently_defaulted() {
    let mut session = SyncTestSession::<Game>::new(2, 4);
    session.add_input(0, Input(1)).expect("valid handle");
    // Player 1's input was never supplied.
    assert!(matches!(
        session.advance_frame(),
        Err(RollbackError::InvalidPlayer(1))
    ));
}

#[test]
fn an_out_of_range_handle_is_rejected() {
    let mut session = SyncTestSession::<Game>::new(2, 4);
    assert!(matches!(
        session.add_input(7, Input(1)),
        Err(RollbackError::InvalidPlayer(7))
    ));
}
