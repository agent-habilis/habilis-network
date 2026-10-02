//! Shared request-fulfilling runner for the integration tests.

use habilis_network_netplay::{Request, SyncTestSession};

use crate::{Game, Input, State};

/// Applies a session's requests to a `State`, exactly as a consumer would.
pub(crate) struct Runner {
    pub(crate) state: State,
}

impl Runner {
    pub(crate) fn new() -> Self {
        Self {
            state: State::default(),
        }
    }

    fn checksum(state: &State) -> u128 {
        u128::from(state.value.cast_unsigned()) ^ (u128::from(state.frame.cast_unsigned()) << 64)
    }

    pub(crate) fn handle(&mut self, request: Request<Game>) {
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
}

/// Runs `script` through a session with the given rollback depth and returns
/// the final state.
pub(crate) fn sim(script: &[(i32, i32)], check_distance: usize) -> State {
    let mut session = SyncTestSession::<Game>::new(2, check_distance);
    let mut runner = Runner::new();
    for (left, right) in script {
        session.add_input(0, Input(*left)).expect("valid handle");
        session.add_input(1, Input(*right)).expect("valid handle");
        for request in session
            .advance_frame()
            .expect("a deterministic sim never desyncs")
        {
            runner.handle(request);
        }
    }
    runner.state
}
