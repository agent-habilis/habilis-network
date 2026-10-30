//! Shared request-fulfilling runner for the integration tests.

mod runner;

use habilis_network_netplay::{PlayerHandle, SyncTestSession};

use crate::{Game, Input, State};

pub(crate) use runner::Runner;

/// Runs `script` through a session with the given rollback depth and returns
/// the final state.
pub(crate) fn sim(script: &[(i32, i32)], check_distance: usize) -> State {
    let mut session = SyncTestSession::<Game>::new(2, check_distance);
    let mut runner = Runner::new();
    for (left, right) in script {
        session
            .add_input(PlayerHandle::new(0), Input(*left))
            .expect("valid handle");
        session
            .add_input(PlayerHandle::new(1), Input(*right))
            .expect("valid handle");
        for request in session
            .advance_frame()
            .expect("a deterministic sim never desyncs")
        {
            runner.handle(request);
        }
    }
    runner.state
}
