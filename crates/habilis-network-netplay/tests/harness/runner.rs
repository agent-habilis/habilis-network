use habilis_network_netplay::Request;

use crate::{Game, State};

/// Applies a session's requests to a `State`, exactly as a consumer would.
#[derive(Debug, Clone, Copy)]
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
        u128::from(state.value.cast_unsigned())
            ^ (u128::from(state.frame.get().cast_unsigned()) << 64)
    }

    pub(crate) fn handle(&mut self, request: Request<Game>) {
        match request {
            Request::SaveState { cell, frame } => {
                cell.save(frame, self.state, Some(Self::checksum(&self.state)));
            }
            Request::LoadState { cell } => {
                self.state = cell.load().expect("the session only loads frames it saved");
            }
            Request::AdvanceFrame { inputs } => {
                let sum: i64 = inputs.iter().map(|(input, _)| i64::from(input.0)).sum();
                self.state.value += sum;
                self.state.frame += 1;
            }
            _ => unreachable!("a request this test does not expect"),
        }
    }
}
