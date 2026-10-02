//! A toy deterministic simulation for the crate's own unit tests.
//!
//! The matching *nondeterministic* one — the case that proves
//! [`crate::SyncTestSession`] actually catches a violation rather than always
//! passing — lives in `tests/determinism.rs`, alongside the public-API test
//! that needs it.

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::request::Request;

/// One player's input: a number folded into the running total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct TestInput(pub(crate) i32);

/// A running total plus the frame it is valid at.
///
/// `frame` is the frame this state sits *before* — a fresh state is at frame
/// 0, having simulated nothing yet, and advancing frame N leaves it at N+1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TestState {
    pub(crate) value: i64,
    pub(crate) frame: crate::frame::Frame,
}

/// A deterministic toy game: the state is a sum of every input ever applied.
pub(crate) struct TestGame;

impl Config for TestGame {
    type Input = TestInput;
    type State = TestState;
    type Address = String;
}

/// Drives a [`TestState`] through the requests a session hands back, exactly
/// as a real consumer would.
pub(crate) struct TestRunner {
    pub(crate) state: TestState,
    /// Every frame advanced, in order — so a test can assert *what* was
    /// re-simulated, not merely that the result matched.
    pub(crate) advanced: Vec<crate::frame::Frame>,
}

impl TestRunner {
    pub(crate) fn new() -> Self {
        Self {
            state: TestState::default(),
            advanced: Vec::new(),
        }
    }

    /// A deterministic checksum of the state — what a real consumer supplies
    /// so desync detection has something to compare.
    fn checksum(state: &TestState) -> u128 {
        // Any stable hash works; this one is trivially portable.
        u128::from(state.value.cast_unsigned()) ^ (u128::from(state.frame.cast_unsigned()) << 64)
    }

    pub(crate) fn handle(&mut self, request: Request<TestGame>) {
        match request {
            Request::SaveState { cell, frame } => {
                cell.save(frame, self.state.clone(), Some(Self::checksum(&self.state)));
            }
            Request::LoadState { cell } => {
                self.state = cell.load().expect("session asked to load an unsaved frame");
            }
            Request::AdvanceFrame { inputs } => {
                let sum: i64 = inputs.iter().map(|(input, _)| i64::from(input.0)).sum();
                self.state.value += sum;
                self.advanced.push(self.state.frame);
                self.state.frame += 1;
            }
        }
    }

    pub(crate) fn handle_all(&mut self, requests: Vec<Request<TestGame>>) {
        for request in requests {
            self.handle(request);
        }
    }
}
