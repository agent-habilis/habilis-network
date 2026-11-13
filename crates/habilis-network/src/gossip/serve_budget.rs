//! How many slice answers this node sends in a window, per endpoint and in all.

use std::collections::HashMap;

use habilis_network_protocol::Channel;
use habilis_network_util::clock::Instant;
use habilis_network_util::tuning::{
    DIGEST_SERVE_WINDOW, DIGEST_SERVES_GLOBAL, DIGEST_SERVES_PER_WINDOW,
};
use iroh::EndpointId;

/// The answers that this node gives to slice pulls and page requests in one window.
///
/// A pull and a page request both count. The count is per endpoint, the connection that the answer
/// goes to. The endpoint is proven by TLS, and a signing key costs nothing to make, so a key would let
/// one peer take every answer of a window. A request over the budget gets no answer, and the asker asks
/// again at its next tick.
#[derive(Debug, Default)]
pub(crate) struct ServeBudget {
    /// When the current window began. `None` before the first answer.
    window_start: Option<Instant>,
    /// The answers in this window, in all.
    global: usize,
    /// The answers in this window, per endpoint and channel.
    per_endpoint: HashMap<(EndpointId, Channel), usize>,
}

impl ServeBudget {
    /// Spends one answer for `endpoint` on `channel` at `now`, if the window has room for it.
    pub(crate) fn admit(&mut self, endpoint: EndpointId, channel: Channel, now: Instant) -> bool {
        let window_over = self
            .window_start
            .is_none_or(|start| now.duration_since(start) >= DIGEST_SERVE_WINDOW);
        if window_over {
            self.window_start = Some(now);
            self.global = 0;
            self.per_endpoint.clear();
        }
        if self.global >= DIGEST_SERVES_GLOBAL {
            return false;
        }
        let spent = self.per_endpoint.entry((endpoint, channel)).or_insert(0);
        if *spent >= DIGEST_SERVES_PER_WINDOW {
            return false;
        }
        *spent += 1;
        self.global += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::ServeBudget;
    use crate::testing;
    use habilis_network_protocol::Channel;
    use habilis_network_util::clock::Instant;
    use habilis_network_util::tuning::DIGEST_SERVE_WINDOW;

    /// The ninth pull of one endpoint on one channel in a window is refused, and another channel still has room.
    #[test]
    fn the_ninth_pull_in_a_window_is_refused() {
        let now = Instant::now();
        let mut budget = ServeBudget::default();
        for _ in 0..8 {
            assert!(
                budget.admit(testing::endpoint_id(1), Channel::State, now),
                "the first 8 pulls are answered"
            );
        }
        assert!(
            !budget.admit(testing::endpoint_id(1), Channel::State, now),
            "the ninth pull is refused"
        );
        assert!(
            budget.admit(testing::endpoint_id(1), Channel::Meta, now),
            "another channel has its own room"
        );
    }

    /// The 33rd answer in a window is refused, whichever endpoint asks for it.
    #[test]
    fn the_global_cap_refuses_the_33rd() {
        let now = Instant::now();
        let mut budget = ServeBudget::default();
        for seed in 1..=32 {
            assert!(
                budget.admit(testing::endpoint_id(seed), Channel::State, now),
                "answer {seed} is within the cap"
            );
        }
        assert!(
            !budget.admit(testing::endpoint_id(33), Channel::State, now),
            "the 33rd answer is refused"
        );
    }

    /// One endpoint that uses its own room does not take the room of another endpoint.
    #[test]
    fn one_endpoint_does_not_use_up_the_room_of_another() {
        let now = Instant::now();
        let mut budget = ServeBudget::default();
        for _ in 0..8 {
            budget.admit(testing::endpoint_id(1), Channel::State, now);
        }
        for _ in 0..8 {
            assert!(
                budget.admit(testing::endpoint_id(2), Channel::State, now),
                "a second endpoint has its own 8 answers"
            );
        }
    }

    /// A new window restores the room of the old one.
    #[test]
    fn a_new_window_restores_the_room() {
        let now = Instant::now();
        let mut budget = ServeBudget::default();
        for _ in 0..8 {
            budget.admit(testing::endpoint_id(1), Channel::State, now);
        }
        assert!(
            !budget.admit(testing::endpoint_id(1), Channel::State, now),
            "the window is full"
        );
        let later = now + DIGEST_SERVE_WINDOW;
        assert!(
            budget.admit(testing::endpoint_id(1), Channel::State, later),
            "the next window has room"
        );
    }
}
