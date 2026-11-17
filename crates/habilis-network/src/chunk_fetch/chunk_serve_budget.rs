//! How many chunk answers this node sends in a window, per endpoint and in all.

use std::collections::HashMap;

use habilis_network_util::clock::Instant;
use habilis_network_util::tuning::{
    CHUNK_SERVE_WINDOW, CHUNK_SERVES_GLOBAL, CHUNK_SERVES_PER_WINDOW,
};
use iroh::EndpointId;

/// The chunk answers that this node gives in one window. A map and a chunk both count. The count is per endpoint,
/// the connection that the answer goes to: the endpoint is proven by TLS, and a signing key costs nothing to make.
/// A request over the budget gets the absent answer, and the asker takes the next source.
#[derive(Debug, Default)]
pub(crate) struct ChunkServeBudget {
    /// When the current window began. `None` before the first answer.
    window_start: Option<Instant>,
    /// The answers in this window, in all.
    global: usize,
    /// The answers in this window, per endpoint.
    per_endpoint: HashMap<EndpointId, usize>,
}

impl ChunkServeBudget {
    /// Spends one answer for `endpoint` at `now`, if the window has room for it.
    pub(crate) fn admit(&mut self, endpoint: EndpointId, now: Instant) -> bool {
        let window_over = self
            .window_start
            .is_none_or(|start| now.duration_since(start) >= CHUNK_SERVE_WINDOW);
        if window_over {
            self.window_start = Some(now);
            self.global = 0;
            self.per_endpoint.clear();
        }
        if self.global >= CHUNK_SERVES_GLOBAL {
            return false;
        }
        let spent = self.per_endpoint.entry(endpoint).or_insert(0);
        if *spent >= CHUNK_SERVES_PER_WINDOW {
            return false;
        }
        *spent += 1;
        self.global += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::ChunkServeBudget;
    use crate::testing;
    use habilis_network_util::clock::Instant;
    use habilis_network_util::tuning::{
        CHUNK_SERVE_WINDOW, CHUNK_SERVES_GLOBAL, CHUNK_SERVES_PER_WINDOW,
    };

    #[test]
    fn an_endpoint_gets_its_share_of_a_window_and_no_more() {
        let now = Instant::now();
        let mut budget = ChunkServeBudget::default();
        for _ in 0..CHUNK_SERVES_PER_WINDOW {
            assert!(
                budget.admit(testing::endpoint_id(1), now),
                "the answers up to the share of an endpoint are given"
            );
        }
        assert!(
            !budget.admit(testing::endpoint_id(1), now),
            "the answer past the share of an endpoint is refused"
        );
        assert!(
            budget.admit(testing::endpoint_id(2), now),
            "another endpoint has its own share"
        );
    }

    #[test]
    fn the_whole_node_gives_no_more_than_the_global_count_in_a_window() {
        let now = Instant::now();
        let mut budget = ChunkServeBudget::default();
        let askers = CHUNK_SERVES_GLOBAL / CHUNK_SERVES_PER_WINDOW;
        for asker in 0..askers {
            let id = u8::try_from(asker + 1).expect("a small asker");
            for _ in 0..CHUNK_SERVES_PER_WINDOW {
                assert!(
                    budget.admit(testing::endpoint_id(id), now),
                    "the answers under the global count are given"
                );
            }
        }
        assert!(
            !budget.admit(testing::endpoint_id(200), now),
            "the answer past the global count is refused, whoever asks"
        );
    }

    #[test]
    fn a_new_window_gives_the_room_back() {
        let now = Instant::now();
        let mut budget = ChunkServeBudget::default();
        for _ in 0..CHUNK_SERVES_PER_WINDOW {
            assert!(
                budget.admit(testing::endpoint_id(1), now),
                "within the share"
            );
        }
        assert!(
            !budget.admit(testing::endpoint_id(1), now),
            "the share is spent"
        );
        assert!(
            budget.admit(testing::endpoint_id(1), now + CHUNK_SERVE_WINDOW),
            "a new window must give the room back"
        );
    }
}
