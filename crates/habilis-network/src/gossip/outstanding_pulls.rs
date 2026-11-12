//! The slice pulls that this node sent and that wait for an answer.

use std::collections::HashMap;

use habilis_network_protocol::{AuthorKey, Channel};
use habilis_network_util::clock::Instant;
use habilis_network_util::tuning::DIGEST_PULL_TTL;
use iroh::EndpointId;

/// The pulls of this node, keyed by the holder endpoint, the channel and the author of the slice
/// that was asked for. A frame that answers a pull skips the duplicate gate and takes no token.
#[derive(Debug, Default)]
pub(crate) struct OutstandingPulls {
    pulls: HashMap<(EndpointId, Channel, AuthorKey), Instant>,
}

impl OutstandingPulls {
    /// Records a pull of the slice of `author` on `channel`, asked of `holder` at `now`. A holder that already
    /// has `cap` open pulls gets no more: the pull is not recorded, and the function says so.
    pub(crate) fn register(
        &mut self,
        holder: EndpointId,
        channel: Channel,
        author: AuthorKey,
        now: Instant,
        cap: usize,
    ) -> bool {
        let open = self
            .pulls
            .keys()
            .filter(|(held, _, _)| *held == holder)
            .count();
        if open >= cap {
            return false;
        }
        self.pulls.insert((holder, channel, author), now);
        true
    }

    /// Takes the pull of `author` on `channel` from `holder`, if it is still open at `now`.
    pub(crate) fn take(
        &mut self,
        holder: EndpointId,
        channel: Channel,
        author: AuthorKey,
        now: Instant,
    ) -> bool {
        self.pulls
            .remove(&(holder, channel, author))
            .is_some_and(|asked| now.duration_since(asked) < DIGEST_PULL_TTL)
    }

    /// Drops the pulls that are older than [`DIGEST_PULL_TTL`] at `now`.
    pub(crate) fn expire(&mut self, now: Instant) {
        self.pulls
            .retain(|_, asked| now.duration_since(*asked) < DIGEST_PULL_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::OutstandingPulls;
    use crate::testing;
    use habilis_network_protocol::{AuthorKey, Channel};
    use habilis_network_util::clock::Instant;

    /// A holder that has its cap of open pulls gets no more; another holder still has its own cap.
    #[test]
    fn a_holder_at_its_cap_gets_no_more_pulls() {
        let now = Instant::now();
        let holder = testing::endpoint_id(81);
        let other = testing::endpoint_id(82);
        let mut pulls = OutstandingPulls::default();
        for seed in 0..3 {
            assert!(
                pulls.register(holder, Channel::State, AuthorKey::from([seed; 32]), now, 3),
                "a pull within the cap is recorded"
            );
        }
        assert!(
            !pulls.register(holder, Channel::State, AuthorKey::from([9; 32]), now, 3),
            "a holder at its cap gets no more pulls"
        );
        assert!(
            pulls.register(other, Channel::State, AuthorKey::from([9; 32]), now, 3),
            "another holder has its own cap"
        );
    }
}
