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
    /// Records a pull of the slice of `author` on `channel`, asked of `holder` at `now`.
    pub(crate) fn register(
        &mut self,
        holder: EndpointId,
        channel: Channel,
        author: AuthorKey,
        now: Instant,
    ) {
        self.pulls.insert((holder, channel, author), now);
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
