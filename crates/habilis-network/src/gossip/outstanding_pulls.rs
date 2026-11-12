//! The slice pulls that this node sent and that wait for an answer.

use std::collections::HashMap;

use habilis_network_protocol::{AuthorKey, Channel};
use habilis_network_util::clock::Instant;
use habilis_network_util::tuning::{DIGEST_PULL_TTL, DIGEST_PULLS_OPEN};
use iroh::EndpointId;

/// The pulls of this node, keyed by the holder endpoint, the channel and the author of the slice
/// that was asked for. A frame that answers a pull skips the duplicate gate and takes no token.
#[derive(Debug, Default)]
pub(crate) struct OutstandingPulls {
    pulls: HashMap<(EndpointId, Channel, AuthorKey), Instant>,
    /// The open pulls of each holder, in all channels, kept beside `pulls` so that the cap is read in one step.
    open: HashMap<EndpointId, usize>,
}

/// Gives back the room of one pull of `holder`.
fn release(open: &mut HashMap<EndpointId, usize>, holder: EndpointId) {
    if let Some(count) = open.get_mut(&holder) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            open.remove(&holder);
        }
    }
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
        let slot = (holder, channel, author);
        if self
            .pulls
            .get(&slot)
            .is_some_and(|asked| now.duration_since(*asked) >= DIGEST_PULL_TTL)
        {
            self.pulls.remove(&slot);
            release(&mut self.open, holder);
        }
        let open = self.open.get(&holder).copied().unwrap_or(0);
        if open >= cap || self.pulls.len() >= DIGEST_PULLS_OPEN {
            return false;
        }
        if self.pulls.insert((holder, channel, author), now).is_none() {
            *self.open.entry(holder).or_insert(0) += 1;
        }
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
        let Some(asked) = self.pulls.remove(&(holder, channel, author)) else {
            return false;
        };
        release(&mut self.open, holder);
        now.duration_since(asked) < DIGEST_PULL_TTL
    }

    /// Drops the pulls that are older than [`DIGEST_PULL_TTL`] at `now`.
    pub(crate) fn expire(&mut self, now: Instant) {
        let open = &mut self.open;
        self.pulls.retain(|(holder, _, _), asked| {
            let live = now.duration_since(*asked) < DIGEST_PULL_TTL;
            if !live {
                release(open, *holder);
            }
            live
        });
    }
}

#[cfg(test)]
mod tests {
    use super::OutstandingPulls;
    use crate::testing;
    use habilis_network_protocol::{AuthorKey, Channel};
    use habilis_network_util::clock::Instant;
    use habilis_network_util::tuning::{DIGEST_PULL_TTL, DIGEST_PULLS_OPEN};

    fn key_of(index: usize) -> AuthorKey {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(
            &u64::try_from(index)
                .expect("an index fits 64 bits")
                .to_be_bytes(),
        );
        AuthorKey::from(bytes)
    }

    /// A pull that is taken gives its room back to the holder.
    #[test]
    fn a_taken_pull_gives_its_room_back() {
        let now = Instant::now();
        let holder = testing::endpoint_id(81);
        let mut pulls = OutstandingPulls::default();
        assert!(
            pulls.register(holder, Channel::State, key_of(1), now, 1),
            "the first pull is recorded"
        );
        assert!(
            !pulls.register(holder, Channel::State, key_of(2), now, 1),
            "the holder is at its cap"
        );
        assert!(
            pulls.take(holder, Channel::State, key_of(1), now),
            "the open pull is taken"
        );
        assert!(
            pulls.register(holder, Channel::State, key_of(2), now, 1),
            "the taken pull gave its room back"
        );
    }

    /// The open count of each holder equals its entries after registers, takes and expiries in turn.
    #[test]
    fn the_open_count_of_a_holder_matches_its_entries() {
        let now = Instant::now();
        let first = testing::endpoint_id(81);
        let second = testing::endpoint_id(82);
        let mut pulls = OutstandingPulls::default();
        pulls.register(first, Channel::State, key_of(1), now, 8);
        pulls.register(first, Channel::Meta, key_of(2), now, 8);
        pulls.register(second, Channel::State, key_of(3), now, 8);
        pulls.take(first, Channel::State, key_of(1), now);
        pulls.expire(now + DIGEST_PULL_TTL);
        pulls.register(first, Channel::State, key_of(4), now + DIGEST_PULL_TTL, 8);
        for holder in [first, second] {
            let entries = pulls
                .pulls
                .keys()
                .filter(|(held, _, _)| *held == holder)
                .count();
            assert_eq!(
                pulls.open.get(&holder).copied().unwrap_or(0),
                entries,
                "the open count of the holder matches its entries"
            );
        }
    }

    /// A key whose pull has expired is pulled again at once, and the expired pull takes no room.
    #[test]
    fn a_key_whose_pull_expired_is_pulled_again_at_once() {
        let now = Instant::now();
        let holder = testing::endpoint_id(81);
        let mut pulls = OutstandingPulls::default();
        assert!(
            pulls.register(holder, Channel::State, key_of(1), now, 1),
            "the first pull is recorded"
        );
        assert!(
            pulls.register(holder, Channel::State, key_of(1), now + DIGEST_PULL_TTL, 1),
            "a key whose pull expired gets a new pull, and the expired one takes no room"
        );
    }

    /// A pull that expires gives its room back to the holder.
    #[test]
    fn an_expired_pull_gives_its_room_back() {
        let now = Instant::now();
        let holder = testing::endpoint_id(81);
        let mut pulls = OutstandingPulls::default();
        assert!(
            pulls.register(holder, Channel::State, key_of(1), now, 1),
            "the first pull is recorded"
        );
        pulls.expire(now + DIGEST_PULL_TTL);
        assert!(
            pulls.register(holder, Channel::State, key_of(2), now + DIGEST_PULL_TTL, 1),
            "the expired pull gave its room back"
        );
    }

    /// The table holds at most `DIGEST_PULLS_OPEN` pulls in all, whichever holder they are for.
    #[test]
    fn the_table_holds_at_most_the_open_pulls_in_all() {
        let now = Instant::now();
        let holder = testing::endpoint_id(81);
        let mut pulls = OutstandingPulls::default();
        for index in 0..DIGEST_PULLS_OPEN {
            assert!(
                pulls.register(holder, Channel::State, key_of(index), now, usize::MAX),
                "a pull within the total is recorded"
            );
        }
        assert!(
            !pulls.register(
                holder,
                Channel::State,
                key_of(DIGEST_PULLS_OPEN),
                now,
                usize::MAX
            ),
            "a pull past the total is refused, whatever the holder cap"
        );
    }

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
