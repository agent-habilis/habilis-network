//! The slices that wait for their author to join the roster.
//!
//! A slice from a key outside the roster is not applied. It waits here, one frame per key, until
//! the key joins or returns. The set is bounded in count and in time, so a flood of fresh keys
//! cannot grow it without limit.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use habilis_network_protocol::AuthorKey;
use habilis_network_protocol::messages::Verified;
use habilis_network_util::clock::Instant;

/// One signed frame per author, held until its author is in the roster.
#[derive(Debug)]
pub(crate) struct PendingSlices {
    held: HashMap<AuthorKey, Held>,
    /// The keys in the order they first arrived. The front is the oldest.
    order: VecDeque<AuthorKey>,
    cap: usize,
    ttl: Duration,
}

#[derive(Debug)]
struct Held {
    frame: Verified,
    version: u64,
    since: Instant,
}

impl PendingSlices {
    /// Makes an empty set that holds at most `cap` keys, each for at most `ttl`.
    #[must_use]
    pub(crate) fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            held: HashMap::new(),
            order: VecDeque::new(),
            cap,
            ttl,
        }
    }

    /// Holds `frame` at `version` unless a version at least as new is already held.
    ///
    /// A full set evicts its oldest key to make room, and logs the eviction. A newer version
    /// restarts the wait of its key, so the cap bounds the number of keys, not how long each one
    /// waits. Returns `true` when the frame is held.
    pub(crate) fn hold(&mut self, frame: &Verified, version: u64, now: Instant) -> bool {
        let key = frame.key();
        if let Some(held) = self.held.get_mut(&key) {
            if version <= held.version {
                return false;
            }
            held.frame = frame.clone();
            held.version = version;
            held.since = now;
            return true;
        }
        if self.held.len() >= self.cap
            && let Some(oldest) = self.order.pop_front()
        {
            self.held.remove(&oldest);
            tracing::debug!(target: "habilis_network::gossip", "a held slice was evicted at the pending cap");
        }
        self.held.insert(
            key,
            Held {
                frame: frame.clone(),
                version,
                since: now,
            },
        );
        self.order.push_back(key);
        true
    }

    /// Removes and returns the held frame of `key`.
    pub(crate) fn take(&mut self, key: &AuthorKey) -> Option<Verified> {
        let held = self.held.remove(key)?;
        self.order.retain(|queued| queued != key);
        Some(held.frame)
    }

    /// Drops every key that has waited for the TTL or longer at `now`.
    pub(crate) fn expire(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.held
            .retain(|_, held| now.saturating_duration_since(held.since) < ttl);
        let held = &self.held;
        self.order.retain(|key| held.contains_key(key));
    }
}

#[cfg(test)]
impl PendingSlices {
    /// Returns the version held for `key`, or `None` when no frame of it waits.
    fn held_version(&self, key: &AuthorKey) -> Option<u64> {
        self.held.get(key).map(|held| held.version)
    }

    /// Returns the number of keys that wait.
    fn len(&self) -> usize {
        self.held.len()
    }

    /// Returns `true` when no key waits.
    fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::PendingSlices;
    use habilis_network_protocol::messages::Verified;
    use habilis_network_protocol::{AuthorKey, Channel, MeshId, Message, MessageBody, Nickname};
    use habilis_network_util::clock::Instant;
    use serde_json::json;
    use std::time::Duration;

    fn key(byte: u8) -> AuthorKey {
        AuthorKey::from([byte; 32])
    }

    /// A signed meta frame of `key` whose body holds `version`.
    fn frame(key: AuthorKey, version: u64) -> Verified {
        let body = json!({"version": version, "value": {}}).to_string();
        Verified::fixture_unchecked(
            Message::new_channel_event(
                &MeshId::from("test"),
                &Nickname::from("peer"),
                MessageBody::from(body.as_str()),
                Channel::Meta,
            ),
            key,
        )
    }

    fn pending() -> PendingSlices {
        PendingSlices::new(1024, Duration::from_secs(90))
    }

    #[test]
    fn a_newer_version_replaces_the_held_one() {
        let mut held = pending();
        let t0 = Instant::now();
        assert!(held.hold(&frame(key(1), 1), 1, t0), "a first frame is held");
        assert!(
            held.hold(&frame(key(1), 2), 2, t0),
            "a newer version is held"
        );
        assert_eq!(
            held.held_version(&key(1)),
            Some(2),
            "the held version is the newer one"
        );
        assert_eq!(held.len(), 1, "one key is held after a replacement");
    }

    #[test]
    fn an_older_or_equal_version_is_not_held() {
        let mut held = pending();
        let t0 = Instant::now();
        assert!(
            held.hold(&frame(key(1), 5), 5, t0),
            "the first version is held"
        );
        assert!(
            !held.hold(&frame(key(1), 4), 4, t0),
            "an older version is refused"
        );
        assert!(
            !held.hold(&frame(key(1), 5), 5, t0),
            "an equal version is refused"
        );
        assert_eq!(
            held.held_version(&key(1)),
            Some(5),
            "the held version stays at the first one"
        );
    }

    #[test]
    fn a_full_set_evicts_the_oldest_arrival_and_keeps_the_new_one() {
        let mut held = PendingSlices::new(2, Duration::from_secs(90));
        let t0 = Instant::now();
        assert!(held.hold(&frame(key(1), 1), 1, t0), "the first key is held");
        assert!(
            held.hold(&frame(key(2), 1), 1, t0),
            "the second key is held"
        );
        assert!(held.hold(&frame(key(3), 1), 1, t0), "the third key is held");
        assert_eq!(
            held.held_version(&key(1)),
            None,
            "the oldest key is evicted"
        );
        assert_eq!(held.held_version(&key(2)), Some(1), "the second key stays");
        assert_eq!(
            held.held_version(&key(3)),
            Some(1),
            "the newest key is held"
        );
    }

    #[test]
    fn an_entry_older_than_the_ttl_expires_and_a_fresh_one_stays() {
        let mut held = pending();
        let t0 = Instant::now();
        assert!(
            held.hold(&frame(key(1), 1), 1, t0),
            "the frame is held before its TTL"
        );
        held.expire(t0 + Duration::from_secs(60));
        assert_eq!(
            held.held_version(&key(1)),
            Some(1),
            "the frame is still held inside its TTL"
        );
        held.expire(t0 + Duration::from_secs(91));
        assert_eq!(
            held.held_version(&key(1)),
            None,
            "the frame is gone past its TTL"
        );
        assert!(held.is_empty(), "the set is empty after the TTL");
    }

    #[test]
    fn take_returns_the_held_frame_and_removes_it() {
        let mut held = pending();
        let t0 = Instant::now();
        assert!(held.hold(&frame(key(1), 3), 3, t0), "the frame is held");
        let taken = held.take(&key(1)).expect("the frame is held");
        assert_eq!(
            taken.key(),
            key(1),
            "take returns the key of the held frame"
        );
        assert_eq!(
            held.take(&key(1)).map(|_| ()),
            None,
            "a second take finds nothing"
        );
        assert!(held.is_empty(), "take leaves the set empty");
    }
}
