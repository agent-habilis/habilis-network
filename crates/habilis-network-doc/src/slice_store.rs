//! The slice store: one JSON slice per author key, on one channel.
//!
//! The store holds the slice of each author on one channel, `state` or `meta`. Only the author
//! raises the version of its own slice. The store knows keys and never nicknames.
//!
//! A slice is the signed frame of its author. Its body is the JSON object
//! `{"version": <u64>, "value": <JSON object or null>}`. A `null` value is a tombstone: the
//! author is gone, and its version is kept until the tombstone TTL ends. Then the key moves to
//! the gone set, and a slice of that key is refused until the gone TTL ends. On a passworded
//! mesh the body is sealed with the channel key, and the store opens it before it reads the
//! slice. The store takes the key from the frame and never from the body, so no frame writes
//! another author's slice.
//!
//! The version-vector sync (the digest round, `missing_for`) reads the held versions to find
//! what a peer lacks. Do not remove it when the store changes.

use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

use habilis_network_protocol::messages::Verified;
use habilis_network_protocol::{AuthorKey, Channel, ContentHash, MessageBody, SymmetricKey};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::wire;

/// The most gone keys one store holds. It matches the author cap, so the set holds a key for each
/// author the store can hold. An overflow evicts the oldest key early, which the engine roster gate
/// makes harmless: the roster refuses that author until it leaves.
const GONE_CAP: usize = 256;

/// The default time a key stays gone. The engine forgets a quiet author after `QUIET_TTL`, one hour,
/// so this is that time plus a margin: a forgotten key stays refused past the forget.
const DEFAULT_GONE_TTL: Duration = Duration::from_hours(2);

/// The bytes that a signed frame adds to its body. Measured at 406 to 414 bytes for a short mesh
/// name and nickname, with room for longer names.
const FRAME_OVERHEAD_BYTES: usize = 512;

/// The caps that bound a [`SliceStore`].
///
/// # Examples
///
/// ```
/// use habilis_network_doc::SliceLimits;
///
/// let limits = SliceLimits::default();
/// assert_eq!(limits.slice_bytes, 3 * 1024);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SliceLimits {
    /// The most bytes one signed slice frame can take.
    pub slice_bytes: usize,
    /// The least time between two writes of one author, after the burst.
    pub write_interval: Duration,
    /// The most authors one store holds.
    pub max_authors: usize,
    /// The writes one author can make at once.
    pub burst: u32,
    /// The time a tombstone keeps its author slot before the key goes to the gone set.
    pub tombstone_ttl: Duration,
    /// The time a key stays in the gone set, where its slices are refused.
    pub gone_ttl: Duration,
}

impl SliceLimits {
    /// Makes limits from the four caps, with the default tombstone and gone TTLs.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_doc::SliceLimits;
    /// use std::time::Duration;
    ///
    /// let limits = SliceLimits::new(1024, Duration::from_secs(2), 16, 4);
    /// assert_eq!(limits.max_authors, 16);
    /// ```
    #[must_use]
    pub fn new(
        slice_bytes: usize,
        write_interval: Duration,
        max_authors: usize,
        burst: u32,
    ) -> Self {
        Self {
            slice_bytes,
            write_interval,
            max_authors,
            burst,
            tombstone_ttl: Duration::from_mins(10),
            gone_ttl: DEFAULT_GONE_TTL,
        }
    }

    /// Sets the time a tombstone keeps its author slot.
    #[must_use]
    pub fn tombstone_ttl(mut self, ttl: Duration) -> Self {
        self.tombstone_ttl = ttl;
        self
    }

    /// Sets the time a key stays in the gone set.
    #[must_use]
    pub fn gone_ttl(mut self, ttl: Duration) -> Self {
        self.gone_ttl = ttl;
        self
    }
}

impl Default for SliceLimits {
    fn default() -> Self {
        Self::new(3 * 1024, Duration::from_secs(1), 256, 5)
    }
}

/// Why the store refused a write.
///
/// # Examples
///
/// ```
/// use habilis_network_doc::SliceError;
///
/// let error = SliceError::TooManyAuthors { limit: 256 };
/// assert_eq!(error.to_string(), "the store holds 256 authors already");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum SliceError {
    /// The frame does not parse, or its body is not `{"version", "value"}` with an object or
    /// `null` value, or its body is plain on a keyed store.
    Malformed,
    /// The frame is from another channel than the store serves.
    WrongChannel,
    /// The body is larger than the slice cap.
    TooLarge {
        /// The size of the body in bytes.
        bytes: usize,
        /// The cap in bytes.
        limit: usize,
    },
    /// The store holds the most authors it can, and the frame is from a new one.
    TooManyAuthors {
        /// The cap on authors.
        limit: usize,
    },
    /// The author sent new versions faster than its burst and rate allow.
    RateLimited,
    /// The key is in the gone set, so its slices are refused until the gone TTL ends.
    GoneKey,
    /// The draft is not the frame it claims: another key or channel signed it, or its body
    /// changed.
    DraftMismatch,
    /// The slice moved on after the draft was made, so the draft version is no longer next.
    StaleDraft,
    /// The body could not be sealed with the channel key.
    Seal,
}

impl fmt::Display for SliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "the frame is not a slice"),
            Self::WrongChannel => write!(f, "the frame is from another channel"),
            Self::TooLarge { bytes, limit } => {
                write!(f, "the body has {bytes} bytes, past the cap of {limit}")
            }
            Self::TooManyAuthors { limit } => {
                write!(f, "the store holds {limit} authors already")
            }
            Self::RateLimited => write!(f, "the author wrote too often"),
            Self::GoneKey => write!(f, "the author is gone"),
            Self::DraftMismatch => write!(f, "the frame is not the draft it claims"),
            Self::StaleDraft => write!(f, "the slice moved on after the draft"),
            Self::Seal => write!(f, "the body could not be sealed"),
        }
    }
}

impl Error for SliceError {}

/// What one [`SliceStore::ingest`] did with a frame.
///
/// # Examples
///
/// ```
/// use habilis_network_doc::SliceIngest;
///
/// assert_ne!(SliceIngest::Applied, SliceIngest::Stale);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SliceIngest {
    /// The frame replaced the held slice of its author, or filled an empty one.
    Applied,
    /// The held slice is this same frame.
    Duplicate,
    /// The held slice has a higher version than the frame.
    Stale,
    /// The frame has the version of the held slice and a higher hash, so the held slice wins.
    Conflict,
    /// The store refused the frame and kept nothing.
    Refused(SliceError),
}

/// A write of the own slice that [`SliceStore::prepare_local`] or
/// [`SliceStore::prepare_leave`] made, and [`SliceStore::commit_local`] still has to sign and keep.
///
/// # Examples
///
/// ```compile_fail
/// use habilis_network_doc::LocalDraft;
/// use habilis_network_protocol::{AuthorKey, Channel, MessageBody};
///
/// let _draft = LocalDraft {
///     channel: Channel::Meta,
///     key: AuthorKey::from([1; 32]),
///     version: 1,
///     body: MessageBody::from("{}"),
/// };
/// ```
#[derive(Debug)]
pub struct LocalDraft {
    channel: Channel,
    key: AuthorKey,
    version: u64,
    body: MessageBody,
}

impl LocalDraft {
    /// The version that the frame of this draft carries.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The body that the frame of this draft must carry, sealed when the channel has a key.
    #[must_use]
    pub fn body(&self) -> &MessageBody {
        &self.body
    }
}

/// The slices of one channel, keyed by author key.
///
/// # Examples
///
/// ```
/// use habilis_network_doc::{SliceLimits, SliceStore};
/// use habilis_network_protocol::Channel;
///
/// let store = SliceStore::new(Channel::Meta, SliceLimits::default());
/// assert_eq!(store.limits().max_authors, 256);
/// ```
#[derive(Debug)]
pub struct SliceStore {
    channel: Channel,
    key: Option<SymmetricKey>,
    limits: SliceLimits,
    slices: HashMap<AuthorKey, Slice>,
    buckets: HashMap<AuthorKey, Bucket>,
    /// The gone keys, oldest first, with the time each one left.
    gone: VecDeque<(AuthorKey, Instant)>,
}

/// One held slice: its signed frame, its version, the hash of the frame, its value, and the
/// time it was kept.
#[derive(Debug)]
struct Slice {
    frame: Verified,
    version: u64,
    hash: ContentHash,
    value: Value,
    since: Instant,
}

/// The write tokens of one author. A token refills once per write interval, up to the burst.
#[derive(Debug)]
struct Bucket {
    tokens: u32,
    refilled: Instant,
}

/// The body of a slice frame. An unknown key is an error, so a typo never passes silently.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SliceBody {
    version: u64,
    value: Value,
}

impl SliceStore {
    /// Makes an empty store for `channel` under `limits`.
    #[must_use]
    pub fn new(channel: Channel, limits: SliceLimits) -> Self {
        Self {
            channel,
            key: None,
            limits,
            slices: HashMap::new(),
            buckets: HashMap::new(),
            gone: VecDeque::new(),
        }
    }

    /// Sets the channel key of a passworded mesh. `None` keeps the bodies in plain JSON.
    #[must_use]
    pub fn with_key(mut self, key: Option<SymmetricKey>) -> Self {
        self.key = key;
        self
    }

    /// Returns the caps of this store.
    #[must_use]
    pub fn limits(&self) -> &SliceLimits {
        &self.limits
    }

    /// Returns the version held for `key`, or `None` when the store holds no slice of it.
    #[must_use]
    pub fn version(&self, key: &AuthorKey) -> Option<u64> {
        self.slices.get(key).map(|slice| slice.version)
    }

    /// Returns the signed frame held for `key`, which a resend or the digest sends.
    #[must_use]
    pub fn frame(&self, key: &AuthorKey) -> Option<&Verified> {
        self.slices.get(key).map(|slice| &slice.frame)
    }

    /// Returns the number of authors that have a slice in this store, tombstones included.
    #[must_use]
    pub fn authors(&self) -> usize {
        self.slices.len()
    }

    /// Returns the whole document as `{<lowercase hex author key>: value}`, without the gone
    /// authors.
    #[must_use]
    pub fn view(&self) -> Map<String, Value> {
        self.slices
            .iter()
            .filter(|(_, slice)| !slice.value.is_null())
            .map(|(key, slice)| {
                let hex = String::from_utf8_lossy(&key.hex()).into_owned();
                (hex, slice.value.clone())
            })
            .collect()
    }

    /// Takes a verified slice frame into the slice of its author, and says what it did.
    ///
    /// The key is the frame's author, so a frame only ever writes its own slice. A `live` frame
    /// that carries a new version spends one token of its author. A resend, with `live` false,
    /// never spends one.
    pub fn ingest(
        &mut self,
        frame: &Verified,
        // True for a live broadcast, false for a digest resend.
        live: bool,
        now: Instant,
    ) -> SliceIngest {
        if frame.kind != self.channel.event_kind() {
            return SliceIngest::Refused(SliceError::WrongChannel);
        }
        let Ok(signed) = frame.serialize() else {
            return SliceIngest::Refused(SliceError::Malformed);
        };
        if signed.len() > self.limits.slice_bytes {
            return SliceIngest::Refused(SliceError::TooLarge {
                bytes: signed.len(),
                limit: self.limits.slice_bytes,
            });
        }
        let Some(plain) = wire::decrypt_body(frame.body.as_str(), self.key.as_ref()) else {
            return SliceIngest::Refused(SliceError::Malformed);
        };
        let parsed: Result<SliceBody, _> = serde_json::from_str(&plain);
        let Ok(body) = parsed else {
            return SliceIngest::Refused(SliceError::Malformed);
        };
        if !(body.value.is_object() || body.value.is_null()) {
            return SliceIngest::Refused(SliceError::Malformed);
        }
        let key = frame.key();
        if self.is_gone(&key) {
            return SliceIngest::Refused(SliceError::GoneKey);
        }
        let hash = frame.content_hash();
        let is_new = match self.slices.get(&key) {
            None => true,
            Some(held) => match body.version.cmp(&held.version) {
                Ordering::Greater => true,
                Ordering::Less => return SliceIngest::Stale,
                Ordering::Equal if hash == held.hash => return SliceIngest::Duplicate,
                Ordering::Equal if hash < held.hash => false,
                Ordering::Equal => return SliceIngest::Conflict,
            },
        };
        if !self.slices.contains_key(&key) && self.slices.len() >= self.limits.max_authors {
            return SliceIngest::Refused(SliceError::TooManyAuthors {
                limit: self.limits.max_authors,
            });
        }
        if live && is_new && !self.take_token(&key, now) {
            return SliceIngest::Refused(SliceError::RateLimited);
        }
        let incoming = Slice {
            frame: frame.clone(),
            version: body.version,
            hash,
            value: body.value,
            since: now,
        };
        self.slices.insert(key, incoming);
        SliceIngest::Applied
    }

    /// Makes the draft of the next write of the own slice `own`, with `value` as its object.
    ///
    /// The draft carries the next version, and the body is sealed when the store has a key. The
    /// write takes one token of the rate limit, last, so a refused draft spends nothing.
    ///
    /// # Errors
    ///
    /// [`SliceError::Malformed`] when the body does not build, [`SliceError::Seal`] when the
    /// channel key does not seal it, [`SliceError::TooLarge`] when the body is past the cap, and
    /// [`SliceError::RateLimited`] when `own` has no token left.
    pub fn prepare_local(
        &mut self,
        own: &AuthorKey,
        value: Map<String, Value>,
        now: Instant,
    ) -> Result<LocalDraft, SliceError> {
        self.draft_at(own, Value::Object(value), now)
    }

    /// Makes the draft of the own tombstone of `own`, which a graceful leave sends.
    ///
    /// # Errors
    ///
    /// The same as [`SliceStore::prepare_local`].
    pub fn prepare_leave(
        &mut self,
        own: &AuthorKey,
        now: Instant,
    ) -> Result<LocalDraft, SliceError> {
        self.draft_at(own, Value::Null, now)
    }

    /// Keeps the signed `frame` of a draft, when the draft is for this channel and this key, its
    /// body is the draft body, and its version is still next.
    ///
    /// The frame is a write of the own author that the draft already paid for, so it never spends
    /// a token here.
    ///
    /// # Errors
    ///
    /// [`SliceError::DraftMismatch`] when the channel, the key or the body differ,
    /// [`SliceError::StaleDraft`] when the slice moved on, and the refusal of
    /// [`SliceStore::ingest`] for a frame past the cap.
    pub fn commit_local(
        &mut self,
        draft: LocalDraft,
        frame: &Verified,
        now: Instant,
    ) -> Result<(), SliceError> {
        let LocalDraft {
            channel,
            key,
            version,
            body,
        } = draft;
        if channel != self.channel || frame.key() != key || frame.body.as_str() != body.as_str() {
            return Err(SliceError::DraftMismatch);
        }
        if self.version(&key).unwrap_or(0) + 1 != version {
            return Err(SliceError::StaleDraft);
        }
        match self.ingest(frame, false, now) {
            SliceIngest::Applied => Ok(()),
            SliceIngest::Refused(error) => Err(error),
            SliceIngest::Duplicate | SliceIngest::Stale | SliceIngest::Conflict => {
                Err(SliceError::StaleDraft)
            }
        }
    }

    /// Moves each tombstone that has lasted its TTL to the gone set, and drops each gone key
    /// that has lasted the gone TTL.
    pub fn expire_tombstones(&mut self, now: Instant) {
        let ttl = self.limits.tombstone_ttl;
        let expired: Vec<AuthorKey> = self
            .slices
            .iter()
            .filter(|(_, slice)| {
                slice.value.is_null() && now.saturating_duration_since(slice.since) >= ttl
            })
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.slices.remove(&key);
            self.buckets.remove(&key);
            self.keep_gone(key, now);
        }
        let gone_ttl = self.limits.gone_ttl;
        while self
            .gone
            .front()
            .is_some_and(|(_, left)| now.saturating_duration_since(*left) >= gone_ttl)
        {
            self.gone.pop_front();
        }
    }

    /// Drops the slice and the bucket of `key`, and puts the key in the gone set.
    ///
    /// The engine calls it for an author that is in neither the live nor the quiet roster after
    /// `QUIET_TTL`, so a crashed author or a missed tombstone does not stay in the store.
    pub fn forget(&mut self, key: &AuthorKey, now: Instant) {
        self.slices.remove(key);
        self.buckets.remove(key);
        self.keep_gone(*key, now);
    }

    /// The number of author buckets, for the tests that check a refused key keeps none.
    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Builds the draft of `own` with `value`, then spends its token.
    fn draft_at(
        &mut self,
        own: &AuthorKey,
        value: Value,
        now: Instant,
    ) -> Result<LocalDraft, SliceError> {
        let version = self.version(own).unwrap_or(0) + 1;
        let mut body_json = json!({"version": version});
        body_json["value"] = value;
        let json = body_json.to_string();
        let plain = MessageBody::try_new(&json).map_err(|_| SliceError::Malformed)?;
        let body = match self.key.as_ref() {
            Some(key) => wire::encrypt_body(&plain, key).map_err(|_| SliceError::Seal)?,
            None => plain,
        };
        let bytes = body.as_str().len();
        let limit = self.limits.slice_bytes.saturating_sub(FRAME_OVERHEAD_BYTES);
        if bytes > limit {
            return Err(SliceError::TooLarge { bytes, limit });
        }
        if !self.take_token(own, now) {
            return Err(SliceError::RateLimited);
        }
        Ok(LocalDraft {
            channel: self.channel,
            key: *own,
            version,
            body,
        })
    }

    /// Whether `key` is in the gone set.
    fn is_gone(&self, key: &AuthorKey) -> bool {
        self.gone.iter().any(|(gone, _)| gone == key)
    }

    /// Adds `key` to the gone set, and drops the oldest gone key when the set is full.
    fn keep_gone(&mut self, key: AuthorKey, now: Instant) {
        if self.gone.len() >= GONE_CAP {
            self.gone.pop_front();
        }
        self.gone.push_back((key, now));
    }

    /// Takes one write token of `own` at `now`, after the tokens it earned since its last write.
    fn take_token(&mut self, own: &AuthorKey, now: Instant) -> bool {
        let burst = self.limits.burst;
        let interval = self.limits.write_interval;
        let bucket = self.buckets.entry(*own).or_insert(Bucket {
            tokens: burst,
            refilled: now,
        });
        let elapsed = now.saturating_duration_since(bucket.refilled);
        let earned = elapsed.as_nanos() / interval.as_nanos().max(1);
        let capped = earned.min(u128::from(burst));
        let add = u32::try_from(capped).unwrap_or(burst);
        bucket.tokens = bucket.tokens.saturating_add(add).min(burst);
        bucket.refilled = if bucket.tokens == burst {
            now
        } else {
            bucket.refilled + interval * add
        };
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FRAME_OVERHEAD_BYTES, LocalDraft, SliceError, SliceIngest, SliceLimits, SliceStore, wire,
    };
    use habilis_network_protocol::messages::Verified;
    use habilis_network_protocol::{
        AuthorKey, Channel, MeshId, Message, MessageBody, Nickname, SymmetricKey,
    };
    use serde_json::{Map, Value, json};
    use std::time::{Duration, Instant};

    fn key(byte: u8) -> AuthorKey {
        AuthorKey::from([byte; 32])
    }

    /// A key that differs for each `index`, for the tests that need many authors.
    fn many_key(index: usize) -> AuthorKey {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&index.to_be_bytes());
        AuthorKey::from(bytes)
    }

    /// A frame of `key` with `version` and `value`, carrying the slice body.
    fn frame(key: AuthorKey, version: u64, value: Value) -> Verified {
        let mut body = json!({"version": version});
        body["value"] = value;
        frame_with_body(key, &body.to_string())
    }

    /// A frame of `key` whose body is `body` as written, on the meta channel.
    fn frame_with_body(key: AuthorKey, body: &str) -> Verified {
        frame_on(key, body, Channel::Meta)
    }

    /// A frame of `key` whose body is `body` as written, on `channel`.
    fn frame_on(key: AuthorKey, body: &str, channel: Channel) -> Verified {
        Verified::fixture_unchecked(
            Message::new_channel_event(
                &MeshId::from("test"),
                &Nickname::from("peer"),
                MessageBody::from(body),
                channel,
            ),
            key,
        )
    }

    /// Makes the frame of `draft`, signed by `key`, with the draft body.
    fn frame_of(draft: &LocalDraft, key: AuthorKey) -> Verified {
        frame_with_body(key, draft.body().as_str())
    }

    fn store() -> SliceStore {
        SliceStore::new(Channel::Meta, SliceLimits::default())
    }

    fn small_store(limits: SliceLimits) -> SliceStore {
        SliceStore::new(Channel::Meta, limits)
    }

    fn object(value: Value) -> Map<String, Value> {
        if let Value::Object(map) = value {
            map
        } else {
            Map::new()
        }
    }

    /// Applies `frame` on the resend path, which never spends a token.
    fn apply(store: &mut SliceStore, frame: &Verified) -> SliceIngest {
        store.ingest(frame, false, Instant::now())
    }

    #[test]
    fn ingest_applies_a_new_slice_under_the_frame_key() {
        let mut store = store();
        assert_eq!(
            apply(&mut store, &frame(key(1), 1, json!({"a": 1}))),
            SliceIngest::Applied,
            "a new author slice must apply"
        );
        assert_eq!(
            store.version(&key(1)),
            Some(1),
            "the slice must sit under the frame key"
        );
        assert_eq!(
            store.version(&key(2)),
            None,
            "no other author slice may change"
        );
    }

    #[test]
    fn ingest_replaces_a_held_slice_with_a_higher_version() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        assert_eq!(
            apply(&mut store, &frame(key(1), 2, json!({"a": 2}))),
            SliceIngest::Applied,
            "a higher version must replace the held slice"
        );
        assert_eq!(
            store.version(&key(1)),
            Some(2),
            "the held version must be 2"
        );
    }

    #[test]
    fn ingest_refuses_a_lower_version_as_stale() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 2, json!({"a": 2})));
        assert_eq!(
            apply(&mut store, &frame(key(1), 1, json!({"a": 1}))),
            SliceIngest::Stale,
            "a lower version must be stale"
        );
        assert_eq!(
            store.version(&key(1)),
            Some(2),
            "the version must not go down"
        );
    }

    #[test]
    fn ingest_reports_the_same_frame_as_a_duplicate() {
        let mut store = store();
        let first = frame(key(1), 1, json!({"a": 1}));
        apply(&mut store, &first);
        assert_eq!(
            apply(&mut store, &first.clone()),
            SliceIngest::Duplicate,
            "the same frame must be a duplicate"
        );
    }

    #[test]
    fn ingest_breaks_a_version_tie_by_the_lower_hash() {
        let mut store = store();
        let one = frame(key(1), 1, json!({"a": 1}));
        let other = frame(key(1), 1, json!({"a": 2}));
        let hash = |signed: &Verified| signed.content_hash();
        apply(&mut store, &one);
        let outcome = apply(&mut store, &other);
        let expected = if hash(&other) < hash(&one) {
            SliceIngest::Applied
        } else {
            SliceIngest::Conflict
        };
        assert_eq!(outcome, expected, "the lower hash must win the version tie");
    }

    #[test]
    fn ingest_refuses_a_frame_past_the_slice_cap_and_keeps_nothing() {
        let limits = SliceLimits::new(64, Duration::from_secs(1), 256, 5);
        let mut store = small_store(limits);
        let big = frame(key(1), 1, json!({"blob": "x".repeat(200)}));
        assert!(
            matches!(
                apply(&mut store, &big),
                SliceIngest::Refused(SliceError::TooLarge { limit: 64, .. })
            ),
            "a frame past the cap must be refused as too large"
        );
        assert_eq!(
            store.version(&key(1)),
            None,
            "a refused frame must leave no slice"
        );
        assert_eq!(store.authors(), 0, "a refused frame must leave no author");
    }

    #[test]
    fn ingest_refuses_a_body_that_is_not_a_slice() {
        let mut store = store();
        assert_eq!(
            apply(&mut store, &frame_with_body(key(1), "not json")),
            SliceIngest::Refused(SliceError::Malformed),
            "a body that is not JSON must be malformed"
        );
        assert_eq!(store.authors(), 0, "a malformed body must leave no author");
    }

    #[test]
    fn ingest_refuses_a_value_that_is_not_an_object() {
        let mut store = store();
        assert_eq!(
            apply(&mut store, &frame(key(1), 1, json!(3))),
            SliceIngest::Refused(SliceError::Malformed),
            "a value that is a number must be malformed"
        );
        assert_eq!(store.authors(), 0, "a malformed value must leave no author");
    }

    #[test]
    fn ingest_refuses_a_new_author_past_the_author_cap() {
        let limits = SliceLimits::new(3072, Duration::from_secs(1), 1, 5);
        let mut store = small_store(limits);
        apply(&mut store, &frame(key(1), 1, json!({})));
        assert_eq!(
            apply(&mut store, &frame(key(2), 1, json!({}))),
            SliceIngest::Refused(SliceError::TooManyAuthors { limit: 1 }),
            "a new author past the cap must be refused"
        );
        assert_eq!(store.authors(), 1, "the refused author must leave no slice");
    }

    #[test]
    fn ingest_refuses_a_frame_of_another_channel() {
        let mut store = store();
        let state_frame = frame_on(key(1), r#"{"version":1,"value":{}}"#, Channel::State);
        assert_eq!(
            apply(&mut store, &state_frame),
            SliceIngest::Refused(SliceError::WrongChannel),
            "a state frame must not write a meta slice"
        );
        assert_eq!(store.authors(), 0, "a refused channel must leave no author");
    }

    #[test]
    fn ingest_opens_a_sealed_body_with_the_channel_key() {
        let channel_key = SymmetricKey::from([3u8; 32]);
        let plain = MessageBody::from(r#"{"version":1,"value":{"a":1}}"#);
        let sealed = wire::encrypt_body(&plain, &channel_key).expect("a sealed body");
        let mut store = store().with_key(Some(SymmetricKey::from([3u8; 32])));
        assert_eq!(
            apply(&mut store, &frame_with_body(key(1), sealed.as_str())),
            SliceIngest::Applied,
            "a body sealed with the channel key must apply"
        );
        assert_eq!(
            store.version(&key(1)),
            Some(1),
            "the opened slice must hold version 1"
        );
    }

    #[test]
    fn ingest_refuses_a_sealed_body_under_another_key() {
        let plain = MessageBody::from(r#"{"version":1,"value":{"a":1}}"#);
        let sealed = wire::encrypt_body(&plain, &SymmetricKey::from([3u8; 32])).expect("sealed");
        let mut store = store().with_key(Some(SymmetricKey::from([4u8; 32])));
        assert_eq!(
            apply(&mut store, &frame_with_body(key(1), sealed.as_str())),
            SliceIngest::Refused(SliceError::Malformed),
            "a body sealed under another key must be malformed"
        );
        assert_eq!(store.authors(), 0, "an unopened body must leave no author");
    }

    #[test]
    fn ingest_refuses_a_plain_body_on_a_keyed_store() {
        let mut store = store().with_key(Some(SymmetricKey::from([3u8; 32])));
        assert_eq!(
            apply(&mut store, &frame(key(1), 1, json!({"a": 1}))),
            SliceIngest::Refused(SliceError::Malformed),
            "a plain body on a keyed store must be malformed"
        );
        assert_eq!(store.authors(), 0, "a plain body must leave no author");
    }

    #[test]
    fn ingest_keeps_a_null_value_as_a_tombstone_that_view_leaves_out() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        assert_eq!(
            apply(&mut store, &frame(key(1), 2, Value::Null)),
            SliceIngest::Applied,
            "a null value at a higher version must apply as a tombstone"
        );
        assert_eq!(
            store.version(&key(1)),
            Some(2),
            "the tombstone must keep its version"
        );
        assert!(store.view().is_empty(), "view must leave out a gone author");
    }

    #[test]
    fn view_maps_each_author_hex_to_its_value() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        let raw = key(1).hex();
        let hex = String::from_utf8_lossy(&raw).into_owned();
        let view = store.view();
        assert_eq!(view.len(), 1, "view must hold one entry per live author");
        assert_eq!(
            view.get(&hex),
            Some(&json!({"a": 1})),
            "view must map the hex key to the value"
        );
    }

    #[test]
    fn prepare_local_bumps_the_version_by_one() {
        let mut store = store();
        let now = Instant::now();
        let first: LocalDraft = store
            .prepare_local(&key(1), object(json!({"a": 1})), now)
            .expect("a first draft");
        assert_eq!(first.version(), 1, "the first draft must be version 1");
        let frame = frame_of(&first, key(1));
        store
            .commit_local(first, &frame, now)
            .expect("the first draft commits");
        let second: LocalDraft = store
            .prepare_local(&key(1), object(json!({"a": 2})), now)
            .expect("a second draft");
        assert_eq!(second.version(), 2, "the next draft must be version 2");
    }

    #[test]
    fn prepare_local_refuses_the_sixth_write_inside_the_burst() {
        let mut store = store();
        let now = Instant::now();
        for _ in 0..5 {
            assert!(
                store.prepare_local(&key(1), Map::new(), now).is_ok(),
                "the first five writes fit the burst of 5"
            );
        }
        assert!(
            matches!(
                store.prepare_local(&key(1), Map::new(), now),
                Err(SliceError::RateLimited)
            ),
            "the sixth write inside the burst must be rate limited"
        );
    }

    #[test]
    fn prepare_local_refused_for_size_spends_no_token() {
        let limits = SliceLimits::new(64 + FRAME_OVERHEAD_BYTES, Duration::from_secs(1), 256, 1);
        let mut store = small_store(limits);
        let now = Instant::now();
        let blob = json!({"blob": "x".repeat(200)});
        assert!(
            matches!(
                store.prepare_local(&key(1), object(blob), now),
                Err(SliceError::TooLarge { limit: 64, .. })
            ),
            "a body past the cap must be refused as too large"
        );
        assert!(
            store.prepare_local(&key(1), Map::new(), now).is_ok(),
            "a refused draft must not spend the only token"
        );
    }

    #[test]
    fn commit_local_refuses_a_frame_past_the_cap() {
        let now = Instant::now();
        let mut source = small_store(SliceLimits::new(4096, Duration::from_secs(1), 256, 5));
        let draft = source
            .prepare_local(&key(1), object(json!({"a": "x".repeat(300)})), now)
            .expect("a draft");
        let frame = frame_of(&draft, key(1));
        let mut store = small_store(SliceLimits::new(576, Duration::from_secs(1), 256, 5));
        assert!(
            matches!(
                store.commit_local(draft, &frame, now),
                Err(SliceError::TooLarge { limit: 576, .. })
            ),
            "a frame past the cap must be refused as too large, even when its draft fit"
        );
        assert_eq!(store.authors(), 0, "a refused frame must leave no slice");
    }

    #[test]
    fn live_new_key_on_a_full_store_is_refused_and_keeps_no_bucket() {
        let mut store = small_store(SliceLimits::new(3072, Duration::from_secs(1), 1, 5));
        apply(&mut store, &frame(key(1), 1, json!({})));
        assert_eq!(
            store.ingest(&frame(key(2), 1, json!({})), true, Instant::now()),
            SliceIngest::Refused(SliceError::TooManyAuthors { limit: 1 }),
            "a live new key on a full store must be refused"
        );
        assert_eq!(
            store.bucket_count(),
            0,
            "a refused key must leave no bucket"
        );
    }

    #[test]
    fn a_gone_key_is_refused_before_a_full_store() {
        let limits =
            SliceLimits::new(3072, Duration::from_secs(1), 2, 5).tombstone_ttl(Duration::ZERO);
        let mut store = small_store(limits);
        let start = Instant::now();
        store.ingest(&frame(key(1), 1, json!({})), false, start);
        store.ingest(&frame(key(2), 1, json!({})), false, start);
        store.ingest(&frame(key(2), 2, Value::Null), false, start);
        store.expire_tombstones(start);
        assert_eq!(
            store.ingest(&frame(key(3), 1, json!({})), false, start),
            SliceIngest::Applied,
            "a freed slot must take a new author"
        );
        assert_eq!(
            store.ingest(&frame(key(2), 3, json!({})), true, start),
            SliceIngest::Refused(SliceError::GoneKey),
            "a gone key must be refused before the store is found full"
        );
        assert_eq!(
            store.ingest(&frame(key(4), 1, json!({})), true, start),
            SliceIngest::Refused(SliceError::TooManyAuthors { limit: 2 }),
            "a new key on a full store must be refused"
        );
    }

    #[test]
    fn forget_removes_the_slice_and_the_bucket_and_refuses_the_key() {
        let mut store = store();
        let now = Instant::now();
        store.ingest(&frame(key(1), 1, json!({})), true, now);
        assert_eq!(store.bucket_count(), 1, "a live write must keep a bucket");
        store.forget(&key(1), now);
        assert_eq!(store.authors(), 0, "forget must remove the slice");
        assert_eq!(store.bucket_count(), 0, "forget must remove the bucket");
        assert_eq!(
            apply(&mut store, &frame(key(1), 2, json!({}))),
            SliceIngest::Refused(SliceError::GoneKey),
            "a forgotten key must be refused"
        );
    }

    #[test]
    fn a_forgotten_key_is_accepted_again_after_the_gone_ttl() {
        let mut store = store();
        let start = Instant::now();
        store.forget(&key(1), start);
        store.expire_tombstones(start + Duration::from_mins(119));
        assert_eq!(
            apply(&mut store, &frame(key(1), 1, json!({}))),
            SliceIngest::Refused(SliceError::GoneKey),
            "a forgotten key must stay refused before the gone TTL ends"
        );
        store.expire_tombstones(start + Duration::from_hours(2));
        assert_eq!(
            apply(&mut store, &frame(key(1), 1, json!({}))),
            SliceIngest::Applied,
            "a forgotten key must be accepted after the gone TTL ends"
        );
    }

    #[test]
    fn prepare_local_checks_the_body_limit_that_leaves_room_for_the_frame() {
        let limits = SliceLimits::new(3072, Duration::from_secs(1), 256, 1);
        let now = Instant::now();
        let probe = small_store(limits)
            .prepare_local(&key(1), object(json!({"blob": ""})), now)
            .expect("a probe draft");
        let empty = probe.body().as_str().len();
        let body_limit = 3072 - FRAME_OVERHEAD_BYTES;
        let under = json!({"blob": "x".repeat(body_limit - 1 - empty)});
        let mut store = small_store(limits);
        let draft: LocalDraft = store
            .prepare_local(&key(1), object(under), now)
            .expect("a body just under the limit must draft");
        let frame = frame_of(&draft, key(1));
        store
            .commit_local(draft, &frame, now)
            .expect("a body just under the limit must commit");
        let over = json!({"blob": "x".repeat(body_limit + 1 - empty)});
        let mut fresh = small_store(limits);
        assert!(
            matches!(
                fresh.prepare_local(&key(1), object(over), now),
                Err(SliceError::TooLarge { limit, .. }) if limit == body_limit
            ),
            "a body just over the limit must be refused in prepare_local"
        );
        assert!(
            fresh.prepare_local(&key(1), Map::new(), now).is_ok(),
            "the refused body must not spend the only token"
        );
    }

    #[test]
    fn commit_local_refuses_a_stale_draft() {
        let mut store = store();
        let now = Instant::now();
        let first: LocalDraft = store
            .prepare_local(&key(1), Map::new(), now)
            .expect("a draft");
        let second: LocalDraft = store
            .prepare_local(&key(1), Map::new(), now)
            .expect("a draft");
        let first_frame = frame_of(&first, key(1));
        let second_frame = frame_of(&second, key(1));
        store
            .commit_local(first, &first_frame, now)
            .expect("the first draft commits");
        assert!(
            matches!(
                store.commit_local(second, &second_frame, now),
                Err(SliceError::StaleDraft)
            ),
            "a draft made before the held version moved on must be stale"
        );
        assert_eq!(
            store.version(&key(1)),
            Some(1),
            "the stale draft must not move the version"
        );
    }

    #[test]
    fn commit_local_refuses_a_frame_signed_by_another_key() {
        let mut store = store();
        let draft: LocalDraft = store
            .prepare_local(&key(1), Map::new(), Instant::now())
            .expect("a draft");
        let frame = frame_of(&draft, key(2));
        assert!(
            matches!(
                store.commit_local(draft, &frame, Instant::now()),
                Err(SliceError::DraftMismatch)
            ),
            "a frame signed by another key must not commit the draft"
        );
        assert_eq!(store.authors(), 0, "a refused frame must leave no slice");
    }

    #[test]
    fn commit_local_refuses_a_draft_of_another_channel() {
        let mut meta = store();
        let mut state = SliceStore::new(Channel::State, SliceLimits::default());
        let now = Instant::now();
        let draft: LocalDraft = meta
            .prepare_local(&key(1), Map::new(), now)
            .expect("a draft");
        let frame = frame_of(&draft, key(1));
        assert!(
            matches!(
                state.commit_local(draft, &frame, now),
                Err(SliceError::DraftMismatch)
            ),
            "a draft of the meta channel must not commit on the state channel"
        );
        assert_eq!(state.authors(), 0, "a refused draft must leave no slice");
    }

    #[test]
    fn prepare_leave_writes_a_tombstone_at_the_next_version() {
        let mut store = store();
        let now = Instant::now();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        let leave: LocalDraft = store.prepare_leave(&key(1), now).expect("a leave draft");
        assert_eq!(leave.version(), 2, "the leave must be the next version");
        let leave_frame = frame_of(&leave, key(1));
        store
            .commit_local(leave, &leave_frame, now)
            .expect("the leave commits");
        assert_eq!(
            store.version(&key(1)),
            Some(2),
            "the held version must be the leave version"
        );
        assert_eq!(
            apply(&mut store, &frame(key(1), 1, json!({"a": 1}))),
            SliceIngest::Stale,
            "a returning older slice must be stale after the leave"
        );
    }

    #[test]
    fn expire_tombstones_frees_the_author_slot_after_the_ttl() {
        let mut store = store();
        let start = Instant::now();
        store.ingest(&frame(key(1), 1, json!({"a": 1})), false, start);
        store.ingest(&frame(key(1), 2, Value::Null), false, start);
        store.expire_tombstones(start + Duration::from_mins(9));
        assert_eq!(
            store.authors(),
            1,
            "a tombstone must keep its slot before the TTL"
        );
        store.expire_tombstones(start + Duration::from_mins(10));
        assert_eq!(
            store.authors(),
            0,
            "an expired tombstone must free its author slot"
        );
    }

    #[test]
    fn ingest_refuses_a_slice_of_a_gone_key() {
        let mut store = store();
        let start = Instant::now();
        store.ingest(&frame(key(1), 1, json!({"a": 1})), false, start);
        store.ingest(&frame(key(1), 2, Value::Null), false, start);
        store.expire_tombstones(start + Duration::from_mins(10));
        assert_eq!(
            apply(&mut store, &frame(key(1), 3, json!({"a": 3}))),
            SliceIngest::Refused(SliceError::GoneKey),
            "a gone key must be refused until the gone TTL ends"
        );
        assert_eq!(store.authors(), 0, "a refused gone key must leave no slice");
    }

    #[test]
    fn gone_set_keeps_its_cap_and_the_oldest_leaves_first() {
        let limits =
            SliceLimits::new(3072, Duration::from_secs(1), 300, 5).tombstone_ttl(Duration::ZERO);
        let mut store = small_store(limits);
        let start = Instant::now();
        for index in 1..=257 {
            let at = start + Duration::from_millis(u64::try_from(index).unwrap_or(0));
            store.ingest(&frame(many_key(index), 1, json!({})), false, at);
            store.ingest(&frame(many_key(index), 2, Value::Null), false, at);
            store.expire_tombstones(at);
        }
        assert_eq!(
            apply(&mut store, &frame(many_key(1), 3, json!({"a": 3}))),
            SliceIngest::Applied,
            "the oldest gone key must leave the gone set when the set is full"
        );
        assert_eq!(
            apply(&mut store, &frame(many_key(257), 3, json!({"a": 3}))),
            SliceIngest::Refused(SliceError::GoneKey),
            "the newest gone key must stay in the gone set"
        );
    }

    #[test]
    fn ingest_live_refuses_the_sixth_new_version_inside_the_burst() {
        let mut store = store();
        let now = Instant::now();
        for version in 1..=5 {
            assert_eq!(
                store.ingest(&frame(key(1), version, json!({})), true, now),
                SliceIngest::Applied,
                "the first five live versions fit the burst of 5"
            );
        }
        assert_eq!(
            store.ingest(&frame(key(1), 6, json!({})), true, now),
            SliceIngest::Refused(SliceError::RateLimited),
            "the sixth live new version inside the burst must be rate limited"
        );
    }

    #[test]
    fn ingest_resend_never_spends_a_token() {
        let mut store = store();
        let now = Instant::now();
        for version in 1..=7 {
            assert_eq!(
                store.ingest(&frame(key(1), version, json!({})), false, now),
                SliceIngest::Applied,
                "a resend of a new version must never spend a token"
            );
        }
    }
}
