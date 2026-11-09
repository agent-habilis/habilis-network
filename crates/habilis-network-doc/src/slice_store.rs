//! The slice store: one JSON slice per author key, on one channel.
//!
//! The store holds the slice of each author on one channel, `state` or `meta`. Only the author
//! raises the version of its own slice. The store knows keys and never nicknames.
//!
//! A slice is the signed frame of its author. Its body is the JSON object
//! `{"version": <u64>, "value": <JSON object or null>}`. A `null` value is a tombstone: the
//! author is gone, and its version is kept. On a passworded mesh the body is sealed with the
//! channel key, and the store opens it before it reads the slice. The store takes the key from
//! the frame and never from the body, so no frame writes another author's slice.
//!
//! The version-vector sync (the digest round, `missing_for`) reads the held versions to find
//! what a peer lacks. Do not remove it when the store changes.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

use habilis_network_protocol::messages::Verified;
use habilis_network_protocol::{
    AuthorKey, Channel, ContentHash, MeshId, Message, MessageBody, MessageKind, Nickname,
    SymmetricKey,
};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::wire;

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
}

impl SliceLimits {
    /// Makes limits from all four caps.
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
        }
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
    /// `null` value.
    Malformed,
    /// The frame is from another channel than the store serves.
    WrongChannel,
    /// The signed frame is larger than the slice cap.
    TooLarge {
        /// The size of the frame in bytes.
        bytes: usize,
        /// The cap in bytes.
        limit: usize,
    },
    /// The store holds the most authors it can, and the frame is from a new one.
    TooManyAuthors {
        /// The cap on authors.
        limit: usize,
    },
    /// The author wrote more often than its burst and rate allow.
    RateLimited,
    /// The frame is not the draft it claims: another key signed it, or its body changed.
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
                write!(f, "the frame has {bytes} bytes, past the cap of {limit}")
            }
            Self::TooManyAuthors { limit } => {
                write!(f, "the store holds {limit} authors already")
            }
            Self::RateLimited => write!(f, "the author wrote too often"),
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

/// A write of the own slice that [`SliceStore::prepare_local`] made and
/// [`SliceStore::commit_local`] still has to sign and keep.
///
/// # Examples
///
/// ```compile_fail
/// use habilis_network_doc::LocalDraft;
/// use habilis_network_protocol::{AuthorKey, MessageBody};
///
/// let _draft = LocalDraft {
///     key: AuthorKey::from([1; 32]),
///     version: 1,
///     body: MessageBody::from("{}"),
/// };
/// ```
#[derive(Debug)]
pub struct LocalDraft {
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
}

/// One held slice: its signed frame, its version, the hash of the frame, and its value.
#[derive(Debug)]
struct Slice {
    frame: Verified,
    version: u64,
    hash: ContentHash,
    value: Value,
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
    /// The key is the frame's author, so a frame only ever writes its own slice.
    pub fn ingest(&mut self, frame: &Verified) -> SliceIngest {
        if frame.kind != self.channel_kind() {
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
        let incoming = Slice {
            frame: frame.clone(),
            version: body.version,
            hash: frame.content_hash(),
            value: body.value,
        };
        self.place(frame.key(), incoming)
    }

    /// Makes the draft of the next write of the own slice `own`, with `value` as its object.
    ///
    /// The write takes one token of the rate limit. The draft carries the next version, and the
    /// body is sealed when the store has a key.
    ///
    /// # Errors
    ///
    /// [`SliceError::RateLimited`] when `own` has no token left, [`SliceError::Malformed`] when the
    /// body does not build, and [`SliceError::Seal`] when the channel key does not seal it.
    pub fn prepare_local(
        &mut self,
        own: &AuthorKey,
        value: Map<String, Value>,
        now: Instant,
    ) -> Result<LocalDraft, SliceError> {
        if !self.take_token(own, now) {
            return Err(SliceError::RateLimited);
        }
        let version = self.version(own).unwrap_or(0) + 1;
        let json = Value::Object(Map::from_iter([
            ("version".to_owned(), Value::from(version)),
            ("value".to_owned(), Value::Object(value)),
        ]))
        .to_string();
        let plain = MessageBody::try_new(&json).map_err(|_| SliceError::Malformed)?;
        let body = match self.key.as_ref() {
            Some(key) => wire::encrypt_body(&plain, key).map_err(|_| SliceError::Seal)?,
            None => plain,
        };
        Ok(LocalDraft {
            key: *own,
            version,
            body,
        })
    }

    /// Keeps the signed `frame` of a draft, when it carries the draft body and the draft version
    /// is still next.
    ///
    /// # Errors
    ///
    /// [`SliceError::DraftMismatch`] when another key signed the frame or its body differs,
    /// [`SliceError::StaleDraft`] when the slice moved on, and the refusal of
    /// [`SliceStore::ingest`] for a frame past the cap.
    pub fn commit_local(&mut self, draft: LocalDraft, frame: &Verified) -> Result<(), SliceError> {
        let LocalDraft { key, version, body } = draft;
        if frame.key() != key || frame.body.as_str() != body.as_str() {
            return Err(SliceError::DraftMismatch);
        }
        if self.version(&key).unwrap_or(0) + 1 != version {
            return Err(SliceError::StaleDraft);
        }
        match self.ingest(frame) {
            SliceIngest::Applied => Ok(()),
            SliceIngest::Refused(error) => Err(error),
            SliceIngest::Duplicate | SliceIngest::Stale | SliceIngest::Conflict => {
                Err(SliceError::StaleDraft)
            }
        }
    }

    /// The message kind of the channel this store serves.
    fn channel_kind(&self) -> MessageKind {
        Message::new_channel_event(
            &MeshId::from("slice-store"),
            &Nickname::from("slice-store"),
            MessageBody::from("{}"),
            self.channel,
        )
        .kind
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

    /// Keeps `incoming` as the slice of `key` when it wins the version and hash rules.
    fn place(&mut self, key: AuthorKey, incoming: Slice) -> SliceIngest {
        let Some(held) = self.slices.get(&key) else {
            if self.slices.len() >= self.limits.max_authors {
                return SliceIngest::Refused(SliceError::TooManyAuthors {
                    limit: self.limits.max_authors,
                });
            }
            self.slices.insert(key, incoming);
            return SliceIngest::Applied;
        };
        let wins = match incoming.version.cmp(&held.version) {
            Ordering::Greater => true,
            Ordering::Less => return SliceIngest::Stale,
            Ordering::Equal if incoming.hash == held.hash => return SliceIngest::Duplicate,
            Ordering::Equal => incoming.hash < held.hash,
        };
        if !wins {
            return SliceIngest::Conflict;
        }
        self.slices.insert(key, incoming);
        SliceIngest::Applied
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalDraft, SliceError, SliceIngest, SliceLimits, SliceStore, wire};
    use habilis_network_protocol::messages::Verified;
    use habilis_network_protocol::{
        AuthorKey, Channel, MeshId, Message, MessageBody, Nickname, SymmetricKey,
    };
    use serde_json::{Map, Value, json};
    use std::time::{Duration, Instant};

    fn key(byte: u8) -> AuthorKey {
        AuthorKey::from([byte; 32])
    }

    /// A frame of `key` with `version` and `value`, carrying the slice body.
    fn frame(key: AuthorKey, version: u64, value: Value) -> Verified {
        let body = Value::Object(Map::from_iter([
            ("version".to_owned(), json!(version)),
            ("value".to_owned(), value),
        ]));
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

    fn store() -> SliceStore {
        SliceStore::new(Channel::Meta, SliceLimits::default())
    }

    fn small_store(limits: SliceLimits) -> SliceStore {
        SliceStore::new(Channel::Meta, limits)
    }

    fn object(pairs: Value) -> Map<String, Value> {
        if let Value::Object(map) = pairs {
            map
        } else {
            Map::new()
        }
    }

    /// Makes the frame of `draft`, signed by `key`, with the draft body.
    fn frame_of(draft: &LocalDraft, key: AuthorKey) -> Verified {
        frame_with_body(key, draft.body().as_str())
    }

    #[test]
    fn ingest_applies_a_new_slice_under_the_frame_key() {
        let mut store = store();
        assert_eq!(
            store.ingest(&frame(key(1), 1, json!({"a": 1}))),
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
        store.ingest(&frame(key(1), 1, json!({"a": 1})));
        assert_eq!(
            store.ingest(&frame(key(1), 2, json!({"a": 2}))),
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
        store.ingest(&frame(key(1), 2, json!({"a": 2})));
        assert_eq!(
            store.ingest(&frame(key(1), 1, json!({"a": 1}))),
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
        store.ingest(&first);
        assert_eq!(
            store.ingest(&first.clone()),
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
        store.ingest(&one);
        let outcome = store.ingest(&other);
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
                store.ingest(&big),
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
            store.ingest(&frame_with_body(key(1), "not json")),
            SliceIngest::Refused(SliceError::Malformed),
            "a body that is not JSON must be malformed"
        );
        assert_eq!(store.authors(), 0, "a malformed body must leave no author");
    }

    #[test]
    fn ingest_refuses_a_value_that_is_not_an_object() {
        let mut store = store();
        assert_eq!(
            store.ingest(&frame(key(1), 1, json!(3))),
            SliceIngest::Refused(SliceError::Malformed),
            "a value that is a number must be malformed"
        );
        assert_eq!(store.authors(), 0, "a malformed value must leave no author");
    }

    #[test]
    fn ingest_refuses_a_new_author_past_the_author_cap() {
        let limits = SliceLimits::new(3072, Duration::from_secs(1), 1, 5);
        let mut store = small_store(limits);
        store.ingest(&frame(key(1), 1, json!({})));
        assert_eq!(
            store.ingest(&frame(key(2), 1, json!({}))),
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
            store.ingest(&state_frame),
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
            store.ingest(&frame_with_body(key(1), sealed.as_str())),
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
            store.ingest(&frame_with_body(key(1), sealed.as_str())),
            SliceIngest::Refused(SliceError::Malformed),
            "a body sealed under another key must be malformed"
        );
        assert_eq!(store.authors(), 0, "an unopened body must leave no author");
    }

    #[test]
    fn ingest_keeps_a_null_value_as_a_tombstone_that_view_leaves_out() {
        let mut store = store();
        store.ingest(&frame(key(1), 1, json!({"a": 1})));
        assert_eq!(
            store.ingest(&frame(key(1), 2, Value::Null)),
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
        store.ingest(&frame(key(1), 1, json!({"a": 1})));
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
            .commit_local(first, &frame)
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
    fn commit_local_refuses_a_draft_too_large_and_keeps_nothing() {
        let limits = SliceLimits::new(64, Duration::from_secs(1), 256, 5);
        let mut store = small_store(limits);
        let blob = json!({"blob": "x".repeat(200)});
        let draft: LocalDraft = store
            .prepare_local(&key(1), object(blob), Instant::now())
            .expect("a draft");
        let frame = frame_of(&draft, key(1));
        assert!(
            matches!(
                store.commit_local(draft, &frame),
                Err(SliceError::TooLarge { limit: 64, .. })
            ),
            "a draft past the cap must be refused as too large"
        );
        assert_eq!(store.authors(), 0, "a refused draft must leave no slice");
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
            .commit_local(first, &first_frame)
            .expect("the first draft commits");
        assert!(
            matches!(
                store.commit_local(second, &second_frame),
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
                store.commit_local(draft, &frame),
                Err(SliceError::DraftMismatch)
            ),
            "a frame signed by another key must not commit the draft"
        );
        assert_eq!(store.authors(), 0, "a refused frame must leave no slice");
    }
}
