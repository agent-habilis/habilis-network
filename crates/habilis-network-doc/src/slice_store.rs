//! The slice store: one JSON slice per author key.
//!
//! The store holds the slice of each author. Only the author raises the version of its own
//! slice. The store knows keys and never nicknames.
//!
//! A slice is the signed frame of its author. Its body is the JSON object
//! `{"version": <u64>, "value": <JSON object>}`. The store reads the key from the frame and
//! never from the body, so no frame writes another author's slice.
//!
//! The version-vector sync (the digest round, `missing_for`) reads the held versions to find
//! what a peer lacks. Do not remove it when the store changes.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::time::Duration;

use habilis_network_protocol::messages::Verified;
use habilis_network_protocol::{AuthorKey, ContentHash};
use serde::Deserialize;

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

/// Why the store refused a frame.
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
pub enum SliceError {
    /// The frame does not parse, or its body is not `{"version", "value"}` with an object value.
    Malformed,
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
}

impl fmt::Display for SliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "the frame is not a slice"),
            Self::TooLarge { bytes, limit } => {
                write!(f, "the frame has {bytes} bytes, past the cap of {limit}")
            }
            Self::TooManyAuthors { limit } => {
                write!(f, "the store holds {limit} authors already")
            }
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

/// The slices of one mesh, keyed by author key.
///
/// # Examples
///
/// ```
/// use habilis_network_doc::{SliceLimits, SliceStore};
///
/// let store = SliceStore::new(SliceLimits::default());
/// assert_eq!(store.limits().max_authors, 256);
/// ```
#[derive(Debug)]
pub struct SliceStore {
    limits: SliceLimits,
    slices: HashMap<AuthorKey, Slice>,
}

/// One held slice: its version, the hash of its signed frame, and its value.
#[derive(Debug)]
struct Slice {
    version: u64,
    hash: ContentHash,
    value: serde_json::Value,
}

/// The body of a slice frame.
#[derive(Deserialize)]
struct SliceBody {
    version: u64,
    value: serde_json::Value,
}

impl SliceStore {
    /// Makes an empty store under `limits`.
    #[must_use]
    pub fn new(limits: SliceLimits) -> Self {
        Self {
            limits,
            slices: HashMap::new(),
        }
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

    /// Returns the number of authors that have a slice in this store.
    #[must_use]
    pub fn authors(&self) -> usize {
        self.slices.len()
    }

    /// Returns the whole document as `{<lowercase hex author key>: value}`.
    #[must_use]
    pub fn view(&self) -> serde_json::Map<String, serde_json::Value> {
        self.slices
            .iter()
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
        let Ok(wire) = frame.serialize() else {
            return SliceIngest::Refused(SliceError::Malformed);
        };
        let bytes = wire.as_bytes();
        if bytes.len() > self.limits.slice_bytes {
            return SliceIngest::Refused(SliceError::TooLarge {
                bytes: bytes.len(),
                limit: self.limits.slice_bytes,
            });
        }
        let Ok(body) = serde_json::from_str::<SliceBody>(frame.body.as_str()) else {
            return SliceIngest::Refused(SliceError::Malformed);
        };
        if !body.value.is_object() {
            return SliceIngest::Refused(SliceError::Malformed);
        }
        let incoming = Slice {
            version: body.version,
            hash: ContentHash::of(bytes),
            value: body.value,
        };
        let key = frame.key();
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
            Ordering::Equal if incoming.hash == held.hash => {
                return SliceIngest::Duplicate;
            }
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
    use super::*;
    use habilis_network_protocol::{Channel, MeshId, Message, MessageBody, Nickname};
    use serde_json::{Value, json};

    fn key(byte: u8) -> AuthorKey {
        AuthorKey::from([byte; 32])
    }

    /// A frame of `key` with `version` and `value`, carrying the slice body.
    fn frame(key: AuthorKey, version: u64, value: Value) -> Verified {
        let body = Value::Object(serde_json::Map::from_iter([
            ("version".to_owned(), json!(version)),
            ("value".to_owned(), value),
        ]));
        frame_with_body(key, &body.to_string())
    }

    /// A frame of `key` whose body is `body` as written.
    fn frame_with_body(key: AuthorKey, body: &str) -> Verified {
        Verified::fixture_unchecked(
            Message::new_channel_event(
                &MeshId::from("test"),
                &Nickname::from("peer"),
                MessageBody::from(body),
                Channel::Meta,
            ),
            key,
        )
    }

    fn store() -> SliceStore {
        SliceStore::new(SliceLimits::default())
    }

    #[test]
    fn ingest_applies_a_new_slice_under_the_frame_key() {
        let mut store = store();
        assert_eq!(
            store.ingest(&frame(key(1), 1, json!({"a": 1}))),
            SliceIngest::Applied
        );
        assert_eq!(store.version(&key(1)), Some(1));
        assert_eq!(store.version(&key(2)), None);
    }

    #[test]
    fn ingest_refuses_a_lower_version_as_stale() {
        let mut store = store();
        store.ingest(&frame(key(1), 2, json!({"a": 2})));
        assert_eq!(
            store.ingest(&frame(key(1), 1, json!({"a": 1}))),
            SliceIngest::Stale
        );
        assert_eq!(store.version(&key(1)), Some(2));
    }

    #[test]
    fn ingest_reports_the_same_frame_as_a_duplicate() {
        let mut store = store();
        let first = frame(key(1), 1, json!({"a": 1}));
        store.ingest(&first);
        assert_eq!(store.ingest(&first.clone()), SliceIngest::Duplicate);
    }

    #[test]
    fn ingest_breaks_a_version_tie_by_the_lower_hash() {
        let mut store = store();
        let one = frame(key(1), 1, json!({"a": 1}));
        let other = frame(key(1), 1, json!({"a": 2}));
        let hash =
            |signed: &Verified| ContentHash::of(signed.serialize().expect("a frame").as_bytes());
        store.ingest(&one);
        let outcome = store.ingest(&other);
        let expected = if hash(&other) < hash(&one) {
            SliceIngest::Applied
        } else {
            SliceIngest::Conflict
        };
        assert_eq!(outcome, expected);
    }

    #[test]
    fn ingest_refuses_a_frame_past_the_slice_cap_and_keeps_nothing() {
        let limits = SliceLimits::new(64, Duration::from_secs(1), 256, 5);
        let mut store = SliceStore::new(limits);
        let big = frame(key(1), 1, json!({"blob": "x".repeat(200)}));
        assert!(matches!(
            store.ingest(&big),
            SliceIngest::Refused(SliceError::TooLarge { limit: 64, .. })
        ));
        assert_eq!(store.version(&key(1)), None);
        assert_eq!(store.authors(), 0);
    }

    #[test]
    fn ingest_refuses_a_body_that_is_not_a_slice() {
        let mut store = store();
        assert_eq!(
            store.ingest(&frame_with_body(key(1), "not json")),
            SliceIngest::Refused(SliceError::Malformed)
        );
        assert_eq!(store.authors(), 0);
    }

    #[test]
    fn ingest_refuses_a_new_author_past_the_author_cap() {
        let limits = SliceLimits::new(3072, Duration::from_secs(1), 1, 5);
        let mut store = SliceStore::new(limits);
        store.ingest(&frame(key(1), 1, json!({})));
        assert_eq!(
            store.ingest(&frame(key(2), 1, json!({}))),
            SliceIngest::Refused(SliceError::TooManyAuthors { limit: 1 })
        );
        assert_eq!(store.authors(), 1);
    }

    #[test]
    fn view_maps_each_author_hex_to_its_value() {
        let mut store = store();
        store.ingest(&frame(key(1), 1, json!({"a": 1})));
        let hex = String::from_utf8_lossy(&key(1).hex()).into_owned();
        let view = store.view();
        assert_eq!(view.len(), 1);
        assert_eq!(view.get(&hex), Some(&json!({"a": 1})));
    }
}
