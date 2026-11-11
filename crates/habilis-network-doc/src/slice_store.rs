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
use std::time::Duration;

use habilis_network_util::clock::Instant;

use habilis_network_protocol::messages::Verified;
use habilis_network_protocol::{AuthorKey, Channel, ContentHash, MessageBody, SymmetricKey};
use habilis_network_util::consts::MAX_MESSAGE_SIZE;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::wire;

/// The most gone keys one store holds. It matches the author cap, so the set holds a key for each
/// author the store can hold. An overflow evicts the oldest key early. That is harmless only when
/// the engine roster gate refuses an author that is not in the roster. The gate is a requirement of
/// the wiring commit, it does not exist yet.
const GONE_CAP: usize = 256;

/// The default time a key stays gone. The engine forgets a quiet author after `QUIET_TTL`, one hour,
/// so this is that time plus a margin: a forgotten key stays refused past the forget. The wiring
/// commit must assert `gone_ttl >= QUIET_TTL` (1 hour, `heartbeat.rs`) in an engine test.
const DEFAULT_GONE_TTL: Duration = Duration::from_hours(2);

/// The longest mesh id text, in bytes. It is `MeshId`'s own limit.
const MAX_MESH_ID_LEN: usize = 512;

/// The longest nickname, in bytes: 32 characters of up to 4 bytes each.
const MAX_NICKNAME_LEN: usize = 128;

/// The frame bytes that do not depend on the mesh id or the nickname. A probe with a 62-byte mesh
/// id from `MeshId::from("test")` and a 4-byte nickname is 404 bytes, so the base is 404 - 66. A
/// test checks that the overhead grows one byte for each byte of mesh id and nickname.
const FRAME_BASE_OVERHEAD: usize = 338;

/// The frame overhead of the worst case: the longest mesh id and the longest nickname. Pass it to
/// [`SliceStore::new`] only where no probe of the session is possible.
const WORST_FRAME_OVERHEAD: usize = FRAME_BASE_OVERHEAD + MAX_MESH_ID_LEN + MAX_NICKNAME_LEN;

/// The bytes of a digest page around its rows: the index, the total, the range, the hash, and the
/// JSON around them.
const PAGE_WRAPPER: usize = 320;

/// The bytes of one page row at the longest version, `["<key hex>",18446744073709551615,"<hash
/// hex>"],`.
const PAGE_ROW: usize = 160;

/// The size of a sealed body relative to its plain JSON, in percent: base58 of the ciphertext is
/// about 1.37 times its bytes.
const SEAL_GROWTH_PERCENT: usize = 138;

/// The frame overhead of the worst case: the longest mesh id and the longest nickname. Use it
/// only where no probe is possible, because it is larger than most sessions need.
///
/// # Examples
///
/// ```
/// use habilis_network_doc::worst_frame_overhead;
///
/// assert!(worst_frame_overhead() > 900);
/// ```
#[must_use]
pub fn worst_frame_overhead() -> usize {
    WORST_FRAME_OVERHEAD
}

/// The frame overhead of a session with this mesh id and this nickname: the envelope of a signed frame
/// around the body, with the mesh id and the nickname in it.
///
/// # Examples
///
/// ```
/// use habilis_network_doc::{frame_overhead, worst_frame_overhead};
///
/// assert!(frame_overhead("mesh", "nick") < worst_frame_overhead());
/// ```
#[must_use]
pub fn frame_overhead(mesh_id: &str, nickname: &str) -> usize {
    FRAME_BASE_OVERHEAD + mesh_id.len() + nickname.len()
}

/// The caps that bound a [`SliceStore`].
///
/// # Examples
///
/// ```
/// use habilis_network_doc::SliceLimits;
///
/// let limits = SliceLimits::default();
/// assert_eq!(limits.slice_bytes, 3840);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SliceLimits {
    /// The most bytes one signed frame can take, as a lower cap. The default is the wire limit,
    /// `MAX_MESSAGE_SIZE`. A store's body limit is this minus its frame overhead.
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
        Self::new(MAX_MESSAGE_SIZE, Duration::from_secs(1), 256, 5)
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

/// One author in a digest page: its key, its version, and the hash of its signed frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DigestEntry {
    key: AuthorKey,
    version: u64,
    hash: ContentHash,
}

impl DigestEntry {
    /// Makes the entry of `key` at `version`, whose signed frame hashes to `hash`.
    #[must_use]
    pub fn new(key: AuthorKey, version: u64, hash: ContentHash) -> Self {
        Self { key, version, hash }
    }

    /// The author key of the entry.
    #[must_use]
    pub fn key(&self) -> AuthorKey {
        self.key
    }

    /// The version of the entry.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The hash of the signed frame of the entry.
    #[must_use]
    pub fn hash(&self) -> ContentHash {
        self.hash
    }
}

/// The root of a store's digest: the hash of every entry, and the number of pages.
///
/// This is the first message of the version-vector sync, which replaces the heads digest. Two
/// stores with equal roots need no more messages. Keep this round when the store changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(try_from = "RootWire", into = "RootWire")]
pub struct DigestRoot {
    /// The hash of all entries, sorted by key.
    pub root: ContentHash,
    /// The number of pages, at least one.
    pub total: usize,
}

/// One page of a store's digest. A page covers the keys from `first_key` up to `end_key`, not
/// included. A key of that range that the page does not list is absent at the sender.
///
/// The sync is pull-first. A peer reads the pages, pulls the keys it wants, and pushes the frames
/// that the other side lacks with `missing_for`, once per page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(try_from = "PageWire", into = "PageWire")]
pub struct DigestPage {
    index: usize,
    total: usize,
    first_key: AuthorKey,
    end_key: Option<AuthorKey>,
    entries: Vec<DigestEntry>,
    hash: ContentHash,
}

impl DigestPage {
    /// The index of the page, from zero.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    /// The number of pages of the digest.
    #[must_use]
    pub fn total(&self) -> usize {
        self.total
    }

    /// The first key of the range. The first page starts at the zero key.
    #[must_use]
    pub fn first_key(&self) -> AuthorKey {
        self.first_key
    }

    /// The first key after the range, or `None` for the last page.
    #[must_use]
    pub fn end_key(&self) -> Option<AuthorKey> {
        self.end_key
    }

    /// The listed entries, sorted by key.
    #[must_use]
    pub fn entries(&self) -> &[DigestEntry] {
        &self.entries
    }

    /// The hash of the listed entries.
    #[must_use]
    pub fn hash(&self) -> ContentHash {
        self.hash
    }
}

/// The wire form of a [`DigestRoot`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootWire {
    root: String,
    total: usize,
}

impl From<DigestRoot> for RootWire {
    fn from(root: DigestRoot) -> Self {
        Self {
            root: String::from_utf8_lossy(&root.root.hex()).into_owned(),
            total: root.total,
        }
    }
}

impl TryFrom<RootWire> for DigestRoot {
    type Error = String;

    fn try_from(wire: RootWire) -> Result<Self, Self::Error> {
        let root = ContentHash::decode_hex(&wire.root).ok_or("the root is not a hash")?;
        if wire.total == 0 {
            return Err("a digest has at least one page".to_owned());
        }
        Ok(Self {
            root,
            total: wire.total,
        })
    }
}

/// The wire form of a [`DigestPage`]. A row is `[key, version, hash]` in hex.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageWire {
    index: usize,
    total: usize,
    first_key: String,
    end_key: Option<String>,
    entries: Vec<(String, u64, String)>,
    hash: String,
}

impl From<DigestPage> for PageWire {
    fn from(page: DigestPage) -> Self {
        let entries = page.entries.iter().map(row_wire).collect();
        Self {
            index: page.index,
            total: page.total,
            first_key: hex_text(&page.first_key.hex()),
            end_key: page.end_key.map(|key| hex_text(&key.hex())),
            entries,
            hash: hex_text(&page.hash.hex()),
        }
    }
}

/// One digest row in its wire form.
fn row_wire(entry: &DigestEntry) -> (String, u64, String) {
    (
        hex_text(&entry.key.hex()),
        entry.version,
        hex_text(&entry.hash.hex()),
    )
}

/// The text of a hex array.
fn hex_text(bytes: &[u8; 64]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

impl TryFrom<PageWire> for DigestPage {
    type Error = String;

    fn try_from(wire: PageWire) -> Result<Self, Self::Error> {
        let first_key =
            AuthorKey::decode_hex(&wire.first_key).ok_or("the first key is not a key")?;
        let end_key = match wire.end_key {
            Some(text) => Some(AuthorKey::decode_hex(&text).ok_or("the end key is not a key")?),
            None => None,
        };
        let mut entries = Vec::with_capacity(wire.entries.len());
        for (key, version, hash) in wire.entries {
            let key = AuthorKey::decode_hex(&key).ok_or("an entry key is not a key")?;
            let hash = ContentHash::decode_hex(&hash).ok_or("an entry hash is not a hash")?;
            entries.push(DigestEntry::new(key, version, hash));
        }
        let hash = ContentHash::decode_hex(&wire.hash).ok_or("the page hash is not a hash")?;
        if page_hash(&entries) != hash {
            return Err("the page hash does not match its entries".to_owned());
        }
        if wire.index >= wire.total {
            return Err("the index is past the total".to_owned());
        }
        if entries
            .windows(2)
            .any(|pair| pair[0].key.as_bytes() >= pair[1].key.as_bytes())
        {
            return Err("the entries are not sorted and unique".to_owned());
        }
        let page = DigestPage {
            index: wire.index,
            total: wire.total,
            first_key,
            end_key,
            entries,
            hash,
        };
        if !page.entries.iter().all(|entry| in_range(&page, &entry.key)) {
            return Err("an entry is outside the page range".to_owned());
        }
        Ok(page)
    }
}

/// The hash of digest entries in the order given: each entry is its key, its version and its hash.
fn page_hash(entries: &[DigestEntry]) -> ContentHash {
    let mut bytes = Vec::with_capacity(entries.len() * 72);
    for entry in entries {
        bytes.extend_from_slice(entry.key.as_bytes());
        bytes.extend_from_slice(&entry.version.to_be_bytes());
        bytes.extend_from_slice(entry.hash.as_bytes());
    }
    ContentHash::of(&bytes)
}

/// Builds page `index` of `total` from the sorted entries of a store, `rows` to a page.
fn build_page(sorted: &[DigestEntry], rows: usize, index: usize, total: usize) -> DigestPage {
    let start = index * rows;
    let window = sorted.iter().skip(start).take(rows);
    let entries: Vec<DigestEntry> = window.cloned().collect();
    let first_key = if index == 0 {
        AuthorKey::from([0; 32])
    } else {
        entries
            .first()
            .map_or(AuthorKey::from([0; 32]), |first| first.key)
    };
    let end_key = sorted.get(start + rows).map(|next| next.key);
    let hash = page_hash(&entries);
    DigestPage {
        index,
        total,
        first_key,
        end_key,
        entries,
        hash,
    }
}

/// Whether `key` is in the range of `page`.
fn in_range(page: &DigestPage, key: &AuthorKey) -> bool {
    let after_first = key.as_bytes() >= page.first_key.as_bytes();
    let before_end = page
        .end_key
        .is_none_or(|end| key.as_bytes() < end.as_bytes());
    after_first && before_end
}

/// The slices of one channel, keyed by author key.
///
/// # Examples
///
/// ```
/// use habilis_network_doc::{SliceLimits, SliceStore, worst_frame_overhead};
/// use habilis_network_protocol::Channel;
///
/// let store = SliceStore::new(Channel::Meta, SliceLimits::default(), worst_frame_overhead());
/// assert_eq!(store.limits().max_authors, 256);
/// ```
#[derive(Debug)]
pub struct SliceStore {
    channel: Channel,
    key: Option<SymmetricKey>,
    limits: SliceLimits,
    frame_overhead: usize,
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
    /// Makes an empty store for `channel` under `limits`. `frame_overhead` is the frame bytes that
    /// a signed frame adds to its body, for the mesh id and the nickname of the session: the engine
    /// signs a probe channel event with an empty body and passes its length minus two, the two
    /// quotes of the empty JSON string. Use [`worst_frame_overhead`] only without a probe.
    #[must_use]
    pub fn new(channel: Channel, limits: SliceLimits, frame_overhead: usize) -> Self {
        Self {
            channel,
            key: None,
            limits,
            frame_overhead,
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

    /// The value of the slice of `key`, when the store holds one.
    #[must_use]
    pub fn value(&self, key: &AuthorKey) -> Option<&Value> {
        self.slices.get(key).map(|slice| &slice.value)
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
        if live && is_new && !self.take_token(&key, now, self.receive_burst()) {
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
        self.draft_at(own, Value::Object(value), now, true)
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
        self.draft_at(own, Value::Null, now, false)
    }

    /// The length in bytes of the escaped body that a write of `value` by `own` would carry.
    ///
    /// A caller measures a write before it sends one. A sealed body is measured at the longest text
    /// its blob can take, so the measure and the cap check of [`SliceStore::prepare_local`] agree on
    /// every seal. The call spends no token and changes nothing.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_doc::{SliceLimits, SliceStore, worst_frame_overhead};
    /// use habilis_network_protocol::Channel;
    /// use serde_json::{Map, Value};
    ///
    /// let store = SliceStore::new(Channel::Meta, SliceLimits::default(), worst_frame_overhead());
    /// let value: Map<String, Value> = serde_json::from_str(r#"{"status":"busy"}"#).expect("an object");
    /// let len = store.body_len(&habilis_network_protocol::AuthorKey::from([1; 32]), value.clone());
    /// assert!(len.is_ok(), "a short value fits");
    /// ```
    ///
    /// # Errors
    ///
    /// The errors of [`SliceStore::prepare_local`] that do not spend a token: [`SliceError::Malformed`],
    /// [`SliceError::Seal`] and [`SliceError::TooLarge`].
    pub fn body_len(
        &self,
        own: &AuthorKey,
        value: Map<String, Value>,
    ) -> Result<usize, SliceError> {
        let (_, _, measured) = self.draft_body(own, Value::Object(value))?;
        Ok(measured)
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
            SliceIngest::Refused(error) => {
                if matches!(error, SliceError::TooLarge { .. }) {
                    self.refund_token(&key);
                }
                Err(error)
            }
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

    /// The rows of one digest page, derived from the frame overhead, so a page fits one message.
    /// A sealed store has fewer rows, because its page body grows when it is sealed.
    fn page_rows(&self) -> usize {
        let mut budget = MAX_MESSAGE_SIZE.saturating_sub(self.frame_overhead + PAGE_WRAPPER);
        if self.key.is_some() {
            budget = budget * 100 / SEAL_GROWTH_PERCENT;
        }
        (budget / PAGE_ROW).max(1)
    }

    /// The stored entries, sorted by key.
    fn sorted_entries(&self) -> Vec<DigestEntry> {
        let mut entries: Vec<DigestEntry> = self
            .slices
            .iter()
            .map(|(key, slice)| DigestEntry::new(*key, slice.version, slice.hash))
            .collect();
        entries.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
        entries
    }

    /// Returns the root of the version digest: the hash and the number of pages.
    #[must_use]
    pub fn digest(&self) -> DigestRoot {
        let sorted = self.sorted_entries();
        DigestRoot {
            root: page_hash(&sorted),
            total: sorted.len().div_ceil(self.page_rows()).max(1),
        }
    }

    /// Returns page `index` of the version digest, or `None` past the last page. Each call reads
    /// the store again. Use [`SliceStore::pages`] to read every page from one snapshot.
    #[must_use]
    pub fn page(&self, index: usize) -> Option<DigestPage> {
        self.pages().nth(index)
    }

    /// Returns every page of the version digest, all built from one snapshot of the store.
    ///
    /// Page `index` covers the keys from the page's first key up to the next page's first key.
    /// The first page starts at the zero key, so every key is in some page.
    pub fn pages(&self) -> impl Iterator<Item = DigestPage> {
        let sorted = self.sorted_entries();
        let rows = self.page_rows();
        let total = sorted.len().div_ceil(rows).max(1);
        (0..total).map(move |index| build_page(&sorted, rows, index, total))
    }

    /// Whether the root of this store is `root`, so two peers with equal stores need one message.
    #[must_use]
    pub fn matches(&self, root: &ContentHash) -> bool {
        page_hash(&self.sorted_entries()) == *root
    }

    /// The stored frames that `page` lacks in its range, or lists at a lower version, or lists at
    /// the same version with a higher hash. This is the push of a peer that lacks an entry, so it
    /// is used once per page. A gone key has no slice, so it is never offered.
    pub fn missing_for<'a>(&'a self, page: &'a DigestPage) -> impl Iterator<Item = Verified> + 'a {
        self.slices
            .iter()
            .filter(move |(key, _)| in_range(page, key))
            .filter(move |(key, slice)| {
                match page.entries.iter().find(|listed| listed.key == **key) {
                    None => true,
                    Some(entry) => {
                        slice.version > entry.version
                            || (slice.version == entry.version && slice.hash < entry.hash)
                    }
                }
            })
            .map(|(_, slice)| slice.frame.clone())
    }

    /// The keys that `page` lists and this store would take: a key it lacks, or a key at a lower
    /// version, or at the same version with a lower hash. A gone key is never wanted. This is the
    /// pull of the asker.
    pub fn wanted_from<'a>(&'a self, page: &'a DigestPage) -> impl Iterator<Item = AuthorKey> + 'a {
        let unknown = page
            .entries
            .iter()
            .filter(move |entry| !self.is_gone(&entry.key));
        unknown
            .filter(move |entry| match self.slices.get(&entry.key) {
                None => true,
                Some(held) => {
                    entry.version > held.version
                        || (entry.version == held.version && entry.hash < held.hash)
                }
            })
            .map(|entry| entry.key)
    }

    /// The frames of the held keys among `keys`, the answer to a pull. It answers at most one
    /// page of keys: the first `page_rows` of `keys` are looked up, and the rest are ignored, so
    /// the asker pulls again for them. A gone key is never held, so it is never served.
    pub fn serve<'a>(&'a self, keys: &'a [AuthorKey]) -> impl Iterator<Item = Verified> + 'a {
        let first = keys.iter().take(self.page_rows());
        let held = first.filter_map(move |key| self.slices.get(key));
        held.map(|slice| slice.frame.clone())
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
        spend: bool,
    ) -> Result<LocalDraft, SliceError> {
        let (version, body, _) = self.draft_body(own, value)?;
        if spend && !self.take_token(own, now, self.limits.burst) {
            return Err(SliceError::RateLimited);
        }
        Ok(LocalDraft {
            channel: self.channel,
            key: *own,
            version,
            body,
        })
    }

    /// Builds the next version and body of the slice of `own`, and the length that the body is
    /// measured at. The length is the bound of a sealed body, so it does not change between seals.
    /// The check against the frame cap uses the measured length.
    fn draft_body(
        &self,
        own: &AuthorKey,
        value: Value,
    ) -> Result<(u64, MessageBody, usize), SliceError> {
        let version = self.version(own).unwrap_or(0) + 1;
        let mut body_json = json!({"version": version});
        body_json["value"] = value;
        let json = body_json.to_string();
        let plain = MessageBody::try_new(&json).map_err(|_| SliceError::Malformed)?;
        let (body, measured) = if let Some(key) = self.key.as_ref() {
            (
                wire::encrypt_body(&plain, key).map_err(|_| SliceError::Seal)?,
                wire::sealed_body_len_bound(plain.as_str().len()),
            )
        } else {
            let escaped =
                serde_json::to_string(plain.as_str()).map_or(usize::MAX, |text| text.len());
            (plain, escaped)
        };
        let limit = self.limits.slice_bytes.saturating_sub(self.frame_overhead);
        if measured > limit {
            return Err(SliceError::TooLarge {
                bytes: measured,
                limit,
            });
        }
        Ok((version, body, measured))
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

    /// Gives one token back to `own`, up to the burst.
    fn refund_token(&mut self, own: &AuthorKey) {
        let burst = self.limits.burst;
        if let Some(bucket) = self.buckets.get_mut(own) {
            bucket.tokens = bucket.tokens.saturating_add(1).min(burst);
        }
    }

    /// The burst of the arrivals of one author. It is twice the send burst, so that the jitter of a
    /// network does not make an honest version `RateLimited`.
    fn receive_burst(&self) -> u32 {
        self.limits.burst.saturating_mul(2)
    }

    /// Takes one write token of `own` at `now`, after the tokens it earned since its last write. The
    /// bucket holds at most `burst` tokens.
    fn take_token(&mut self, own: &AuthorKey, now: Instant, burst: u32) -> bool {
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
        DigestEntry, DigestPage, DigestRoot, FRAME_BASE_OVERHEAD, LocalDraft, MAX_MESH_ID_LEN,
        MAX_NICKNAME_LEN, PAGE_ROW, PAGE_WRAPPER, SliceError, SliceIngest, SliceLimits, SliceStore,
        WORST_FRAME_OVERHEAD, in_range, page_hash, row_wire, wire,
    };
    use habilis_network_protocol::messages::Verified;
    use habilis_network_protocol::{
        AuthorKey, Channel, ContentHash, MeshId, Message, MessageBody, Nickname, SymmetricKey,
    };
    use habilis_network_util::consts::MAX_MESSAGE_SIZE;
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
        SliceStore::new(Channel::Meta, SliceLimits::default(), WORST_FRAME_OVERHEAD)
    }

    fn small_store(limits: SliceLimits) -> SliceStore {
        SliceStore::new(Channel::Meta, limits, WORST_FRAME_OVERHEAD)
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
    fn body_len_is_the_escaped_length_of_the_draft_body_and_spends_no_token() {
        let mut store = store();
        let now = Instant::now();
        let value = object(json!({"a": 1}));
        let measured = store
            .body_len(&key(1), value.clone())
            .expect("a body that fits");
        let draft = store
            .prepare_local(&key(1), value, now)
            .expect("a draft that fits");
        let escaped: usize =
            serde_json::to_string(draft.body().as_str()).map_or(0, |text| text.len());
        assert_eq!(measured, escaped, "the measured length must be the draft's");
        for _ in 0..4 {
            assert!(
                store.body_len(&key(1), Map::new()).is_ok(),
                "a measure never spends a token"
            );
        }
        assert!(
            store.prepare_local(&key(1), Map::new(), now).is_ok(),
            "the first five writes fit the burst of 5, measures included"
        );
    }

    #[test]
    fn body_len_refuses_a_body_past_the_cap_with_the_typed_error() {
        let limits = SliceLimits::new(64 + WORST_FRAME_OVERHEAD, Duration::from_secs(1), 256, 1);
        let store = small_store(limits);
        let blob = object(json!({"blob": "x".repeat(200)}));
        assert!(
            matches!(
                store.body_len(&key(1), blob),
                Err(SliceError::TooLarge { limit: 64, .. })
            ),
            "a body past the cap must refuse with TooLarge"
        );
    }

    /// The largest blob of `x` characters that `store` measures within its cap.
    fn largest_fitting(store: &SliceStore) -> usize {
        let mut fitting = 0;
        while store
            .body_len(&key(1), object(json!({"blob": "x".repeat(fitting + 1)})))
            .is_ok()
        {
            fitting += 1;
        }
        fitting
    }

    #[test]
    fn a_plain_write_at_the_limit_fits_and_one_byte_more_is_too_large() {
        let limits = SliceLimits::new(3072, Duration::from_secs(1), 256, 5);
        let store = small_store(limits);
        let limit = 3072 - WORST_FRAME_OVERHEAD;
        let edge = largest_fitting(&store);
        let at = store
            .body_len(&key(1), object(json!({"blob": "x".repeat(edge)})))
            .expect("the largest write that fits");
        assert!(at <= limit, "the largest fitting write is within the limit");
        assert!(
            matches!(
                store.body_len(&key(1), object(json!({"blob": "x".repeat(edge + 1)}))),
                Err(SliceError::TooLarge { limit: refused, .. }) if refused == limit
            ),
            "one byte past the largest fitting write is TooLarge at the limit"
        );
    }

    #[test]
    fn a_sealed_write_at_the_limit_is_ok_on_every_seal() {
        let limits = SliceLimits::new(3072, Duration::from_secs(1), 256, 200);
        let mut store: SliceStore =
            small_store(limits).with_key(Some(SymmetricKey::from([3u8; 32])));
        let edge = largest_fitting(&store);
        let limit = 3072 - WORST_FRAME_OVERHEAD;
        assert!(
            matches!(
                store.body_len(&key(1), object(json!({"blob": "x".repeat(edge + 1)}))),
                Err(SliceError::TooLarge { limit: refused, .. }) if refused == limit
            ),
            "one byte past the largest fitting sealed write is TooLarge"
        );
        let now = Instant::now();
        for seal in 0..200 {
            assert!(
                store
                    .prepare_local(&key(1), object(json!({"blob": "x".repeat(edge)})), now)
                    .is_ok(),
                "seal {seal}: a write at the limit must fit on every seal"
            );
        }
    }

    #[test]
    fn a_new_version_from_a_key_outside_the_roster_spends_a_token() {
        let mut store = store();
        let now = Instant::now();
        let mut refused = Vec::new();
        for version in 1..=11 {
            let body = format!(r#"{{"version":{version},"value":{{}}}}"#);
            let frame = frame_with_body(key(9), &body);
            if let SliceIngest::Refused(error) = store.ingest(&frame, true, now) {
                refused.push((version, error));
            }
        }
        assert!(
            matches!(refused.as_slice(), [(11, SliceError::RateLimited)]),
            "only the eleventh new version of a key with a receive burst of 10 is refused: {refused:?}"
        );
    }

    /// Five arrivals of one author come 300 ms late, and its sixth version comes half an interval after
    /// the fifth. The arrivals are jittered, so the sixth is inside the send burst's interval, and it is
    /// still applied: the receive bucket is twice the send burst.
    #[test]
    fn a_jittered_sixth_version_is_applied_inside_the_receive_burst() {
        let limits = SliceLimits::new(3072, Duration::from_secs(1), 256, 5);
        let mut store = small_store(limits);
        let start = Instant::now();
        let late = Duration::from_millis(300);
        for version in 1..=5 {
            let body = format!(r#"{{"version":{version},"value":{{}}}}"#);
            let frame = frame_with_body(key(9), &body);
            assert!(
                matches!(
                    store.ingest(&frame, true, start + late),
                    SliceIngest::Applied
                ),
                "version {version} of the burst is applied"
            );
        }
        let sixth = frame_with_body(key(9), r#"{"version":6,"value":{}}"#);
        assert!(
            matches!(
                store.ingest(&sixth, true, start + late + Duration::from_millis(500)),
                SliceIngest::Applied
            ),
            "the sixth version, half an interval after the fifth, is applied"
        );
    }

    #[test]
    fn a_first_slice_of_a_new_key_applies_with_a_full_bucket() {
        let mut store = store();
        let frame = frame_with_body(key(9), r#"{"version":1,"value":{"k":1}}"#);
        assert!(
            matches!(
                store.ingest(&frame, true, Instant::now()),
                SliceIngest::Applied
            ),
            "the first slice of a key that is not yet in the store applies"
        );
    }

    #[test]
    fn a_realistic_sealed_card_fits_a_typical_session_and_not_the_worst_case() {
        let sealed = |overhead: usize| {
            SliceStore::new(Channel::Meta, SliceLimits::default(), overhead)
                .with_key(Some(SymmetricKey::from([3u8; 32])))
        };
        let card = object(json!({"card": "x".repeat(2300)}));
        let typical = super::frame_overhead(&"m".repeat(100), &"n".repeat(36));
        assert!(
            sealed(typical).body_len(&key(1), card.clone()).is_ok(),
            "a card of about 2.3 KB fits the frame of a session with a typical mesh id and nickname"
        );
        assert!(
            matches!(
                sealed(WORST_FRAME_OVERHEAD).body_len(&key(1), card),
                Err(SliceError::TooLarge { .. })
            ),
            "the same card is TooLarge under the worst-case overhead"
        );
    }

    #[test]
    fn a_sealed_card_sized_meta_entry_is_too_large_for_one_slice() {
        let store: SliceStore =
            SliceStore::new(Channel::Meta, SliceLimits::default(), WORST_FRAME_OVERHEAD)
                .with_key(Some(SymmetricKey::from([3u8; 32])));
        let card = object(json!({"card": "x".repeat(2400)}));
        assert!(
            matches!(
                store.body_len(&key(1), card),
                Err(SliceError::TooLarge { .. })
            ),
            "a sealed entry of about 2.4 KB does not fit one slice of the default limits"
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
        let limits = SliceLimits::new(64 + WORST_FRAME_OVERHEAD, Duration::from_secs(1), 256, 1);
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
        let empty: usize =
            serde_json::to_string(probe.body().as_str()).map_or(0, |text| text.len());
        let body_limit = 3072 - WORST_FRAME_OVERHEAD;
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
        let mut state =
            SliceStore::new(Channel::State, SliceLimits::default(), WORST_FRAME_OVERHEAD);
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
    fn ingest_live_refuses_the_eleventh_new_version_inside_the_receive_burst() {
        let mut store = store();
        let now = Instant::now();
        for version in 1..=10 {
            assert_eq!(
                store.ingest(&frame(key(1), version, json!({})), true, now),
                SliceIngest::Applied,
                "the first ten live versions fit the receive burst of 10"
            );
        }
        assert_eq!(
            store.ingest(&frame(key(1), 11, json!({})), true, now),
            SliceIngest::Refused(SliceError::RateLimited),
            "the eleventh live new version inside the receive burst must be rate limited"
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

    /// The key of the peer `index`, for the tests that need several authors.
    fn author_key(index: usize) -> AuthorKey {
        many_key(index + 1)
    }

    /// Advances a xorshift generator and returns a value below `bound`.
    fn pick(seed: &mut u64, bound: usize) -> usize {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        usize::try_from(*seed % u64::try_from(bound).unwrap_or(1)).unwrap_or(0)
    }

    /// The frame overhead of a probe channel event with `mesh` and `nickname` and an empty body.
    fn probe_overhead(mesh: &MeshId, nickname: &Nickname) -> usize {
        let probe = Verified::fixture_unchecked(
            Message::new_channel_event(mesh, nickname, MessageBody::from(""), Channel::Meta),
            key(7),
        );
        probe.serialize().expect("a probe must serialize").len() - 2
    }

    /// The escaped length of the body of a draft whose value has `blob` as its only string.
    fn escaped_body_len(store: &mut SliceStore, blob: &str) -> usize {
        let draft = store
            .prepare_local(&key(1), object(json!({"blob": blob})), Instant::now())
            .expect("a draft");
        serde_json::to_string(draft.body().as_str()).map_or(usize::MAX, |text| text.len())
    }

    #[test]
    fn root_is_equal_for_equal_stores_and_changes_with_any_slice() {
        let mut first_store = store();
        let mut second_store = store();
        let one = frame(key(1), 1, json!({"a": 1}));
        let two = frame(key(2), 1, json!({"b": 2}));
        apply(&mut first_store, &one);
        apply(&mut first_store, &two);
        apply(&mut second_store, &two.clone());
        apply(&mut second_store, &one.clone());
        assert_eq!(
            first_store.digest().root,
            second_store.digest().root,
            "equal stores must have one root"
        );
        assert!(
            second_store.matches(&first_store.digest().root),
            "equal stores must match each other's root"
        );
        apply(&mut first_store, &frame(key(1), 2, json!({"a": 3})));
        assert_ne!(
            first_store.digest().root,
            second_store.digest().root,
            "a new version must change the root"
        );
        assert!(
            !second_store.matches(&first_store.digest().root),
            "a changed store must not match the old root"
        );
    }

    #[test]
    fn a_page_fits_the_exact_session_overhead_plain_and_sealed() {
        let mesh = MeshId::from("test");
        let nickname = Nickname::from(&*"\u{1F600}".repeat(MAX_NICKNAME_LEN / 4));
        for overhead in [probe_overhead(&mesh, &nickname), WORST_FRAME_OVERHEAD] {
            let limits = SliceLimits::new(MAX_MESSAGE_SIZE, Duration::from_secs(1), 256, 5);
            let mut plain = SliceStore::new(Channel::Meta, limits, overhead);
            for index in 0..256 {
                let body = json!({"version": u64::MAX, "value": {"n": index}});
                apply(
                    &mut plain,
                    &frame_with_body(author_key(index), &body.to_string()),
                );
            }
            for page in plain.pages() {
                let text = serde_json::to_string(&page).expect("a page must serialize");
                let escaped = serde_json::to_string(text.as_str()).expect("escaped").len();
                assert!(
                    escaped + overhead <= MAX_MESSAGE_SIZE,
                    "a plain page must fit at {overhead}"
                );
            }
            let sealed = plain.with_key(Some(SymmetricKey::from([3u8; 32])));
            for page in sealed.pages() {
                let text = serde_json::to_string(&page).expect("a page must serialize");
                let body = wire::encrypt_body(
                    &MessageBody::from(text.as_str()),
                    &SymmetricKey::from([3u8; 32]),
                )
                .expect("a sealed page");
                let escaped = serde_json::to_string(body.as_str()).expect("escaped").len();
                assert!(
                    escaped + overhead <= MAX_MESSAGE_SIZE,
                    "a sealed page must fit at {overhead}"
                );
            }
        }
    }

    #[test]
    fn the_page_estimates_cover_the_measured_wrapper_and_row() {
        let empty = store().page(0).expect("a page");
        let wrapper = serde_json::to_string(&empty)
            .expect("a page must serialize")
            .len();
        assert!(
            PAGE_WRAPPER >= wrapper,
            "PAGE_WRAPPER must cover the measured {wrapper} bytes"
        );
        let entry = DigestEntry::new(key(1), u64::MAX, ContentHash::of(b"row"));
        let row = serde_json::to_string(&row_wire(&entry))
            .expect("a row must serialize")
            .len()
            + 1;
        assert!(
            PAGE_ROW >= row,
            "PAGE_ROW must cover the measured {row} bytes"
        );
    }

    #[test]
    fn a_body_past_three_kib_drafts_under_the_wire_limit() {
        let mut store = SliceStore::new(Channel::Meta, SliceLimits::default(), 404);
        assert!(
            store
                .prepare_local(
                    &key(1),
                    object(json!({"a": "x".repeat(3_000)})),
                    Instant::now()
                )
                .is_ok(),
            "a body that fits the wire limit must draft"
        );
    }

    #[test]
    fn a_digest_page_with_unsorted_entries_is_refused() {
        let mut first = store();
        apply(&mut first, &frame(key(1), 1, json!({"a": 1})));
        apply(&mut first, &frame(key(2), 1, json!({"b": 2})));
        let first_page = first.pages().next().expect("a page");
        let mut rows = first_page.entries().to_vec();
        rows.reverse();
        let hash = page_hash(&rows);
        let page = DigestPage {
            index: 0,
            total: 1,
            first_key: AuthorKey::from([0; 32]),
            end_key: None,
            entries: rows,
            hash,
        };
        let text = serde_json::to_string(&page).expect("a page must serialize");
        let parsed: Result<DigestPage, _> = serde_json::from_str(&text);
        assert!(parsed.is_err(), "entries out of key order must be refused");
    }

    #[test]
    fn a_digest_page_past_its_total_is_refused() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        let page = store.page(0).expect("a page");
        let text = serde_json::to_string(&page).expect("a page must serialize");
        let mut value: Value = serde_json::from_str(&text).expect("a value");
        value["index"] = json!(5);
        let parsed: Result<DigestPage, _> = serde_json::from_value(value);
        assert!(parsed.is_err(), "an index past the total must be refused");
    }

    #[test]
    fn pages_come_from_one_snapshot_and_match_page() {
        let mut store = small_store(SliceLimits::default());
        for index in 0..40 {
            apply(
                &mut store,
                &frame(author_key(index), 1, json!({"n": index})),
            );
        }
        let pages: Vec<DigestPage> = store.pages().collect();
        assert_eq!(
            pages.len(),
            store.digest().total,
            "pages must match the digest total"
        );
        let numbered = pages.iter().enumerate();
        for (index, page) in numbered {
            assert_eq!(
                store.page(index).as_ref(),
                Some(page),
                "page {index} must match page()"
            );
        }
    }

    #[test]
    fn serve_answers_at_most_one_page_of_keys() {
        let mut store = store();
        for index in 0..30 {
            apply(
                &mut store,
                &frame(author_key(index), 1, json!({"n": index})),
            );
        }
        let asked: Vec<AuthorKey> = (0..30).map(author_key).collect();
        let first_page = store.page(0).expect("a page");
        let rows = first_page.entries().len();
        assert_eq!(
            store.serve(&asked).count(),
            rows,
            "serve must answer one page of keys"
        );
        assert!(rows < 30, "the test must need more than one page");
    }

    #[test]
    fn pages_split_the_keys_into_ranges_that_hold_each_key_once() {
        let mut store = store();
        for index in 0..40 {
            apply(
                &mut store,
                &frame(author_key(index), 1, json!({"n": index})),
            );
        }
        let total = store.digest().total;
        assert!(total > 1, "40 authors must not fit one page");
        let pages: Vec<DigestPage> = (0..total).filter_map(|index| store.page(index)).collect();
        assert_eq!(
            pages.len(),
            total,
            "every index below the total must be a page"
        );
        assert_eq!(
            pages[0].first_key(),
            AuthorKey::from([0; 32]),
            "the first page starts at zero"
        );
        assert!(
            pages[total - 1].end_key().is_none(),
            "the last page has no end key"
        );
        for page in &pages {
            for entry in page.entries() {
                assert!(
                    in_range(page, &entry.key()),
                    "a listed key must be in its page range"
                );
                let holders: usize = pages
                    .iter()
                    .filter(|other| in_range(other, &entry.key()))
                    .count();
                assert_eq!(holders, 1, "a key must be in exactly one page range");
            }
        }
    }

    #[test]
    fn missing_for_offers_an_author_the_other_side_lacks() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        let theirs = store_with_nothing();
        let page = theirs.page(0).expect("a page");
        let offered: Vec<Verified> = store.missing_for(&page).collect();
        assert_eq!(offered.len(), 1, "a lacking author must be offered");
        assert_eq!(
            offered[0].key(),
            key(1),
            "the offered frame must be the author's own"
        );
    }

    /// A store that holds nothing, for the tests that read an empty peer.
    fn store_with_nothing() -> SliceStore {
        store()
    }

    /// A store that holds the one entry `key` at `version` with the frame `signed`.
    fn peer_holding(signed: &Verified) -> SliceStore {
        let mut peer = store();
        apply(&mut peer, signed);
        peer
    }

    #[test]
    fn missing_for_offers_a_higher_version_and_never_a_lower_one() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 2, json!({"a": 2})));
        let behind = peer_holding(&frame(key(1), 1, json!({"a": 1})));
        let behind_page = behind.page(0).expect("a page");
        assert_eq!(
            store.missing_for(&behind_page).count(),
            1,
            "a higher version must be offered"
        );
        let ahead = peer_holding(&frame(key(1), 3, json!({"a": 3})));
        let ahead_page = ahead.page(0).expect("a page");
        assert_eq!(
            store.missing_for(&ahead_page).count(),
            0,
            "a lower version must never be offered"
        );
    }

    #[test]
    fn missing_for_resolves_an_equal_version_by_the_lower_hash() {
        let one = frame(key(1), 1, json!({"a": 1}));
        let other = frame(key(1), 1, json!({"a": 2}));
        let (low, high) = if one.content_hash() < other.content_hash() {
            (one, other)
        } else {
            (other, one)
        };
        let mut holds_high = store();
        apply(&mut holds_high, &high);
        let theirs_low = peer_holding(&low);
        let theirs_low_page = theirs_low.page(0).expect("a page");
        assert_eq!(
            holds_high.missing_for(&theirs_low_page).count(),
            0,
            "the higher hash must not be offered against the lower hash"
        );
        let mut holds_low = store();
        apply(&mut holds_low, &low);
        let theirs_high = peer_holding(&high);
        let theirs_high_page = theirs_high.page(0).expect("a page");
        assert_eq!(
            holds_low.missing_for(&theirs_high_page).count(),
            1,
            "the lower hash must be offered against the higher hash"
        );
    }

    #[test]
    fn missing_for_offers_a_tombstone_as_its_frame() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 2, Value::Null));
        let behind = peer_holding(&frame(key(1), 1, json!({"a": 1})));
        let page = behind.page(0).expect("a page");
        let offered: Vec<Verified> = store.missing_for(&page).collect();
        assert_eq!(offered.len(), 1, "a tombstone must be offered");
        assert!(
            offered[0].body.as_str().contains("null"),
            "the offered tombstone must be its own signed frame with a null value"
        );
    }

    #[test]
    fn a_forgotten_key_is_never_offered_listed_or_wanted() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        store.forget(&key(1), Instant::now());
        let high = peer_holding(&frame(key(1), 9, json!({"a": 9})));
        let page = high.page(0).expect("a page");
        assert_eq!(
            store.missing_for(&page).count(),
            0,
            "a forgotten key must not be offered"
        );
        assert_eq!(
            store.wanted_from(&page).count(),
            0,
            "a forgotten key must not be wanted"
        );
        assert_eq!(
            store.digest().total,
            1,
            "the digest of a store with no key is one empty page"
        );
        assert!(
            store.page(0).expect("a page").entries().is_empty(),
            "a forgotten key must not be listed"
        );
    }

    #[test]
    fn wanted_from_lists_a_key_the_store_would_take() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 5, json!({"a": 5})));
        let mut theirs = small_store(SliceLimits::default());
        apply(&mut theirs, &frame(key(1), 4, json!({"a": 4})));
        apply(&mut theirs, &frame(key(2), 1, json!({"b": 1})));
        let page = theirs.page(0).expect("a page");
        let wanted: Vec<AuthorKey> = store.wanted_from(&page).collect();
        assert_eq!(
            wanted,
            vec![key(2)],
            "a new key must be wanted and a lower version must not"
        );
    }

    #[test]
    fn serve_returns_exactly_the_keys_held() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        store.forget(&key(2), Instant::now());
        let asked = [key(1), key(2), key(3)];
        let served: Vec<Verified> = store.serve(&asked).collect();
        assert_eq!(served.len(), 1, "only the held key must be served");
        assert_eq!(
            served[0].key(),
            key(1),
            "the served frame must be the held author's"
        );
    }

    #[test]
    fn a_digest_page_round_trips_through_its_wire_form() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        let page = store.page(0).expect("a page");
        let text = serde_json::to_string(&page).expect("a page must serialize");
        let back: DigestPage = serde_json::from_str(&text).expect("a page must parse");
        assert_eq!(back, page, "a page must come back equal from its wire form");
        let unknown = text.replacen('{', "{\"extra\":1,", 1);
        assert!(
            {
                let parsed: Result<DigestPage, _> = serde_json::from_str(&unknown);
                parsed.is_err()
            },
            "an unknown field must be refused"
        );
    }

    #[test]
    fn a_digest_root_round_trips_through_its_wire_form() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        let root = store.digest();
        let text = serde_json::to_string(&root).expect("a root must serialize");
        let back: DigestRoot = serde_json::from_str(&text).expect("a root must parse");
        assert_eq!(back, root, "a root must come back equal from its wire form");
    }

    #[test]
    fn prepare_leave_spends_no_token_and_is_never_rate_limited() {
        let mut store = small_store(SliceLimits::new(3072, Duration::from_secs(1), 256, 1));
        let now = Instant::now();
        store
            .prepare_local(&key(1), Map::new(), now)
            .expect("the only token");
        assert!(
            matches!(
                store.prepare_local(&key(1), Map::new(), now),
                Err(SliceError::RateLimited)
            ),
            "the bucket must be empty for the next write"
        );
        assert!(
            store.prepare_leave(&key(1), now).is_ok(),
            "a leave must not be rate limited with an empty bucket"
        );
        let mut fresh = small_store(SliceLimits::new(3072, Duration::from_secs(1), 256, 1));
        fresh.prepare_leave(&key(2), now).expect("a leave");
        assert!(
            fresh.prepare_local(&key(2), Map::new(), now).is_ok(),
            "a leave must not spend the only token"
        );
    }

    #[test]
    fn a_body_of_quotes_is_refused_in_prepare_local_at_its_escaped_size() {
        let mut store = small_store(SliceLimits::new(3072, Duration::from_secs(1), 256, 5));
        let items = vec![""; 800];
        assert!(
            matches!(
                store.prepare_local(&key(1), object(json!({"q": items})), Instant::now()),
                Err(SliceError::TooLarge { .. })
            ),
            "a body whose escaped JSON is past the limit must be refused in prepare_local"
        );
    }

    #[test]
    fn a_body_that_fits_the_session_overhead_is_refused_under_the_worst_case() {
        let limits = SliceLimits::new(3072, Duration::from_secs(1), 256, 1);
        let session = probe_overhead(&MeshId::from("test"), &Nickname::from("peer"));
        let base = escaped_body_len(&mut small_store(limits), "");
        let blob = "x".repeat(3072 - session - base);
        let mut session_store = SliceStore::new(Channel::Meta, limits, session);
        assert!(
            session_store
                .prepare_local(&key(1), object(json!({"blob": blob})), Instant::now())
                .is_ok(),
            "a body that fits the session overhead must draft"
        );
        let mut worst = small_store(limits);
        assert!(
            matches!(
                worst.prepare_local(&key(1), object(json!({"blob": blob})), Instant::now()),
                Err(SliceError::TooLarge { .. })
            ),
            "the same body must be refused under the worst-case overhead"
        );
    }

    #[test]
    fn frame_overhead_grows_one_byte_per_mesh_id_and_nickname_byte() {
        let mesh = MeshId::from("test");
        let short = Nickname::from("peer");
        assert_eq!(
            probe_overhead(&mesh, &short),
            FRAME_BASE_OVERHEAD + mesh.as_str().len() + short.as_str().len(),
            "the overhead must be the base plus the mesh id and the nickname"
        );
    }

    #[test]
    fn a_too_large_commit_refunds_the_token() {
        let limits = SliceLimits::new(3072, Duration::from_secs(1), 256, 1);
        let mut store = SliceStore::new(Channel::Meta, limits, 0);
        let now = Instant::now();
        let draft = store
            .prepare_local(&key(1), object(json!({"a": "x".repeat(2_800)})), now)
            .expect("the draft fits when the overhead is zero");
        let signed = frame_of(&draft, key(1));
        assert!(
            matches!(
                store.commit_local(draft, &signed, now),
                Err(SliceError::TooLarge { .. })
            ),
            "the frame with its real overhead must be refused at commit"
        );
        assert!(
            store.prepare_local(&key(1), Map::new(), now).is_ok(),
            "a refused commit must refund the only token"
        );
    }

    #[test]
    fn the_worst_case_overhead_covers_the_longest_mesh_id_and_nickname() {
        let mesh = MeshId::from("test");
        let nickname = Nickname::from(&*"\u{1F600}".repeat(32));
        let probe = probe_overhead(&mesh, &nickname);
        assert!(
            probe + (MAX_MESH_ID_LEN - mesh.as_str().len()) <= WORST_FRAME_OVERHEAD,
            "the worst case must cover a mesh id of {MAX_MESH_ID_LEN} bytes"
        );
    }

    #[test]
    fn peers_converge_under_loss_leave_forget_and_conflict() {
        const NODES: usize = 5;
        const LEAVER: usize = 0;
        const CONFLICTED: usize = 2;
        let limits = SliceLimits::new(3072, Duration::from_millis(1), 256, 1_000);
        let mut nodes: Vec<SliceStore> = (0..NODES)
            .map(|_| SliceStore::new(Channel::Meta, limits, 3_000))
            .collect();
        let start = Instant::now();
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut winner = Value::Null;
        for tick in 0..400_u64 {
            let now = start + Duration::from_millis(tick);
            if tick == 250 {
                let own = author_key(LEAVER);
                let draft = nodes[LEAVER].prepare_leave(&own, now).expect("a leave");
                let signed = frame_of(&draft, own);
                nodes[LEAVER]
                    .commit_local(draft, &signed, now)
                    .expect("the leave commits");
            } else if tick == 300 {
                let conflict_at = nodes[CONFLICTED]
                    .version(&author_key(CONFLICTED))
                    .unwrap_or(0)
                    + 1;
                let first = frame(author_key(CONFLICTED), conflict_at, json!({"c": 1}));
                let second = frame(author_key(CONFLICTED), conflict_at, json!({"c": 2}));
                winner = if first.content_hash() < second.content_hash() {
                    json!({"c": 1})
                } else {
                    json!({"c": 2})
                };
                nodes[1].ingest(&first, false, now);
                nodes[3].ingest(&second, false, now);
            } else if pick(&mut seed, 3) == 0 {
                let author = pick(&mut seed, NODES);
                let writes_left = if author == LEAVER {
                    tick < 250
                } else {
                    author != CONFLICTED || tick < 300
                };
                if writes_left {
                    let own = author_key(author);
                    let draft = nodes[author]
                        .prepare_local(&own, object(json!({"tick": tick})), now)
                        .expect("a write must draft");
                    let signed = frame_of(&draft, own);
                    nodes[author]
                        .commit_local(draft, &signed, now)
                        .expect("an own write commits");
                }
            } else {
                let from = pick(&mut seed, NODES);
                let to = pick(&mut seed, NODES);
                if from != to {
                    exchange(&mut nodes, from, to, now, &mut seed, true);
                }
            }
        }
        for _ in 0..NODES + 2 {
            full_round(&mut nodes, start, &mut seed, false);
        }
        let later = start + Duration::from_secs(3_600);
        for node in &mut nodes[..NODES - 1] {
            node.forget(&author_key(LEAVER), later);
        }
        for _ in 0..NODES + 2 {
            full_round(&mut nodes, later, &mut seed, false);
        }
        assert_ne!(
            nodes[0].digest(),
            nodes[NODES - 1].digest(),
            "a mismatch must last until every peer forgets"
        );
        nodes[NODES - 1].forget(&author_key(LEAVER), later);
        for _ in 0..NODES + 2 {
            full_round(&mut nodes, later, &mut seed, false);
        }
        let root = nodes[0].digest();
        let view = nodes[0].view();
        for index in 0..nodes.len() {
            let node = &nodes[index];
            assert_eq!(
                node.digest(),
                root,
                "peer {index} must have the same digest root"
            );
            assert_eq!(node.view(), view, "peer {index} must have the same view");
            assert_eq!(
                node.version(&author_key(LEAVER)),
                None,
                "a gone author must not return on {index}"
            );
            for other in &nodes {
                let other_total = other.digest().total;
                for page_index in 0..other_total {
                    let page = other.page(page_index).expect("a page");
                    assert_eq!(
                        node.wanted_from(&page).count(),
                        0,
                        "nothing must be wanted on {index}"
                    );
                    assert_eq!(
                        node.missing_for(&page).count(),
                        0,
                        "nothing must be missing on {index}"
                    );
                }
            }
        }
        let conflicted_hex = String::from_utf8_lossy(&author_key(CONFLICTED).hex()).into_owned();
        assert_eq!(
            view.get(&conflicted_hex),
            Some(&winner),
            "the lower hash must win the conflict"
        );
    }

    /// Carries a pass of the sync from `from` to `to`: `from` pulls the keys it wants from `to`, and
    /// pushes the frames that `to` lacks, page by page. A lossy pass drops some frames.
    fn exchange(
        nodes: &mut [SliceStore],
        from: usize,
        to: usize,
        now: Instant,
        seed: &mut u64,
        lossy: bool,
    ) {
        let pages: Vec<DigestPage> = nodes[to].pages().collect();
        for page in &pages {
            let wanted: Vec<AuthorKey> = nodes[from].wanted_from(page).collect();
            let pulled: Vec<Verified> = nodes[to].serve(&wanted).collect();
            for frame in &pulled {
                if !lossy || pick(seed, 4) != 0 {
                    nodes[from].ingest(frame, false, now);
                }
            }
            let pushed: Vec<Verified> = nodes[from].missing_for(page).collect();
            for frame in &pushed {
                if !lossy || pick(seed, 4) != 0 {
                    nodes[to].ingest(frame, false, now);
                }
            }
        }
    }

    /// One exchange in both directions for every pair of `nodes`.
    fn full_round(nodes: &mut [SliceStore], now: Instant, seed: &mut u64, lossy: bool) {
        for from in 0..nodes.len() {
            for to in 0..nodes.len() {
                if from != to {
                    exchange(nodes, from, to, now, seed, lossy);
                }
            }
        }
    }
    #[test]
    fn a_digest_root_has_the_golden_wire_form() {
        let zeros = "0".repeat(64);
        let root = DigestRoot {
            root: ContentHash::decode_hex(&zeros).expect("a hash"),
            total: 2,
        };
        let text = serde_json::to_string(&root).expect("a root must serialize");
        assert_eq!(
            text,
            format!(r#"{{"root":"{zeros}","total":2}}"#),
            "the root wire form changed"
        );
    }

    #[test]
    fn a_digest_page_has_the_golden_wire_form() {
        let zeros = "0".repeat(64);
        let entries = vec![DigestEntry::new(
            key(1),
            1,
            ContentHash::decode_hex(&zeros).expect("a hash"),
        )];
        let hash = page_hash(&entries);
        let page = DigestPage {
            index: 0,
            total: 1,
            first_key: AuthorKey::from([0; 32]),
            end_key: None,
            entries,
            hash,
        };
        let key_hex = String::from_utf8_lossy(&key(1).hex()).into_owned();
        let hash_hex = String::from_utf8_lossy(&hash.hex()).into_owned();
        let golden = format!(
            r#"{{"index":0,"total":1,"first_key":"{zeros}","end_key":null,"entries":[["{key_hex}",1,"{zeros}"]],"hash":"{hash_hex}"}}"#
        );
        let text = serde_json::to_string(&page).expect("a page must serialize");
        assert_eq!(text, golden, "the page wire form changed");
        let back: DigestPage = serde_json::from_str(&golden).expect("the golden page must parse");
        assert_eq!(back, page, "the golden page must parse back equal");
    }

    #[test]
    fn a_page_with_a_wrong_hash_is_refused() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        let text = serde_json::to_string(&store.page(0).expect("a page")).expect("a page");
        let mut value: Value = serde_json::from_str(&text).expect("a value");
        value["hash"] = json!("0".repeat(64));
        let parsed: Result<DigestPage, _> = serde_json::from_value(value);
        assert!(
            parsed.is_err(),
            "a page whose hash does not match its entries must be refused"
        );
    }
}
