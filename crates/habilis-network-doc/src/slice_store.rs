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

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::time::Duration;

use habilis_network_util::clock::Instant;
use habilis_network_util::tuning;

use habilis_network_protocol::digest::{DigestEntry, DigestPage, DigestRoot, PAGE_ROW, page_hash};
use habilis_network_protocol::messages::Verified;
use habilis_network_protocol::{
    AuthorKey, Channel, ContentHash, Identity, MeshId, Message, MessageBody, MessageKind, Nickname,
    SymmetricKey,
};
use habilis_network_util::consts::MAX_MESSAGE_SIZE;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::chunk_pointer::{CHUNKS_KEY, ChunkPointer};
use crate::pending_slices::PendingSlices;
use crate::slice_value::SliceValue;
use crate::wire;

/// The default time a key stays gone, after a signed goodbye or a replaced run. It must cover
/// `QUIET_TTL` plus `ALIVE_TIMEOUT`: a peer that missed the goodbye keeps the old slice until it
/// drops the key. The engine test `the_gone_ttl_outlasts_the_quiet_ttl_and_the_alive_timeout` pins it.
const DEFAULT_GONE_TTL: Duration = Duration::from_hours(2);

/// The escaped length of the empty body, `""`. A frame with no body still carries it, so the probe takes it off.
const EMPTY_BODY_ESCAPED: usize = 2;

/// The page overhead of a store that no probe sized, beyond its event overhead: 374 bytes for the fields of
/// a `SlicePage` (the addressee, the channel, the 3-digit index and total, and the end key), and 32 bytes
/// for the escape of up to 32 quote characters in a nickname. `page_frame_overhead` measures the same 374 and
/// the escapes of the session, and the engine always sets that value.
const PAGE_OVERHEAD_UNPROBED: usize = 406;

/// The bytes of a signed `SlicePage` frame of this session that its rows do not fill. It is the frame of
/// one row, less the bytes of that row, at the worst shape: a 3-digit index and total, an end key, and the
/// longer channel name. The frame is built and serialized, so a quote in the nickname is escaped, and the
/// fields of the kind are counted, as the wire writes them.
///
/// # Examples
///
/// A page of this session fits one frame with the rows that its overhead leaves room for.
///
/// The probe signs a one-row page frame and a two-row page frame. A row costs their difference, so the overhead
/// is the one-row frame less one row. If a frame does not serialize, the result is `usize::MAX`, and the probe
/// logs an error.
///
/// ```
/// use habilis_network_doc::page_frame_overhead;
/// use habilis_network_protocol::{MeshId, Nickname};
///
/// let mesh = MeshId::try_new("3JdXQ9vrT6yaHUx8D5NwPc1qEb2f7tr4V2R4NcAzv6MmL3N2nSxpRCYZBz8dL7wyqjW")
///     .unwrap_or_else(|_| MeshId::from("test"));
/// let overhead = page_frame_overhead(&mesh, &Nickname::from("peer"));
/// assert!(overhead < 1_000);
/// ```
#[must_use]
pub fn page_frame_overhead(mesh: &MeshId, nickname: &Nickname) -> usize {
    let one = page_frame_len(mesh, nickname, 1);
    let two = page_frame_len(mesh, nickname, 2);
    if one == usize::MAX {
        tracing::error!(target: "habilis_network::gossip", "the page frame overhead probe did not serialize its frame");
    }
    one.saturating_sub(two.saturating_sub(one))
}

/// The length of a signed `SlicePage` frame of `rows` rows, at the worst shape of the page: index 997
/// of 999 pages, so both numbers take 3 digits, and the page has an end key. It is a middle page: the
/// last page has no end key, and a frame that the wire refuses sizes nothing.
fn page_frame_len(mesh: &MeshId, nickname: &Nickname, rows: usize) -> usize {
    let entries: Vec<DigestEntry> = (0..2000u64)
        .map(|index| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&index.to_be_bytes());
            DigestEntry::new(
                AuthorKey::from(bytes),
                u64::MAX,
                ContentHash::of(&index.to_be_bytes()),
            )
        })
        .collect();
    let Ok(page) = DigestPage::build(&entries, rows, 997, 999) else {
        return usize::MAX;
    };
    let kind = MessageKind::SlicePage {
        to: AuthorKey::from([0xff; 32]),
        channel: Channel::State,
        page,
    };
    let Ok(body) = MessageBody::try_new("{}") else {
        return usize::MAX;
    };
    let signed = Message::new_frame(mesh, nickname, kind, body).sign(&Identity::generate());
    signed
        .serialize()
        .map_or(usize::MAX, |frame| frame.into_bytes().len())
}

/// The frame overhead of the worst case: a State event with the longest mesh id (511 bytes) and the longest
/// nickname (32 emoji). A test pins it against the probe. Pass it to [`SliceStore::new`] only where no probe
/// of the session is possible.
const WORST_FRAME_OVERHEAD: usize = 979;

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

/// The frame overhead of a session on `channel`: the bytes of a signed channel event that its body does not
/// fill. It is the envelope, the mesh id, the nickname as JSON, and the channel name. The probe signs and
/// serializes a real frame with an empty body, and takes off the escaped empty body, so a quote in the
/// nickname and the length of the channel name are counted. A store on `channel` takes a body of at most
/// `slice_bytes` minus this overhead, escaped, and the frame then fits.
///
/// If the probe cannot serialize its frame, the result is `usize::MAX`: the cap is then zero, and every
/// write is refused as too large. That is the fail-closed answer, and it is a bug, not a state of a session.
///
/// # Examples
///
/// ```
/// use habilis_network_doc::{frame_overhead, worst_frame_overhead};
/// use habilis_network_protocol::{Channel, MeshId, Nickname};
///
/// let mesh = MeshId::from("test");
/// let overhead = frame_overhead(Channel::State, &mesh, &Nickname::from("peer"));
/// assert!(overhead < worst_frame_overhead());
/// ```
#[must_use]
pub fn frame_overhead(channel: Channel, mesh: &MeshId, nickname: &Nickname) -> usize {
    let Ok(body) = MessageBody::try_new("") else {
        return usize::MAX;
    };
    let Ok(frame) = Message::new_channel_event(mesh, nickname, body, channel)
        .sign(&Identity::generate())
        .serialize()
    else {
        tracing::error!(target: "habilis_network::gossip", "the frame overhead probe did not serialize its frame");
        return usize::MAX;
    };
    frame.into_bytes().len() - EMPTY_BODY_ESCAPED
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
    /// The most authors one store holds. The default is 1024, the cap of the live roster. The
    /// pending set holds as many keys.
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
        Self::new(MAX_MESSAGE_SIZE, Duration::from_secs(1), 1024, 5)
    }
}

/// Why the store refused a write.
///
/// # Examples
///
/// ```
/// use habilis_network_doc::SliceError;
///
/// let error = SliceError::TooManyAuthors { limit: 1024 };
/// assert_eq!(error.to_string(), "the store holds 1024 authors already");
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
    /// The value holds the reserved `$chunks` key, which only a chunk pointer may carry.
    Reserved,
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
            Self::Reserved => write!(f, "the value holds the reserved \"$chunks\" key"),
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
/// use habilis_network_doc::{SliceLimits, SliceStore, worst_frame_overhead};
/// use habilis_network_protocol::Channel;
///
/// let store = SliceStore::new(Channel::Meta, SliceLimits::default(), worst_frame_overhead());
/// assert_eq!(store.limits().max_authors, 1024);
/// ```
#[derive(Debug)]
pub struct SliceStore {
    channel: Channel,
    key: Option<SymmetricKey>,
    limits: SliceLimits,
    frame_overhead: usize,
    /// The bytes of a `SlicePage` frame that its rows do not fill, as `page_frame_overhead` measures them.
    page_overhead: usize,
    slices: HashMap<AuthorKey, Slice>,
    buckets: HashMap<AuthorKey, Bucket>,
    /// The gone keys, oldest first, with the time each one left.
    gone: VecDeque<(AuthorKey, Instant)>,
    /// The frames of authors that are not in the roster yet. They wait for [`SliceStore::take_pending`].
    pending: PendingSlices,
}

/// One held slice: its signed frame, its version, the hash of the frame, its value, and the
/// time it was kept.
#[derive(Debug)]
struct Slice {
    frame: Verified,
    version: u64,
    hash: ContentHash,
    value: SliceValue,
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
        let pending = PendingSlices::new(limits.max_authors, tuning::alive_timeout());
        Self {
            channel,
            key: None,
            limits,
            frame_overhead,
            page_overhead: frame_overhead + PAGE_OVERHEAD_UNPROBED,
            slices: HashMap::new(),
            buckets: HashMap::new(),
            gone: VecDeque::new(),
            pending,
        }
    }

    /// Sets the page overhead that the rows of a digest page must leave room for. The engine sets the value
    /// that `page_frame_overhead` measures for its session.
    #[must_use]
    pub fn with_page_overhead(mut self, page_overhead: usize) -> Self {
        self.page_overhead = page_overhead;
        self
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
        self.slices.get(key).and_then(|slice| match &slice.value {
            SliceValue::Inline(value) => Some(value),
            SliceValue::Pointer(_) => None,
        })
    }

    /// The pointer that the slice of `key` holds, when it holds one in place of a value.
    #[must_use]
    pub fn pointer(&self, key: &AuthorKey) -> Option<&ChunkPointer> {
        self.slices.get(key).and_then(|slice| match &slice.value {
            SliceValue::Inline(_) => None,
            SliceValue::Pointer(pointer) => Some(pointer),
        })
    }

    /// Returns the signed frame held for `key`, which a resend sends. No caller yet.
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
            .filter(|(_, slice)| !slice.value.is_tombstone())
            .map(|(key, slice)| {
                let hex = String::from_utf8_lossy(&key.hex()).into_owned();
                (hex, slice.value.to_value())
            })
            .collect()
    }

    /// Checks a frame the way [`SliceStore::ingest`] does, and returns its version and value.
    fn read(&self, frame: &Verified) -> Result<(u64, SliceValue), SliceError> {
        if frame.kind != self.channel.event_kind() {
            return Err(SliceError::WrongChannel);
        }
        let signed = frame.serialize().map_err(|_| SliceError::Malformed)?;
        if signed.len() > self.limits.slice_bytes {
            return Err(SliceError::TooLarge {
                bytes: signed.len(),
                limit: self.limits.slice_bytes,
            });
        }
        let plain = wire::decrypt_body(frame.body.as_str(), self.key.as_ref())
            .ok_or(SliceError::Malformed)?;
        let body: SliceBody = serde_json::from_str(&plain).map_err(|_| SliceError::Malformed)?;
        if !(body.value.is_object() || body.value.is_null()) {
            return Err(SliceError::Malformed);
        }
        if body.value.get(CHUNKS_KEY).is_none() {
            return Ok((body.version, SliceValue::Inline(body.value)));
        }
        if body
            .value
            .as_object()
            .is_some_and(|object| object.len() > 1)
        {
            return Err(SliceError::Reserved);
        }
        let pointer = ChunkPointer::parse(&body.value).ok_or(SliceError::Malformed)?;
        Ok((body.version, SliceValue::Pointer(pointer)))
    }

    /// Holds a frame of an author that is not in the roster yet, until [`SliceStore::take_pending`]
    /// returns it.
    ///
    /// # Errors
    ///
    /// Returns the error of [`SliceStore::ingest`] for a frame it would refuse as malformed, too
    /// large or on another channel, and `GoneKey` for a key that said goodbye.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_doc::{SliceLimits, SliceStore, worst_frame_overhead};
    /// use habilis_network_protocol::{Channel, Identity, MeshId, Message, MessageBody, Nickname};
    /// use habilis_network_util::clock::Instant;
    ///
    /// let mut store = SliceStore::new(Channel::Meta, SliceLimits::default(), worst_frame_overhead());
    /// let identity = Identity::generate();
    /// let body = MessageBody::try_new(r#"{"version":1,"value":{}}"#).expect("a slice body");
    /// let frame = Message::new_channel_event(&MeshId::from("demo"), &Nickname::from("peer"), body, Channel::Meta).sign(&identity);
    /// store.hold(&frame, Instant::now()).expect("a well-formed frame is held");
    /// assert!(store.view().is_empty());
    /// ```
    pub fn hold(&mut self, frame: &Verified, now: Instant) -> Result<(), SliceError> {
        let (version, _) = self.read(frame)?;
        let key = frame.key();
        if self.is_gone(&key) {
            return Err(SliceError::GoneKey);
        }
        self.pending.hold(frame, version, now);
        Ok(())
    }

    /// Takes the held frame of `key` out of the pending set, unless its TTL ended at `now`.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_doc::{SliceLimits, SliceStore, worst_frame_overhead};
    /// use habilis_network_protocol::{AuthorKey, Channel};
    /// use habilis_network_util::clock::Instant;
    ///
    /// let mut store = SliceStore::new(Channel::Meta, SliceLimits::default(), worst_frame_overhead());
    /// assert!(store.take_pending(&AuthorKey::from([1u8; 32]), Instant::now()).is_none());
    /// ```
    pub fn take_pending(&mut self, key: &AuthorKey, now: Instant) -> Option<Verified> {
        self.pending.expire(now);
        self.pending.take(key)
    }

    /// Takes a verified slice frame into the slice of its author, and says what it did.
    ///
    /// The key is the frame's author, so a frame only ever writes its own slice. A `live` frame
    /// that carries a new version spends one token of its author. A resend, with `live` false,
    /// never spends one. No caller sends a resend yet.
    pub fn ingest(
        &mut self,
        frame: &Verified,
        // True for a live broadcast, false for a resend (no caller yet).
        live: bool,
        now: Instant,
    ) -> SliceIngest {
        let (version, value) = match self.read(frame) {
            Ok(read) => read,
            Err(error) => return SliceIngest::Refused(error),
        };
        let key = frame.key();
        if self.is_gone(&key) {
            return SliceIngest::Refused(SliceError::GoneKey);
        }
        let hash = frame.content_hash();
        let is_new = match self.slices.get(&key) {
            None => true,
            Some(held) => match version.cmp(&held.version) {
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
            version,
            hash,
            value,
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
    /// [`SliceError::Malformed`] when the body does not build, [`SliceError::Reserved`] when the value holds the `$chunks` key, [`SliceError::Seal`] when the
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

    /// Makes the draft of the own tombstone of `own`, the farewell of a leaving member.
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

    /// Moves each tombstone that has lasted its TTL to the gone set, drops each gone key that has
    /// lasted the gone TTL, and drops each held frame that has waited for the alive timeout.
    /// Expires the tombstones, the gone keys and the held frames whose time has come at `now`.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_doc::{SliceLimits, SliceStore, worst_frame_overhead};
    /// use habilis_network_protocol::Channel;
    /// use habilis_network_util::clock::Instant;
    ///
    /// let mut store = SliceStore::new(Channel::Meta, SliceLimits::default(), worst_frame_overhead());
    /// store.expire(Instant::now());
    /// assert!(store.view().is_empty());
    /// ```
    pub fn expire(&mut self, now: Instant) {
        let ttl = self.limits.tombstone_ttl;
        let expired: Vec<AuthorKey> = self
            .slices
            .iter()
            .filter(|(_, slice)| {
                slice.value.is_tombstone() && now.saturating_duration_since(slice.since) >= ttl
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
        self.pending.expire(now);
    }

    /// Drops the slice and the bucket of `key`, and puts the key in the gone set.
    ///
    /// The engine calls it for a signed goodbye and for a replaced run. A key that lapses quiet goes through
    /// [`SliceStore::release`] instead: that key can return, so it gets no gone entry.
    pub fn forget(&mut self, key: &AuthorKey, now: Instant) {
        self.slices.remove(key);
        self.buckets.remove(key);
        self.pending.take(key);
        self.keep_gone(*key, now);
    }

    /// Drops the slice and the bucket of `key`, and keeps no gone entry and no pending frame.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_doc::{SliceLimits, SliceStore, worst_frame_overhead};
    /// use habilis_network_protocol::{AuthorKey, Channel};
    ///
    /// let mut store = SliceStore::new(Channel::Meta, SliceLimits::default(), worst_frame_overhead());
    /// store.release(&AuthorKey::from([1u8; 32]));
    /// assert_eq!(store.held_keys().count(), 0);
    /// ```
    pub fn release(&mut self, key: &AuthorKey) {
        self.slices.remove(key);
        self.buckets.remove(key);
        self.pending.take(key);
    }

    /// Returns the keys that hold a slice in this store, tombstones included.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_doc::{SliceLimits, SliceStore, worst_frame_overhead};
    /// use habilis_network_protocol::Channel;
    ///
    /// let store = SliceStore::new(Channel::Meta, SliceLimits::default(), worst_frame_overhead());
    /// assert_eq!(store.held_keys().count(), 0);
    /// ```
    pub fn held_keys(&self) -> impl Iterator<Item = AuthorKey> + '_ {
        self.slices.keys().copied()
    }

    /// Moves the slice of `key` into the pending set, for a key that lost its nickname and can return.
    /// The slice comes back on `take_pending` when the key rejoins, and it expires with the pending TTL.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_doc::{SliceLimits, SliceStore, worst_frame_overhead};
    /// use habilis_network_protocol::{AuthorKey, Channel};
    /// use habilis_network_util::clock::Instant;
    ///
    /// let mut store = SliceStore::new(Channel::Meta, SliceLimits::default(), worst_frame_overhead());
    /// store.park(&AuthorKey::from([1u8; 32]), Instant::now());
    /// assert!(store.view().is_empty());
    /// ```
    pub fn park(&mut self, key: &AuthorKey, now: Instant) {
        if let Some(slice) = self.slices.remove(key) {
            self.pending.hold(&slice.frame, slice.version, now);
        }
    }

    /// The number of rows that one digest page holds, and so the number of keys that one pull carries. It is
    /// derived from the page overhead, so a page fits one message. A page is never sealed, because its kind
    /// is never sealed, so a sealed and a plain store of one session have the same rows. The overhead depends on
    /// the mesh id and the nickname of the session, so two nodes can have different rows.
    /// A pull holds the keys of one page of the holder. The holder serves at most one of its pages, so the
    /// counts do not have to agree.
    #[must_use]
    pub fn page_rows(&self) -> usize {
        let budget = MAX_MESSAGE_SIZE.saturating_sub(self.page_overhead);
        (budget / PAGE_ROW).max(1)
    }

    /// The stored entries, sorted by key.
    fn sorted_entries(&self) -> Vec<DigestEntry> {
        let mut entries: Vec<DigestEntry> = self
            .slices
            .iter()
            .map(|(key, slice)| DigestEntry::new(*key, slice.version, slice.hash))
            .collect();
        entries.sort_by(|left, right| {
            let (left, right) = (left.key(), right.key());
            left.as_bytes().cmp(right.as_bytes())
        });
        entries
    }

    /// Returns the root of the version digest: the hash and the number of pages.
    ///
    /// # Panics
    ///
    /// Never: the number of pages is at least one.
    #[must_use]
    pub fn digest(&self) -> DigestRoot {
        let sorted = self.sorted_entries();
        let total: usize = sorted.len().div_ceil(self.page_rows()).max(1);
        DigestRoot::new(page_hash(&sorted), total).expect("a digest has at least one page")
    }

    /// Returns page `index` of the version digest, or `None` past the last page. Each call reads
    /// the store again. Use [`SliceStore::pages`] to read every page from one snapshot.
    ///
    /// # Panics
    ///
    /// Never: the store lists its entries sorted, and the rows and the total are at least one.
    #[must_use]
    pub fn page(&self, index: usize) -> Option<DigestPage> {
        let (sorted, rows, total) = self.paging();
        if index >= total {
            return None;
        }
        Some(build_page(&sorted, rows, index, total))
    }

    /// The sorted entries of the store, the rows of a page, and the number of pages, from one snapshot.
    fn paging(&self) -> (Vec<DigestEntry>, usize, usize) {
        let sorted = self.sorted_entries();
        let rows = self.page_rows();
        let total = sorted.len().div_ceil(rows).max(1);
        (sorted, rows, total)
    }

    /// Returns every page of the version digest, all built from one snapshot of the store.
    ///
    /// Page `index` covers the keys from the page's first key up to the next page's first key.
    /// The first page starts at the zero key, so every key is in some page.
    ///
    /// # Panics
    ///
    /// Never: the store lists its entries sorted, and the rows and the total are at least one.
    pub fn pages(&self) -> impl Iterator<Item = DigestPage> {
        let (sorted, rows, total) = self.paging();
        (0..total).map(move |index| build_page(&sorted, rows, index, total))
    }

    /// Whether the root of this store is `root`, so two peers with equal stores need one message.
    #[must_use]
    pub fn matches(&self, root: &ContentHash) -> bool {
        page_hash(&self.sorted_entries()) == *root
    }

    /// The keys that `page` lists and this store would take: a key it lacks, or a key at a lower
    /// version, or at the same version with a lower hash. A gone key is never wanted. This is the
    /// pull of the asker.
    pub fn wanted_from<'a>(&'a self, page: &'a DigestPage) -> impl Iterator<Item = AuthorKey> + 'a {
        let listed = page.entries().iter();
        let unknown = listed.filter(move |entry| !self.is_gone(&entry.key()));
        unknown
            .filter(move |entry| match self.slices.get(&entry.key()) {
                None => true,
                Some(held) => {
                    entry.version() > held.version
                        || (entry.version() == held.version && entry.hash() < held.hash)
                }
            })
            .map(DigestEntry::key)
    }

    /// The frames of the held keys among `keys`, the answer to a pull. It answers at most one
    /// page of keys: the first `page_rows` distinct keys of `keys` are looked up, and the rest are ignored, so
    /// the asker pulls again for them. A gone key is never held, so it is never served.
    pub fn serve<'a>(&'a self, keys: &'a [AuthorKey]) -> impl Iterator<Item = Verified> + 'a {
        let mut asked = HashSet::new();
        let distinct = keys.iter().filter(move |key| asked.insert(**key));
        let first = distinct.take(self.page_rows());
        let held = first.filter_map(move |key| self.slices.get(key));
        held.map(|slice| slice.frame.clone())
    }

    /// The number of author buckets, for the tests that check a refused key keeps none.
    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// The number of keys in the gone set, for the tests that check a key takes one entry.
    #[cfg(test)]
    fn gone_count(&self) -> usize {
        self.gone.len()
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
        if value.get(CHUNKS_KEY).is_some() {
            return Err(SliceError::Reserved);
        }
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

    /// Whether `key` is in the gone set: a signed goodbye or a replaced run put it there, and the store refuses its
    /// slices until the gone TTL ends. A key that was only released is not gone.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_doc::{SliceLimits, SliceStore, worst_frame_overhead};
    /// use habilis_network_protocol::{AuthorKey, Channel};
    ///
    /// let store = SliceStore::new(Channel::Meta, SliceLimits::default(), worst_frame_overhead());
    /// assert!(!store.is_gone(&AuthorKey::from([1u8; 32])));
    /// ```
    #[must_use]
    pub fn is_gone(&self, key: &AuthorKey) -> bool {
        self.gone.iter().any(|(gone, _)| gone == key)
    }

    /// Adds `key` to the gone set, and drops the oldest gone key when the set holds `max_authors` keys: the set holds
    /// a key for each author the store can hold. A key that is already gone is moved to the end, so it takes one entry.
    /// An evicted key that is outside the roster is not applied again, as the engine holds its slice as pending until it
    /// joins. A quiet key that is evicted is not protected: the cap makes this need more than `max_authors` gone keys
    /// inside the gone TTL. The case is a peer that missed the `Left` of a member but got its tombstone: the key is
    /// quiet there, and only the gone set refuses a late old slice of it.
    fn keep_gone(&mut self, key: AuthorKey, now: Instant) {
        self.gone.retain(|(held, _)| *held != key);
        if self.gone.len() >= self.limits.max_authors {
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

/// Builds page `index` of `total` from the sorted entries of a store. A store lists its entries sorted, and
/// its rows and total are at least one, so the build cannot refuse them.
fn build_page(sorted: &[DigestEntry], rows: usize, index: usize, total: usize) -> DigestPage {
    DigestPage::build(sorted, rows, index, total)
        .expect("a store lists sorted entries, with rows and total at least one")
}

#[cfg(test)]
mod tests {
    use super::{
        LocalDraft, PAGE_OVERHEAD_UNPROBED, SliceError, SliceIngest, SliceLimits, SliceStore,
        WORST_FRAME_OVERHEAD, wire,
    };
    use crate::ChunkPointer;
    use habilis_network_chunks::Root;
    use habilis_network_protocol::digest::{DigestEntry, DigestPage};
    use habilis_network_protocol::messages::{MessageError, Verified};
    use habilis_network_protocol::{
        AuthorKey, Channel, ContentHash, Identity, Lookup, Mesh, MeshConfig, MeshId, MeshName,
        Message, MessageBody, Nickname, RelayLadder, Seed, SymmetricKey,
    };
    use habilis_network_util::consts::MAX_MESSAGE_SIZE;
    use serde_json::{Map, Value, json};
    use std::time::{Duration, Instant};

    /// The longest mesh id text, in bytes. It is `MeshId`'s own limit.
    const MAX_MESH_ID_LEN: usize = 512;

    /// The longest nickname, in bytes: 32 characters of up to 4 bytes each.
    const MAX_NICKNAME_LEN: usize = 128;

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

    /// Applies `frame` on the resend path, which never spends a token. No caller yet.
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
    fn ingest_refuses_a_value_with_the_reserved_chunks_key() {
        let mut store = store();
        assert_eq!(
            apply(&mut store, &frame(key(1), 1, json!({"$chunks": 1, "a": 2}))),
            SliceIngest::Refused(SliceError::Reserved),
            "an inline value with the chunks key must be refused as reserved"
        );
        assert_eq!(store.authors(), 0, "a reserved value must leave no author");
    }

    #[test]
    fn prepare_local_refuses_a_value_with_the_reserved_chunks_key() {
        let mut store = store();
        assert_eq!(
            store
                .prepare_local(&key(1), object(json!({"$chunks": 1})), Instant::now())
                .map(|_| ()),
            Err(SliceError::Reserved),
            "a write with the chunks key must be refused as reserved"
        );
    }

    fn pointer_value() -> (ChunkPointer, Value) {
        let pointer = ChunkPointer::new(Root::from_bytes([7; 32]), 100_000);
        let value = pointer.to_value();
        (pointer, value)
    }

    #[test]
    fn ingest_applies_a_pointer_slice_and_keeps_the_pointer() {
        let mut store = store();
        let (pointer, value) = pointer_value();
        assert_eq!(
            apply(&mut store, &frame(key(1), 1, value)),
            SliceIngest::Applied,
            "a slice that is exactly one pointer must apply"
        );
        assert_eq!(
            store.pointer(&key(1)),
            Some(&pointer),
            "the store must keep the pointer"
        );
        assert_eq!(
            store.value(&key(1)),
            None,
            "a pointer slice holds no inline value"
        );
    }

    #[test]
    fn view_reads_a_pointer_slice_as_its_pointer_value() {
        let mut store = store();
        let (_, value) = pointer_value();
        apply(&mut store, &frame(key(1), 1, value.clone()));
        let hex = String::from_utf8_lossy(&key(1).hex()).into_owned();
        assert_eq!(
            store.view().get(&hex),
            Some(&value),
            "the view must show the pointer, not drop the slice"
        );
    }

    #[test]
    fn ingest_refuses_a_chunks_key_that_is_not_a_pointer() {
        let mut store = store();
        for value in [
            json!({"$chunks": 1}),
            json!({"$chunks": {"root": "zz", "size": 1}}),
            json!({"$chunks": {"root": "00", "size": 1, "extra": 1}}),
        ] {
            assert_eq!(
                apply(&mut store, &frame(key(1), 1, value.clone())),
                SliceIngest::Refused(SliceError::Malformed),
                "a lone chunks key that is no pointer must be malformed: {value}"
            );
        }
    }

    #[test]
    fn a_nested_chunks_key_is_not_reserved() {
        let mut store = store();
        assert!(
            store
                .prepare_local(
                    &key(1),
                    object(json!({"a": {"$chunks": 1}})),
                    Instant::now()
                )
                .is_ok(),
            "only the top-level key is reserved"
        );
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
    fn a_passworded_page_holds_the_rows_of_a_plain_page() {
        let channel_key = SymmetricKey::from([3u8; 32]);
        let plain_body = MessageBody::from(r#"{"version":1,"value":{}}"#);
        let sealed = wire::encrypt_body(&plain_body, &channel_key).expect("a sealed body");
        let overhead = super::frame_overhead(
            Channel::Meta,
            &MeshId::from("m".repeat(62).as_str()),
            &Nickname::from("nick"),
        );
        let limits = SliceLimits::default();
        let mut plain = SliceStore::new(Channel::Meta, limits, overhead);
        let mut passworded =
            SliceStore::new(Channel::Meta, limits, overhead).with_key(Some(channel_key));
        for index in 0..40 {
            assert_eq!(
                apply(
                    &mut plain,
                    &frame_with_body(many_key(index), plain_body.as_str())
                ),
                SliceIngest::Applied,
                "a plain slice of key {index} must apply"
            );
            assert_eq!(
                apply(
                    &mut passworded,
                    &frame_with_body(many_key(index), sealed.as_str())
                ),
                SliceIngest::Applied,
                "a sealed slice of key {index} must apply"
            );
        }
        let plain_first = plain.pages().next().expect("a page");
        let plain_rows: usize = plain_first.entries().len();
        let sealed_first = passworded.pages().next().expect("a page");
        let sealed_rows: usize = sealed_first.entries().len();
        assert!(
            plain_rows < 40,
            "the page holds fewer rows than the 40 slices, so it is one page of many"
        );
        assert_eq!(
            sealed_rows, plain_rows,
            "a page of a passworded store holds the rows of a plain page at the same overhead"
        );
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
        let typical = super::frame_overhead(
            Channel::Meta,
            &MeshId::from("test"),
            &nickname_with_quotes(9, 0),
        );
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
        store.expire(start);
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
    fn a_released_key_has_no_pending_frame() {
        let mut store = store();
        let now = Instant::now();
        store
            .hold(&frame(key(1), 1, json!({})), now)
            .expect("a stranger frame must be held");
        store.release(&key(1));
        assert!(
            store.take_pending(&key(1), now).is_none(),
            "release must clear the pending frame too"
        );
    }

    #[test]
    fn the_default_store_holds_1024_authors() {
        let mut store = store();
        let now = Instant::now();
        for index in 0..1024 {
            assert_eq!(
                store.ingest(&frame(many_key(index), 1, json!({})), true, now),
                SliceIngest::Applied,
                "author {index} must be accepted by the default store"
            );
        }
        assert_eq!(
            store.authors(),
            1024,
            "the default store must hold 1024 authors"
        );
        assert_eq!(
            apply(&mut store, &frame(many_key(1024), 1, json!({}))),
            SliceIngest::Refused(SliceError::TooManyAuthors { limit: 1024 }),
            "the 1025th author must be refused"
        );
    }

    #[test]
    fn a_forgotten_key_is_accepted_again_after_the_gone_ttl() {
        let mut store = store();
        let start = Instant::now();
        store.forget(&key(1), start);
        store.expire(start + Duration::from_mins(119));
        assert_eq!(
            apply(&mut store, &frame(key(1), 1, json!({}))),
            SliceIngest::Refused(SliceError::GoneKey),
            "a forgotten key must stay refused before the gone TTL ends"
        );
        store.expire(start + Duration::from_hours(2));
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
    fn expire_frees_the_author_slot_after_the_ttl() {
        let mut store = store();
        let start = Instant::now();
        store.ingest(&frame(key(1), 1, json!({"a": 1})), false, start);
        store.ingest(&frame(key(1), 2, Value::Null), false, start);
        store.expire(start + Duration::from_mins(9));
        assert_eq!(
            store.authors(),
            1,
            "a tombstone must keep its slot before the TTL"
        );
        store.expire(start + Duration::from_mins(10));
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
        store.expire(start + Duration::from_mins(10));
        assert_eq!(
            apply(&mut store, &frame(key(1), 3, json!({"a": 3}))),
            SliceIngest::Refused(SliceError::GoneKey),
            "a gone key must be refused until the gone TTL ends"
        );
        assert_eq!(store.authors(), 0, "a refused gone key must leave no slice");
    }

    /// The gone set holds one key for each author the store can hold, so forgetting `max_authors` keys at once keeps
    /// the first one gone: the store does not evict it while there is room for it.
    #[test]
    fn a_gone_set_of_max_authors_keeps_its_first_key_gone() {
        let limits =
            SliceLimits::new(3072, Duration::from_secs(1), 300, 5).tombstone_ttl(Duration::ZERO);
        let mut store = small_store(limits);
        let start = Instant::now();
        for index in 1..=300 {
            store.forget(&many_key(index), start);
        }
        assert_eq!(
            apply(&mut store, &frame(many_key(1), 1, json!({"a": 1}))),
            SliceIngest::Refused(SliceError::GoneKey),
            "the first key of max_authors gone keys must still be gone"
        );
    }

    /// After many writes of many keys the store stays under its caps: the author cap holds for the applied slices,
    /// the pending set holds at most one frame for each author it can take, and the gone set holds at most `max_authors`
    /// keys. The test counts entries, not bytes: the byte bound of one slice has its own tests.
    #[test]
    fn the_store_stays_under_its_caps_after_many_writes() {
        let limits =
            SliceLimits::new(3072, Duration::from_secs(1), 20, 5).tombstone_ttl(Duration::ZERO);
        let mut store = small_store(limits);
        let now = Instant::now();
        for index in 1..=500 {
            store.ingest(&frame(many_key(index), 1, json!({"a": 1})), false, now);
            store
                .hold(&frame(many_key(index + 1000), 1, json!({})), now)
                .expect("the frame is well formed");
            store.forget(&many_key(index + 2000), now);
        }
        assert!(
            store.authors() <= 20,
            "the applied slices stay under the author cap"
        );
        let pending: usize = (1..=500)
            .filter(|index| store.take_pending(&many_key(index + 1000), now).is_some())
            .count();
        assert!(
            pending <= 20,
            "the pending set stays under its cap, not {pending}"
        );
        assert!(store.gone_count() <= 20, "the gone set stays under its cap");
    }

    /// A key that is forgotten twice takes one entry of the gone set, so a repeat does not push other keys out.
    #[test]
    fn a_key_forgotten_twice_takes_one_gone_entry() {
        let mut store = store();
        let now = Instant::now();
        store.forget(&key(1), now);
        store.forget(&key(1), now);
        assert_eq!(
            store.gone_count(),
            1,
            "a key forgotten twice is one gone entry"
        );
    }

    #[test]
    fn gone_set_keeps_its_cap_and_the_oldest_leaves_first() {
        let limits =
            SliceLimits::new(3072, Duration::from_secs(1), 300, 5).tombstone_ttl(Duration::ZERO);
        let mut store = small_store(limits);
        let start = Instant::now();
        for index in 1..=301 {
            let at = start + Duration::from_millis(u64::try_from(index).unwrap_or(0));
            store.ingest(&frame(many_key(index), 1, json!({})), false, at);
            store.ingest(&frame(many_key(index), 2, Value::Null), false, at);
            store.expire(at);
        }
        assert_eq!(
            apply(&mut store, &frame(many_key(1), 3, json!({"a": 3}))),
            SliceIngest::Applied,
            "the oldest gone key must leave the gone set when the set is full"
        );
        assert_eq!(
            apply(&mut store, &frame(many_key(301), 3, json!({"a": 3}))),
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
        super::frame_overhead(Channel::State, mesh, nickname)
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
            first_store.digest().root(),
            second_store.digest().root(),
            "equal stores must have one root"
        );
        assert!(
            second_store.matches(&first_store.digest().root()),
            "equal stores must match each other's root"
        );
        apply(&mut first_store, &frame(key(1), 2, json!({"a": 3})));
        assert_ne!(
            first_store.digest().root(),
            second_store.digest().root(),
            "a new version must change the root"
        );
        assert!(
            !second_store.matches(&first_store.digest().root()),
            "a changed store must not match the old root"
        );
    }

    /// The longest mesh id that a real mesh makes: 511 bytes, from a 32-char name and a long relay URL.
    fn longest_mesh_id() -> MeshId {
        let name = MeshName::try_new(&"a".repeat(32)).expect("a 32-char name");
        let mut best = None;
        for host in 1..400 {
            let url = format!("https://{}.example.com/", "r".repeat(host));
            let parsed: Result<RelayLadder, _> = url.parse();
            let Ok(ladder) = parsed else {
                continue;
            };
            let Ok(config) = MeshConfig::resolve(&[Lookup::Relay], Some(ladder), &[]) else {
                continue;
            };
            let Ok(mesh) = Mesh::try_new(Seed::new([4u8; 32]), name.clone(), config) else {
                continue;
            };
            let text = mesh.to_string();
            if text.len() > 512 {
                break;
            }
            if let Ok(id) = MeshId::try_new(&text) {
                best = Some(id);
            }
        }
        best.expect("a long valid mesh id")
    }

    /// The longest nickname: 32 emoji, 128 bytes.
    fn longest_nickname() -> Nickname {
        Nickname::from(&*"\u{1F600}".repeat(MAX_NICKNAME_LEN / 4))
    }

    /// The control at the longest real mesh id: every page of both channels, at the longest nickname.
    #[test]
    fn every_page_at_the_longest_mesh_id_fits_one_frame() {
        let mesh = longest_mesh_id();
        let nickname = longest_nickname();
        assert!(
            mesh.as_str().len() >= 500,
            "the test must run at a mesh id near the limit"
        );
        let page_overhead = super::page_frame_overhead(&mesh, &nickname);
        let limits = SliceLimits::new(MAX_MESSAGE_SIZE, Duration::from_secs(1), 256, 5);
        for channel in [Channel::Meta, Channel::State] {
            let mut store = SliceStore::new(
                channel,
                limits,
                super::frame_overhead(channel, &mesh, &nickname),
            )
            .with_page_overhead(page_overhead);
            for index in 0..256 {
                let body = json!({"version": u64::MAX, "value": {"n": index}});
                apply(
                    &mut store,
                    &frame_on(many_key(index), &body.to_string(), channel),
                );
            }
            let mut pages = 0;
            for page in store.pages() {
                pages += 1;
                let size = slice_page_frame(page, channel, &mesh, &nickname);
                assert!(
                    size.as_ref().is_ok_and(|size| *size <= MAX_MESSAGE_SIZE),
                    "a page on {channel:?} at the longest mesh id is refused: {size:?}"
                );
            }
            assert!(pages > 0, "a full store has pages");
        }
    }

    /// A nickname of `emoji` four-byte characters and `quotes` quote characters. Each quote is one byte in
    /// the nickname, and two bytes on the wire, where JSON escapes it.
    fn nickname_with_quotes(emoji: usize, quotes: usize) -> Nickname {
        let text = format!("{}{}", "\u{1F600}".repeat(emoji), "\"".repeat(quotes));
        Nickname::try_new(&text).expect("a nickname of 1 to 32 characters")
    }

    /// One row of a page with its comma: `["<64 hex>",18446744073709551615,"<64 hex>"],`, 157 bytes.
    const ROW_WITH_COMMA: usize = 157;

    /// A signed `SlicePage` of the worst shape (index 997 of 999, an end key, `state`) is the page probe
    /// plus exactly one row for each row. The frame is built here, independently of the probe, so a probe
    /// a few bytes short fails this test.
    #[test]
    fn a_worst_shape_page_frame_is_the_probe_plus_its_rows_exactly() {
        let mesh = MeshId::from("test");
        let nickname = nickname_with_quotes(9, 0);
        let overhead = super::page_frame_overhead(&mesh, &nickname);
        let sorted: Vec<DigestEntry> = (0..999u64 * 16 + 2)
            .map(|index| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&index.to_be_bytes());
                DigestEntry::new(
                    AuthorKey::from(bytes),
                    u64::MAX,
                    ContentHash::of(&index.to_be_bytes()),
                )
            })
            .collect();
        for rows in [1usize, 16] {
            let page =
                DigestPage::build(&sorted, rows, 997, 999).expect("a page of the worst shape");
            let kind = habilis_network_protocol::MessageKind::SlicePage {
                to: key(9),
                channel: Channel::State,
                page,
            };
            let body = MessageBody::try_new("{}").expect("a body");
            let signed =
                Message::new_frame(&mesh, &nickname, kind, body).sign(&Identity::generate());
            let wire = signed.serialize().expect("a worst-shape page serializes");
            let frame_len = wire.as_bytes().len();
            assert!(
                Message::parse(wire.as_bytes()).is_ok(),
                "a worst-shape page of {rows} rows does not parse: a frame that the wire refuses sizes nothing"
            );
            assert_eq!(
                frame_len,
                overhead + rows * ROW_WITH_COMMA,
                "a {rows}-row page of the worst shape is the probe plus its rows, exactly"
            );
        }
    }

    /// The largest local draft that the cap takes, on each channel, with a nickname of 32 quotes, is a
    /// signed channel event that serializes. The cap is the limit of the body, so a frame that does not
    /// serialize at the cap is a draft that the store took and the wire refuses.
    #[test]
    fn a_draft_at_the_cap_serializes_on_both_channels_with_quotes() {
        let mesh = MeshId::from("test");
        let nickname = nickname_with_quotes(0, 32);
        for channel in [Channel::Meta, Channel::State] {
            let limits = SliceLimits::new(MAX_MESSAGE_SIZE, Duration::from_secs(1), 256, 5);
            let draft_of = |len: usize| {
                let mut value = Map::new();
                value.insert("text".to_owned(), Value::String("a".repeat(len)));
                SliceStore::new(
                    channel,
                    limits,
                    super::frame_overhead(channel, &mesh, &nickname),
                )
                .prepare_local(&key(1), value, Instant::now())
                .ok()
            };
            let (mut low, mut high) = (0usize, 100_000usize);
            while low < high {
                let middle = (low + high).div_ceil(2);
                if draft_of(middle).is_some() {
                    low = middle;
                } else {
                    high = middle - 1;
                }
            }
            let draft = draft_of(low).expect("a draft fits at some length");
            let signed =
                Message::new_channel_event(&mesh, &nickname, draft.body().clone(), channel)
                    .sign(&Identity::generate());
            let frame = signed.serialize();
            assert!(
                frame.is_ok(),
                "a draft at the cap on {channel:?} with 32 quotes does not serialize: {:?}",
                frame.err()
            );
        }
    }

    /// Every page of both channels fits one frame at every nickname that holds quote characters. The quote
    /// is escaped in the JSON, so its frame is longer than its raw byte count. The sweep takes the most
    /// characters that fit 32 with each count of quotes, at both mesh ids.
    #[test]
    fn every_page_on_both_channels_fits_for_a_nickname_with_quotes() {
        let limits = SliceLimits::new(MAX_MESSAGE_SIZE, Duration::from_secs(1), 256, 5);
        let meshes = [MeshId::from("test"), longest_mesh_id()];
        for mesh in &meshes {
            for quotes in 0..=32 {
                let nickname = nickname_with_quotes(32 - quotes, quotes);
                let page_overhead = super::page_frame_overhead(mesh, &nickname);
                for channel in [Channel::Meta, Channel::State] {
                    let mut store = SliceStore::new(
                        channel,
                        limits,
                        super::frame_overhead(channel, mesh, &nickname),
                    )
                    .with_page_overhead(page_overhead);
                    for index in 0..256 {
                        let body = json!({"version": u64::MAX, "value": {"n": index}});
                        apply(
                            &mut store,
                            &frame_on(many_key(index), &body.to_string(), channel),
                        );
                    }
                    for page in store.pages() {
                        let size = slice_page_frame(page, channel, mesh, &nickname);
                        assert!(
                            size.as_ref().is_ok_and(|size| *size <= MAX_MESSAGE_SIZE),
                            "a page on {channel:?} with {quotes} quotes is refused: {size:?}"
                        );
                    }
                }
            }
        }
    }

    /// A nickname of exactly `bytes` bytes, from 1- to 4-byte characters, within the 32-character limit.
    fn nickname_of_bytes(bytes: usize) -> Nickname {
        let mut text = String::new();
        let mut left = bytes;
        while left > 0 {
            let size = left.min(4);
            let ch = match size {
                4 => '\u{1F600}',
                3 => '\u{4E2D}',
                2 => '\u{00E9}',
                _ => 'n',
            };
            text.push(ch);
            left -= ch.len_utf8();
        }
        Nickname::try_new(&text).expect("a nickname of 1 to 32 characters")
    }

    /// The bytes of the signed `SlicePage` frame of `page` on `channel`, at `mesh` and `nickname`.
    fn slice_page_frame(
        page: DigestPage,
        channel: Channel,
        mesh: &MeshId,
        nickname: &Nickname,
    ) -> Result<usize, MessageError> {
        let kind = habilis_network_protocol::MessageKind::SlicePage {
            to: key(9),
            channel,
            page,
        };
        let mut message = Message::fixture(kind, "");
        message.mesh = mesh.clone();
        message.author = nickname.clone();
        Verified::fixture_unchecked(message, key(9))
            .serialize()
            .map(|frame| frame.into_bytes().len())
    }

    /// Every page of both channels fits one frame at every nickname length from 1 to 128 bytes, at the
    /// 62-byte fixture mesh id and at the 511-byte longest mesh id. The store holds 256 authors, so its
    /// pages reach two index digits.
    /// A store that no probe sized still leaves room for a page of the worst nickname, at both mesh ids.
    #[test]
    fn the_default_page_overhead_covers_the_probe_at_the_worst_nickname() {
        let nickname = nickname_with_quotes(0, 32);
        for mesh in [MeshId::from("test"), longest_mesh_id()] {
            let probe = super::page_frame_overhead(&mesh, &nickname);
            let default =
                super::frame_overhead(Channel::Meta, &mesh, &nickname) + PAGE_OVERHEAD_UNPROBED;
            assert!(
                default >= probe,
                "the default page overhead {default} is below the probe {probe}"
            );
        }
    }

    #[test]
    fn every_page_on_both_channels_fits_at_every_nickname_length() {
        let limits = SliceLimits::new(MAX_MESSAGE_SIZE, Duration::from_secs(1), 256, 5);
        let meshes = [MeshId::from("test"), longest_mesh_id()];
        for mesh in &meshes {
            for bytes in 1..=MAX_NICKNAME_LEN {
                let nickname = nickname_of_bytes(bytes);
                let page_overhead = super::page_frame_overhead(mesh, &nickname);
                for channel in [Channel::Meta, Channel::State] {
                    let mut store = SliceStore::new(
                        channel,
                        limits,
                        super::frame_overhead(channel, mesh, &nickname),
                    )
                    .with_page_overhead(page_overhead);
                    for index in 0..256 {
                        let body = json!({"version": u64::MAX, "value": {"n": index}});
                        let frame = frame_on(many_key(index), &body.to_string(), channel);
                        apply(&mut store, &frame);
                    }
                    for page in store.pages() {
                        let size = slice_page_frame(page, channel, mesh, &nickname);
                        assert!(
                            size.as_ref().is_ok_and(|size| *size <= MAX_MESSAGE_SIZE),
                            "a page on {channel:?} at a {bytes} B nickname is refused: {size:?}"
                        );
                    }
                }
            }
        }
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
            store.digest().total(),
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

    /// A pull that names one held key many times gets one frame of it, not one per name.
    #[test]
    fn serve_answers_each_key_once() {
        let mut store = store();
        apply(&mut store, &frame(author_key(1), 1, json!({"n": 1})));
        let asked = vec![author_key(1); 18];
        assert_eq!(
            store.serve(&asked).count(),
            1,
            "one key named 18 times is one frame"
        );
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
        let total = store.digest().total();
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
                    page.covers(&entry.key()),
                    "a listed key must be in its page range"
                );
                let key = entry.key();
                let holders: usize = pages.iter().filter(|other| other.covers(&key)).count();
                assert_eq!(holders, 1, "a key must be in exactly one page range");
            }
        }
    }

    #[test]
    fn a_forgotten_key_is_never_wanted_or_listed() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        store.forget(&key(1), Instant::now());
        let high = peer_holding(&frame(key(1), 9, json!({"a": 9})));
        let page = high.page(0).expect("a page");
        assert_eq!(
            store.wanted_from(&page).count(),
            0,
            "a forgotten key must not be wanted"
        );
        assert_eq!(
            store.digest().total(),
            1,
            "the digest of a store with no key is one empty page"
        );
        assert!(
            store.page(0).expect("a page").entries().is_empty(),
            "a forgotten key must not be listed"
        );
    }

    /// A store that holds the one entry `key` at `version` with the frame `signed`.
    fn peer_holding(signed: &Verified) -> SliceStore {
        let mut peer = store();
        apply(&mut peer, signed);
        peer
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
    fn serve_returns_the_frame_of_a_tombstone() {
        let mut store = store();
        apply(&mut store, &frame(key(1), 1, json!({"a": 1})));
        apply(&mut store, &frame(key(1), 2, Value::Null));
        let served: Vec<Verified> = store.serve(&[key(1)]).collect();
        assert_eq!(served.len(), 1, "a held tombstone is served");
        let wire = served[0].serialize().expect("a served frame serializes");
        let text = String::from_utf8_lossy(wire.as_bytes()).into_owned();
        assert!(
            text.contains(r#"\"value\":null"#),
            "the served frame must carry the null value of the tombstone: {text}"
        );
        assert!(
            !text.contains(r#"\"a\":1"#),
            "the served frame must not carry the old value: {text}"
        );
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

    /// The probe of a channel event grows one byte for each byte of mesh id and of nickname, on each channel.
    #[test]
    fn frame_overhead_grows_one_byte_per_mesh_id_and_nickname_byte() {
        let mesh = MeshId::from("test");
        let short = Nickname::from("peer");
        let longer = Nickname::from("peers");
        for channel in [Channel::Meta, Channel::State] {
            assert_eq!(
                super::frame_overhead(channel, &mesh, &longer),
                super::frame_overhead(channel, &mesh, &short) + 1,
                "one more nickname byte is one more frame byte on {channel:?}"
            );
        }
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
                let other_total = other.digest().total();
                for page_index in 0..other_total {
                    let page = other.page(page_index).expect("a page");
                    assert_eq!(
                        node.wanted_from(&page).count(),
                        0,
                        "nothing must be wanted on {index}"
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

    /// Carries a pass of the sync from `from` to `to`: `from` pulls the keys it wants from `to`, page by page.
    /// A lossy pass drops some frames.
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
    fn a_malformed_frame_is_not_held() {
        let mut store = store();
        let bad = frame_with_body(key(1), "not json");
        assert!(
            matches!(store.hold(&bad, Instant::now()), Err(SliceError::Malformed)),
            "a malformed frame is refused by hold"
        );
        assert!(
            store.take_pending(&key(1), Instant::now()).is_none(),
            "a refused frame is not held"
        );
    }

    #[test]
    fn a_held_frame_is_taken_once_and_expires_after_its_ttl() {
        let mut store = store();
        let t0 = Instant::now();
        store
            .hold(&frame(key(1), 1, json!({})), t0)
            .expect("the frame is well formed");
        assert!(
            store
                .take_pending(&key(1), t0 + Duration::from_secs(91))
                .is_none(),
            "the held frame is gone after its TTL"
        );
        store
            .hold(&frame(key(1), 2, json!({})), t0)
            .expect("the frame is well formed");
        assert!(
            store.take_pending(&key(1), t0).is_some(),
            "a held frame is taken once"
        );
        assert!(
            store.take_pending(&key(1), t0).is_none(),
            "a taken frame is not held again"
        );
    }
}
