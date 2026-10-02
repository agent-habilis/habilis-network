//! Content-addressed chunks over data you already own.
//!
//! A file is a **merkle leaf row**: fixed 64 `KiB` chunks, each addressed by
//! `blake3` of its own bytes, plus an ordered list of those addresses that
//! names the file. Two properties fall out, and the crate exists for both:
//!
//! > **A chunk proves itself.** Hash what arrived, compare it to the address
//! > you asked for. No proof, no tree walk, no outboard — so a chunk is
//! > acceptable from any peer, with zero trust and no per-peer bookkeeping.
//!
//! > **The store never chooses where bytes live.** An origin's file stays
//! > exactly where the user put it; the store holds addresses beside it and
//! > reads through. That is what keeps serving a 500 GB tree a `stat` walk
//! > instead of a full read of it.
//!
//! # Why not bao
//!
//! `BLAKE3` threads a chunk counter into its compression function, so a bao
//! subtree hash is bound to *where* the bytes sit. Excellent as a proof of
//! placement, useless as a content address: the same 64 `KiB` at two offsets
//! hashes two ways, so nothing ever dedups and no peer can answer for a chunk
//! without first agreeing which file and which offset it came from. Placement
//! is proved here by the leaf row instead — leaf *k* belongs at offset
//! *k* × [`CHUNK_BYTES`], and the row is what the root commits to.
//!
//! That is also what separated this crate from the retired `habilis-network-blobs`:
//! blobs proved *placement* (bao outboards over one file), chunks proves
//! *content*. This crate replaced it after v0.6.0.
//!
//! # What this crate is not
//!
//! No transport, no ALPN, no framing. No discovery. No download scheduler —
//! that needs peer budgets and connection state, and making it generic is how
//! a blob-transfer library gets rebuilt by accident. No manifests, no shares,
//! no tokens. It takes a hash, some bytes and a chunk map. See
//! `tests/isolation.rs`, which fails the build if that stops being true.
//!
//! # Both runtimes
//!
//! The same store runs under tokio and in a browser, so every future here is
//! `?Send`: an `IndexedDB` backend holds `Rc`-flavoured state and an OPFS one is
//! pinned to a single Worker thread. Callers that need `Send` get it from their
//! own backend, not from this trait.

use std::fmt;
use std::future::Future;

use anyhow::{Result, bail};

/// Bytes per chunk.
///
/// Fixed offsets, deliberately, rather than content-defined chunking. CDC
/// dedups content that shifted, but it breaks the fixed `offset -> index`
/// mapping that lets a caller turn a byte range into chunk numbers without
/// consulting anything. Everything downstream — range reads, availability,
/// scheduling — depends on that mapping being arithmetic.
pub const CHUNK_BYTES: u64 = 64 * 1024;

/// [`CHUNK_BYTES`] as a `usize`, for slicing.
///
/// Written as a literal rather than a cast so it is correct on a 32-bit target
/// by construction; `chunk_bytes_agree` pins the two together.
pub const CHUNK_BYTES_USIZE: usize = 64 * 1024;

/// Domain separator for a root, so a root can never collide with the hash of a
/// chunk that happens to hold the same bytes.
const ROOT_CONTEXT: &[u8] = b"habilis-network-chunks/root/v1";

/// The address of one chunk: `blake3` over its bytes and nothing else.
///
/// Position-independent on purpose. Two files holding the same 64 `KiB` at any
/// offset, in any share, produce the same address and share one stored copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkHash([u8; 32]);

/// The name of a whole file: a commitment to its ordered leaf row.
///
/// A distinct type from [`ChunkHash`] rather than a bare `[u8; 32]`, because
/// the two are asked for in adjacent calls and swapping them would be a silent
/// bug — `get(root)` would simply find nothing rather than fail loudly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Root([u8; 32]);

macro_rules! digest_newtype {
    ($name:ident, $what:literal) => {
        impl $name {
            /// Wrap raw digest bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// The raw digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Lowercase hex, the form every backend keys records by.
            #[must_use]
            pub fn to_hex(&self) -> String {
                let mut out = String::with_capacity(64);
                for byte in self.0 {
                    use fmt::Write as _;
                    let _ = write!(out, "{byte:02x}");
                }
                out
            }

            /// Parse the form [`Self::to_hex`] writes.
            ///
            /// # Errors
            /// The text is not exactly 64 hex digits.
            pub fn from_hex(text: &str) -> Result<Self> {
                let bytes = text.as_bytes();
                if bytes.len() != 64 {
                    bail!(
                        concat!("a ", $what, " is 64 hex digits, got {}"),
                        bytes.len()
                    );
                }
                // Decode from bytes, never by slicing the `&str`: the guard
                // above counts bytes, and a slice that lands inside a
                // multibyte char panics. Any non-hex byte is a plain error.
                let mut out = [0u8; 32];
                for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
                    let (Some(high), Some(low)) = (hex_nibble(pair[0]), hex_nibble(pair[1])) else {
                        bail!(concat!("a ", $what, " is hex"));
                    };
                    *slot = (high << 4) | low;
                }
                Ok(Self(out))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.to_hex())
            }
        }
    };
}

/// One ASCII hex digit to its value, either case. `None` for anything else,
/// a UTF-8 continuation byte included.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

digest_newtype!(ChunkHash, "chunk hash");
digest_newtype!(Root, "root");

/// Address one chunk's bytes.
#[must_use]
pub fn chunk_hash(bytes: &[u8]) -> ChunkHash {
    ChunkHash(*blake3::hash(bytes).as_bytes())
}

/// How many chunks a file of `size` bytes occupies.
///
/// Zero for an empty file, which is a real case rather than an error: an empty
/// file has a root, holds no chunks, and is complete the moment it is known.
#[must_use]
pub fn chunk_count(size: u64) -> usize {
    usize::try_from(size.div_ceil(CHUNK_BYTES)).unwrap_or(usize::MAX)
}

/// A file's ordered leaf row, and the root that commits to it.
///
/// This is the whole merkle structure. The row proves placement — leaf *k*
/// belongs at offset *k* × [`CHUNK_BYTES`] — and each leaf proves its own bytes,
/// so verifying a chunk needs the row and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkMap {
    root: Root,
    leaves: Vec<ChunkHash>,
    size: u64,
}

impl ChunkMap {
    /// Build from a whole file already in memory.
    ///
    /// For anything that will not fit, feed [`ChunkMapBuilder`] instead — an
    /// origin hashing a 50 GB file must not be asked to hold it.
    #[must_use]
    pub fn build(bytes: &[u8]) -> Self {
        let mut builder = ChunkMapBuilder::new();
        for chunk in bytes.chunks(CHUNK_BYTES_USIZE) {
            builder.push(chunk);
        }
        builder.finish()
    }

    /// Rebuild from a leaf row that was persisted or received.
    ///
    /// The root is **recomputed**, never taken on trust: a stored row whose
    /// root was written separately could disagree with itself after a partial
    /// write, and this is the one place that would be noticed.
    ///
    /// # Errors
    /// The row length does not match the size it claims to describe.
    pub fn from_leaves(leaves: Vec<ChunkHash>, size: u64) -> Result<Self> {
        let expected = chunk_count(size);
        if leaves.len() != expected {
            bail!(
                "a {size}-byte file has {expected} chunks, but the row holds {}",
                leaves.len()
            );
        }
        Ok(Self {
            root: root_of(&leaves, size),
            leaves,
            size,
        })
    }

    /// The name of this file.
    #[must_use]
    pub const fn root(&self) -> Root {
        self.root
    }

    /// The ordered leaf row.
    #[must_use]
    pub fn leaves(&self) -> &[ChunkHash] {
        &self.leaves
    }

    /// Total bytes described.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// How many chunks this file occupies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the file holds no chunks, which means it holds no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The address of chunk `index`, or `None` past the end.
    #[must_use]
    pub fn leaf(&self, index: usize) -> Option<ChunkHash> {
        self.leaves.get(index).copied()
    }

    /// Which chunk covers `offset`.
    #[must_use]
    pub fn index_at(&self, offset: u64) -> usize {
        usize::try_from(offset / CHUNK_BYTES).unwrap_or(usize::MAX)
    }

    /// The byte range chunk `index` occupies, clamped to the file's end.
    ///
    /// The last chunk is short whenever the size is not a multiple of
    /// [`CHUNK_BYTES`], and that shortness is part of what it hashes — so a
    /// caller that pads it would compute a different address.
    #[must_use]
    pub fn range_of(&self, index: usize) -> std::ops::Range<u64> {
        let start = u64::try_from(index)
            .unwrap_or(u64::MAX)
            .saturating_mul(CHUNK_BYTES)
            .min(self.size);
        let end = start.saturating_add(CHUNK_BYTES).min(self.size);
        start..end
    }

    /// Which chunks cover `[offset, offset + len)`.
    #[must_use]
    pub fn indices_for(&self, offset: u64, len: u64) -> std::ops::Range<usize> {
        if len == 0 || offset >= self.size {
            return 0..0;
        }
        let end = offset.saturating_add(len).min(self.size);
        let first = self.index_at(offset);
        let last = usize::try_from(end.div_ceil(CHUNK_BYTES)).unwrap_or(usize::MAX);
        first..last.min(self.leaves.len())
    }

    /// Whether `bytes` really are chunk `index` of this file.
    ///
    /// The entire verification story. A peer that sends anything else fails
    /// here, whoever it is and whatever it claimed.
    #[must_use]
    pub fn verify(&self, index: usize, bytes: &[u8]) -> bool {
        self.leaves
            .get(index)
            .is_some_and(|expected| *expected == chunk_hash(bytes))
    }
}

/// Fold a leaf row into the root that names it.
///
/// The size is committed alongside the row so that a truncated row cannot be
/// passed off as a shorter file that happens to share a prefix.
fn root_of(leaves: &[ChunkHash], size: u64) -> Root {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ROOT_CONTEXT);
    hasher.update(&size.to_le_bytes());
    for leaf in leaves {
        hasher.update(leaf.as_bytes());
    }
    Root(*hasher.finalize().as_bytes())
}

/// Build a [`ChunkMap`] from chunks fed in order, without holding the file.
///
/// The shape an origin needs: read [`CHUNK_BYTES`] at a time, hash, discard.
/// Peak memory is one chunk plus the row, and the row is ~0.05 % of the file.
#[derive(Debug, Default)]
pub struct ChunkMapBuilder {
    leaves: Vec<ChunkHash>,
    size: u64,
    short_chunk_seen: bool,
}

impl ChunkMapBuilder {
    /// A builder holding nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next chunk, in file order.
    ///
    /// # Panics
    /// A chunk shorter than [`CHUNK_BYTES`] may only be the last one. Feeding
    /// another after it means the caller mis-chunked, which would silently
    /// produce a map that verifies against nothing — worth failing loudly at
    /// the seam rather than at some peer's download three hops away.
    pub fn push(&mut self, chunk: &[u8]) {
        assert!(
            !self.short_chunk_seen,
            "only the last chunk may be shorter than CHUNK_BYTES"
        );
        let len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        assert!(len <= CHUNK_BYTES, "a chunk is at most CHUNK_BYTES");
        if len < CHUNK_BYTES {
            self.short_chunk_seen = true;
        }
        self.leaves.push(chunk_hash(chunk));
        self.size += len;
    }

    /// Close the row and compute the root.
    #[must_use]
    pub fn finish(self) -> ChunkMap {
        let root = root_of(&self.leaves, self.size);
        ChunkMap {
            root,
            leaves: self.leaves,
            size: self.size,
        }
    }
}

/// Which chunks of a map something holds.
///
/// A plain bitmap over leaf indices. Deliberately not a range set: a peer that
/// seeds what it happened to look at holds scattered singletons, which is the
/// worst case for runs and the ordinary case here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    bits: Vec<u8>,
    len: usize,
}

impl Coverage {
    /// Coverage of a map with `len` chunks, holding none of them.
    #[must_use]
    pub fn empty(len: usize) -> Self {
        Self {
            bits: vec![0u8; len.div_ceil(8)],
            len,
        }
    }

    /// Coverage of a map with `len` chunks, holding all of them.
    #[must_use]
    pub fn complete(len: usize) -> Self {
        let mut coverage = Self::empty(len);
        for index in 0..len {
            coverage.insert(index);
        }
        coverage
    }

    /// How many chunks the map has.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the map has no chunks at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Record that chunk `index` is held. Out-of-range indices are ignored.
    pub fn insert(&mut self, index: usize) {
        if index >= self.len {
            return;
        }
        if let Some(byte) = self.bits.get_mut(index / 8) {
            *byte |= 1 << (index % 8);
        }
    }

    /// Record that chunk `index` is no longer held.
    pub fn remove(&mut self, index: usize) {
        if index >= self.len {
            return;
        }
        if let Some(byte) = self.bits.get_mut(index / 8) {
            *byte &= !(1 << (index % 8));
        }
    }

    /// Whether chunk `index` is held.
    #[must_use]
    pub fn contains(&self, index: usize) -> bool {
        if index >= self.len {
            return false;
        }
        self.bits
            .get(index / 8)
            .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
    }

    /// How many chunks are held.
    #[must_use]
    pub fn count(&self) -> usize {
        (0..self.len).filter(|index| self.contains(*index)).count()
    }

    /// Whether every chunk is held.
    ///
    /// True for an empty map, and that is correct rather than a quirk: a
    /// zero-byte file is fully held by anyone who knows its root.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        (0..self.len).all(|index| self.contains(index))
    }

    /// Held chunks as a share of the whole, in `0.0..=1.0`.
    ///
    /// `1.0` for an empty map, matching [`Self::is_complete`].
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "a progress fraction for a UI; a file would need 2^52 chunks \
                  (256 EiB) before the mantissa mattered"
    )]
    pub fn fraction(&self) -> f64 {
        if self.len == 0 {
            return 1.0;
        }
        self.count() as f64 / self.len as f64
    }

    /// Indices this does not hold.
    pub fn missing(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.len).filter(move |index| !self.contains(*index))
    }

    /// Indices this holds.
    pub fn held(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.len).filter(move |index| self.contains(*index))
    }

    /// Fold another peer's coverage of the same map into this one.
    pub fn union(&mut self, other: &Self) {
        for index in other.held() {
            self.insert(index);
        }
    }

    /// The raw bitmap, for a backend that persists it.
    ///
    /// The length is not encoded here — a caller that stores this stores the
    /// chunk count alongside, or takes it from the map.
    #[must_use]
    pub fn as_bits(&self) -> &[u8] {
        &self.bits
    }

    /// Rebuild from [`Self::as_bits`] and a known chunk count.
    ///
    /// # Errors
    /// The bitmap is too short for the count it claims to cover.
    pub fn from_bits(bits: &[u8], len: usize) -> Result<Self> {
        let needed = len.div_ceil(8);
        if bits.len() < needed {
            bail!(
                "a coverage of {len} chunks needs {needed} bytes, got {}",
                bits.len()
            );
        }
        Ok(Self {
            bits: bits[..needed].to_vec(),
            len,
        })
    }
}

/// What a caller knows about a file, independent of where its bytes live.
///
/// The store never opens this itself — that is the backend's job — and never
/// interprets `key`. A native backend uses a path; a browser backend uses
/// whatever it can reopen the bytes with. Keeping it opaque is what stops this
/// crate learning about filesystems.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileId {
    /// Opaque to this crate. Whatever the backend can reopen the bytes with.
    pub key: String,
    /// Size at the moment the caller looked.
    pub size: u64,
    /// Seconds since the epoch; `0` when unknown.
    pub mtime: i64,
}

impl FileId {
    /// Whether `other` describes the same file *version* as this one.
    ///
    /// The comparison guarding every read of a non-owned file. Two files at one
    /// key with different sizes or mtimes are different content, and answering
    /// for one under the other's root is the silent-corruption case this
    /// exists to prevent.
    ///
    /// Mutable files are supported, not a violation: a file whose version has
    /// moved is *unbound*, and an unbound file is refused rather than served
    /// wrongly.
    #[must_use]
    pub fn same_version(&self, other: &Self) -> bool {
        self.key == other.key && self.size == other.size && self.mtime == other.mtime
    }
}

/// The read half: everything needed to *answer* for chunks.
///
/// Split from [`ChunkStore`] because the most important implementor cannot
/// write at all. A native origin serves the user's own files **in place** — it
/// holds addresses beside them and reads through — so `put` would have to
/// either copy the bytes, which is the whole thing this crate avoids, or lie.
/// A source that only reads is the honest shape, and it means the conformance
/// suite can hold every backend to the same read contract without carving out
/// exceptions.
pub trait ChunkSource {
    /// One chunk's bytes, by address.
    ///
    /// `None` means "not held", which is ordinary. A backend that does not own
    /// its bytes resolves the address through a reverse index to a file and an
    /// offset, and reads through — see the module docs.
    fn get(&self, hash: ChunkHash) -> impl Future<Output = Result<Option<Vec<u8>>>>;

    /// Whether this chunk can be answered for right now.
    fn has(&self, hash: ChunkHash) -> impl Future<Output = Result<bool>>;

    /// The leaf row for `root`, if this source knows it.
    fn map(&self, root: Root) -> impl Future<Output = Result<Option<ChunkMap>>>;

    /// Which chunks of `root` this source can answer for.
    ///
    /// Empty coverage for a root it has never seen. This is the answer to
    /// "what can I seed", and the source for both an availability view and a
    /// scheduler.
    ///
    /// **Partial is a first-class answer.** A source holding some of a file
    /// serves those chunks and says so; there is no notion of holding a file
    /// "in full" before it may be shared.
    fn coverage(&self, root: Root) -> impl Future<Output = Result<Coverage>>;

    /// Coverage for several roots, asked once.
    ///
    /// One `Coverage` per input root, in the same order, so a caller can zip the
    /// answers back onto whatever it asked about. An unknown root covers
    /// nothing, exactly as [`Self::coverage`] says.
    ///
    /// Exists because "what do I hold of *everything*" is a different question
    /// from "what do I hold of *this*", and a backend may answer them by
    /// different routes. The default is the obvious loop, which is right
    /// wherever a per-root answer already costs what the row costs; a backend
    /// where it does not overrides this. See `IdbStore`, where the single-root
    /// answer probes leaves and the batched one takes a single snapshot of the
    /// keyspace — the loop there would re-scan the whole store per root.
    ///
    /// # Errors
    /// Whatever the backend's [`Self::coverage`] would raise for one root.
    fn coverage_of(&self, roots: &[Root]) -> impl Future<Output = Result<Vec<Coverage>>> {
        async move {
            let mut out = Vec::with_capacity(roots.len());
            for root in roots {
                out.push(self.coverage(*root).await?);
            }
            Ok(out)
        }
    }

    /// The root bound to this file *version*, if the file still matches it.
    ///
    /// `None` means *do not answer for this*: either nothing was ever bound, or
    /// the file moved underneath and the row describes content that is gone.
    /// Both are ordinary, neither is an error.
    fn bind(&self, file: &FileId) -> impl Future<Output = Result<Option<Root>>>;
}

/// The write half: a store that keeps chunks of its own.
///
/// # Ordering, which is a correctness rule and not a preference
///
/// Coverage that outlives its chunks is the dangerous direction: it makes this
/// peer advertise bytes it cannot serve, which to everyone else looks like a
/// peer that lies. **Write the chunk, then the coverage that claims it.** The
/// reverse — chunks present but coverage lost — costs a re-fetch and nothing
/// else.
pub trait ChunkStore: ChunkSource {
    /// Store one chunk, verifying it addresses what the caller claims.
    ///
    /// # Errors
    /// `blake3(bytes) != hash`, or the backend could not write.
    fn put(&self, hash: ChunkHash, bytes: &[u8]) -> impl Future<Output = Result<()>>;

    /// Record a leaf row, so its chunks can be named and swept.
    fn put_map(&self, map: &ChunkMap) -> impl Future<Output = Result<()>>;

    /// Record that this file version hashes to `root`.
    fn set_bind(&self, file: &FileId, root: Root) -> impl Future<Output = Result<()>>;

    /// Begin a reclamation pass, clearing every previous mark.
    ///
    /// Reclamation is mark-and-sweep rather than reference counting: nothing is
    /// mutated in a content-addressed store, so there are no orphans to track —
    /// only garbage, collected when the caller decides.
    fn start_marking(&self) -> impl Future<Output = Result<()>>;

    /// Mark every chunk of `root` as live for the current pass.
    ///
    /// **Derive the set of roots from persisted maps, never from an in-memory
    /// held-set.** A set that lost an entry to a reload would make [`sweep`]
    /// delete live data.
    ///
    /// [`sweep`]: ChunkStore::sweep
    fn mark(&self, root: Root) -> impl Future<Output = Result<()>>;

    /// Delete every chunk not marked in the current pass, returning the count.
    fn sweep(&self) -> impl Future<Output = Result<u64>>;

    /// Drop specific chunks, keeping everything else.
    ///
    /// Local eviction, typically under storage pressure. **A caller that clears
    /// must re-advertise**, or readers keep being sent to a peer that no longer
    /// has what it claimed.
    fn clear(&self, hashes: &[ChunkHash]) -> impl Future<Output = Result<()>>;
}

/// The filesystem backends. Host-only, and gated on the target rather than a
/// feature so it cannot be misconfigured: a wasm build simply does not have
/// `std::fs`, and the browser backends are what it uses instead.
#[cfg(not(target_arch = "wasm32"))]
pub mod fs;
/// The browser backend. Main-thread capable, so a tab can seed without a Worker.
#[cfg(target_arch = "wasm32")]
pub mod idb;
pub mod mem;

#[cfg(not(target_arch = "wasm32"))]
pub use fs::{FsOrigin, FsStore};
#[cfg(target_arch = "wasm32")]
pub use idb::IdbStore;
pub use mem::MemStore;

#[cfg(test)]
mod tests {
    use super::{
        CHUNK_BYTES, CHUNK_BYTES_USIZE, ChunkHash, ChunkMap, ChunkMapBuilder, Coverage, FileId,
        Root, chunk_count, chunk_hash,
    };

    /// Bytes that differ per position and per seed, so a chunk taken from one
    /// place cannot accidentally equal a chunk taken from another.
    fn body(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|index| {
                u8::try_from(index % 256)
                    .unwrap_or(0)
                    .wrapping_mul(31)
                    .wrapping_add(seed)
            })
            .collect()
    }

    /// The two spellings of the chunk size must agree, or every slice in the
    /// crate is off by whatever the difference is.
    #[test]
    fn chunk_bytes_agree() {
        assert_eq!(u64::try_from(CHUNK_BYTES_USIZE).expect("fits"), CHUNK_BYTES);
    }

    /// The crate's premise in one assertion: the same bytes at different
    /// offsets get the same address. This is exactly what bao cannot do, and
    /// the reason dedup and serve-by-hash are possible at all.
    #[test]
    fn the_same_bytes_address_the_same_wherever_they_sit() {
        let chunk = body(CHUNK_BYTES_USIZE, 7);
        let mut early = Vec::new();
        early.extend_from_slice(&chunk);
        early.extend_from_slice(&body(CHUNK_BYTES_USIZE, 99));

        let mut late = Vec::new();
        late.extend_from_slice(&body(CHUNK_BYTES_USIZE, 99));
        late.extend_from_slice(&chunk);

        let early_map = ChunkMap::build(&early);
        let late_map = ChunkMap::build(&late);

        assert_eq!(early_map.leaf(0), late_map.leaf(1));
        assert_eq!(early_map.leaf(1), late_map.leaf(0));
        // Same leaves, different order, so the files are not the same file.
        assert_ne!(early_map.root(), late_map.root());
    }

    #[test]
    fn a_root_commits_to_order_and_to_size() {
        let leaves = vec![chunk_hash(b"a"), chunk_hash(b"b")];
        let forward = ChunkMap::from_leaves(leaves.clone(), CHUNK_BYTES + 1).expect("two chunks");
        let reversed: Vec<ChunkHash> = leaves.into_iter().rev().collect();
        let backward = ChunkMap::from_leaves(reversed, CHUNK_BYTES + 1).expect("two chunks");
        assert_ne!(forward.root(), backward.root());
    }

    /// A row that does not describe the size it claims is refused, rather than
    /// producing a map that would verify against nothing.
    #[test]
    fn a_row_that_disagrees_with_its_size_is_refused() {
        let leaves = vec![chunk_hash(b"only one")];
        assert!(ChunkMap::from_leaves(leaves, CHUNK_BYTES * 4).is_err());
    }

    #[test]
    fn a_rebuilt_map_matches_the_one_that_was_built() {
        let bytes = body(CHUNK_BYTES_USIZE * 3 + 11, 3);
        let built = ChunkMap::build(&bytes);
        let rebuilt =
            ChunkMap::from_leaves(built.leaves().to_vec(), built.size()).expect("same row");
        assert_eq!(built, rebuilt);
        assert_eq!(built.root(), rebuilt.root());
    }

    /// The streaming builder is what an origin uses on a file it will not hold
    /// in memory, so it must agree with the all-at-once path exactly.
    #[test]
    fn the_streaming_builder_agrees_with_the_whole_file_path() {
        let bytes = body(CHUNK_BYTES_USIZE * 2 + 5, 21);
        let mut builder = ChunkMapBuilder::new();
        for chunk in bytes.chunks(CHUNK_BYTES_USIZE) {
            builder.push(chunk);
        }
        assert_eq!(builder.finish(), ChunkMap::build(&bytes));
    }

    #[test]
    fn an_empty_file_has_a_root_and_no_chunks() {
        let map = ChunkMap::build(b"");
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        assert_eq!(chunk_count(0), 0);
        // Complete, because there is nothing left to want.
        assert!(Coverage::empty(0).is_complete());
        assert!((Coverage::empty(0).fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_file_shorter_than_one_chunk_is_one_chunk() {
        let map = ChunkMap::build(b"short");
        assert_eq!(map.len(), 1);
        assert_eq!(map.range_of(0), 0..5);
        assert!(map.verify(0, b"short"));
        assert!(!map.verify(0, b"other"));
    }

    /// The last chunk's shortness is part of what it hashes, so a padded
    /// version must not verify.
    #[test]
    fn a_padded_last_chunk_does_not_verify() {
        let bytes = body(CHUNK_BYTES_USIZE + 10, 5);
        let map = ChunkMap::build(&bytes);
        let mut padded = bytes[CHUNK_BYTES_USIZE..].to_vec();
        padded.resize(CHUNK_BYTES_USIZE, 0);
        assert!(map.verify(1, &bytes[CHUNK_BYTES_USIZE..]));
        assert!(!map.verify(1, &padded));
    }

    #[test]
    fn exact_multiples_do_not_gain_an_empty_trailing_chunk() {
        let map = ChunkMap::build(&body(CHUNK_BYTES_USIZE * 2, 1));
        assert_eq!(map.len(), 2);
        assert_eq!(map.range_of(1), CHUNK_BYTES..CHUNK_BYTES * 2);
    }

    #[test]
    fn byte_ranges_map_onto_chunk_indices() {
        let map = ChunkMap::build(&body(CHUNK_BYTES_USIZE * 4, 2));
        assert_eq!(map.indices_for(0, CHUNK_BYTES), 0..1);
        // A window straddling a boundary needs both chunks.
        assert_eq!(map.indices_for(CHUNK_BYTES - 1, 2), 0..2);
        assert_eq!(map.indices_for(0, CHUNK_BYTES * 4), 0..4);
        // Past the end, and zero length, both want nothing.
        assert_eq!(map.indices_for(CHUNK_BYTES * 9, 10), 0..0);
        assert_eq!(map.indices_for(0, 0), 0..0);
        // A read running past the end is clamped rather than refused.
        assert_eq!(map.indices_for(CHUNK_BYTES * 3, CHUNK_BYTES * 99), 3..4);
    }

    /// The invariant a caller narrowing a full-row scan down to this range is
    /// relying on: nothing storable falls outside it.
    ///
    /// `agent-share`'s browser client walks these positions to decide which
    /// chunks of a read it can keep, and it keeps a chunk only when the chunk
    /// lies wholly inside the read. If this range ever missed one of those, the
    /// symptom would be a file that transfers in full and still never becomes
    /// seedable — silent, and only visible as coverage that stops short.
    #[test]
    fn byte_ranges_cover_every_chunk_a_read_could_hold_whole() {
        let map = ChunkMap::build(&body(CHUNK_BYTES_USIZE * 8 + 17, 3));
        for offset in [0, 1, 17, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES * 3 + 5] {
            for len in [1, 17, CHUNK_BYTES, CHUNK_BYTES * 4, CHUNK_BYTES * 99] {
                let end = offset + len;
                let narrowed = map.indices_for(offset, len);
                let whole = (0..map.len()).filter(|position| {
                    let range = map.range_of(*position);
                    range.start >= offset && range.end <= end
                });
                for position in whole {
                    assert!(
                        narrowed.contains(&position),
                        "chunk {position} fits wholly in {offset}..{end} but {narrowed:?} skips it"
                    );
                }
            }
        }
    }

    #[test]
    fn verifying_past_the_end_is_false_not_a_panic() {
        let map = ChunkMap::build(b"tiny");
        assert!(!map.verify(9, b"tiny"));
        assert_eq!(map.leaf(9), None);
    }

    #[test]
    fn coverage_tracks_what_is_held() {
        let mut coverage = Coverage::empty(10);
        assert!(!coverage.is_complete());
        assert_eq!(coverage.count(), 0);
        coverage.insert(0);
        coverage.insert(9);
        assert!(coverage.contains(0));
        assert!(coverage.contains(9));
        assert!(!coverage.contains(5));
        assert_eq!(coverage.count(), 2);
        assert_eq!(coverage.missing().count(), 8);
        coverage.remove(0);
        assert!(!coverage.contains(0));
        assert_eq!(Coverage::complete(10).count(), 10);
        assert!(Coverage::complete(10).is_complete());
    }

    /// Out-of-range writes are ignored rather than panicking or growing the
    /// map: a peer describing a different file must not be able to resize ours.
    #[test]
    fn out_of_range_coverage_is_ignored() {
        let mut coverage = Coverage::empty(4);
        coverage.insert(99);
        coverage.remove(99);
        assert!(!coverage.contains(99));
        assert_eq!(coverage.len(), 4);
        assert_eq!(coverage.count(), 0);
    }

    #[test]
    fn coverage_survives_a_round_trip_through_bits() {
        let mut coverage = Coverage::empty(20);
        for index in [0, 3, 7, 19] {
            coverage.insert(index);
        }
        let restored = Coverage::from_bits(coverage.as_bits(), 20).expect("round trip");
        assert_eq!(restored, coverage);
        assert!(Coverage::from_bits(&[0u8; 1], 20).is_err());
    }

    #[test]
    fn coverage_unions_across_peers() {
        let mut ours = Coverage::empty(8);
        ours.insert(1);
        let mut theirs = Coverage::empty(8);
        theirs.insert(6);
        ours.union(&theirs);
        assert!(ours.contains(1) && ours.contains(6));
        assert_eq!(ours.count(), 2);
    }

    #[test]
    fn a_version_change_unbinds_a_file() {
        let file = FileId {
            key: "a.txt".to_owned(),
            size: 10,
            mtime: 100,
        };
        assert!(file.same_version(&file.clone()));
        let touched = FileId {
            mtime: 101,
            ..file.clone()
        };
        let grown = FileId {
            size: 11,
            ..file.clone()
        };
        assert!(!file.same_version(&touched));
        assert!(!file.same_version(&grown));
    }

    #[test]
    fn digests_round_trip_through_hex() {
        let hash = chunk_hash(b"payload");
        assert_eq!(ChunkHash::from_hex(&hash.to_hex()).expect("hex"), hash);
        let root = ChunkMap::build(b"payload").root();
        assert_eq!(Root::from_hex(&root.to_hex()).expect("hex"), root);
        assert_eq!(hash.to_hex().len(), 64);
        assert!(ChunkHash::from_hex("nope").is_err());
        assert!(ChunkHash::from_hex(&"z".repeat(64)).is_err());
    }

    /// The length guard counts bytes but the old decoder sliced the `&str`,
    /// which panics at a char boundary. A store directory or a `binds.tsv`
    /// row is where such a name arrives from, and both are documented to
    /// degrade a row at a time rather than abort.
    #[test]
    fn non_ascii_hex_of_the_right_byte_length_errors_rather_than_panics() {
        let text = format!("{}a", "€".repeat(21));
        assert_eq!(text.len(), 64);
        assert!(ChunkHash::from_hex(&text).is_err());
        assert!(Root::from_hex(&text).is_err());
    }

    /// A root and a chunk hash are different types *and* different values, even
    /// for a one-chunk file whose row holds exactly one address.
    #[test]
    fn a_root_is_not_its_own_leaf() {
        let map = ChunkMap::build(b"single chunk");
        assert_ne!(map.root().as_bytes(), map.leaf(0).expect("one").as_bytes());
    }

    #[test]
    #[should_panic(expected = "only the last chunk")]
    fn a_short_chunk_mid_stream_is_a_caller_bug() {
        let mut builder = ChunkMapBuilder::new();
        builder.push(b"short");
        builder.push(b"another");
    }
}
