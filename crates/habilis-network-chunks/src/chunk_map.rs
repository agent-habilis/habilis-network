use crate::chunk_hash::chunk_hash;
use crate::{CHUNK_BYTES, CHUNK_BYTES_USIZE, ChunkError, ChunkHash, Root};

/// Domain separator for a root, so a root can never collide with the hash of a
/// chunk that happens to hold the same bytes.
const ROOT_CONTEXT: &[u8] = b"habilis-network-chunks/root/v1";

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
    /// # Errors
    /// [`ChunkError::Malformed`] when the row length does not match the size it claims to describe.
    pub fn from_leaves(leaves: Vec<ChunkHash>, size: u64) -> Result<Self, ChunkError> {
        let expected = chunk_count(size);
        if leaves.len() != expected {
            return Err(ChunkError::Malformed(format!(
                "a {size}-byte file has {expected} chunks, but the row holds {}",
                leaves.len()
            )));
        }
        Ok(Self {
            root: root_of(&leaves, size),
            leaves,
            size,
        })
    }

    /// The name of this file.
    #[must_use]
    pub fn root(&self) -> Root {
        self.root
    }

    /// The ordered leaf row.
    #[must_use]
    pub fn leaves(&self) -> &[ChunkHash] {
        &self.leaves
    }

    /// Total bytes described.
    #[must_use]
    pub fn size(&self) -> u64 {
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
#[must_use]
pub struct ChunkMapBuilder {
    leaves: Vec<ChunkHash>,
    size: u64,
    short_chunk_seen: bool,
}

impl ChunkMapBuilder {
    /// A builder holding nothing.
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
