use num_traits::ToPrimitive;

use crate::ChunkError;

/// Which chunks of a map something holds.
///
/// A plain bitmap over leaf indices. Deliberately not a range set: a peer that
/// seeds what it happened to look at holds scattered singletons, which is the
/// worst case for runs and the ordinary case here.
///
/// # Examples
///
/// Coverage records which chunks of a file a peer holds.
///
/// ```
/// use habilis_network_chunks::Coverage;
///
/// let mut coverage = Coverage::empty(3);
/// coverage.insert(1);
/// assert!(coverage.contains(1));
/// assert_eq!(coverage.count(), 1);
/// assert!(!coverage.is_complete());
/// assert!(Coverage::complete(2).is_complete());
/// ```
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
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the map has no chunks at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
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
    pub fn fraction(&self) -> f64 {
        if self.len == 0 {
            return 1.0;
        }
        // A `usize` always converts to an `f64`; the fallback is unreachable.
        let held = self.count().to_f64().unwrap_or(f64::NAN);
        held / self.len.to_f64().unwrap_or(f64::NAN)
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
    /// # Errors
    /// [`ChunkError::Malformed`] when the bitmap is too short for the count it claims to cover.
    pub fn decode_bits(bits: &[u8], len: usize) -> Result<Self, ChunkError> {
        let needed = len.div_ceil(8);
        let Some(kept) = bits.get(..needed) else {
            return Err(ChunkError::Malformed(format!(
                "a coverage of {len} chunks needs {needed} bytes, got {}",
                bits.len()
            )));
        };
        Ok(Self {
            bits: kept.to_vec(),
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
///
/// # Examples
///
/// Two file ids name the same version only when the key, size and time match.
///
/// ```
/// use habilis_network_chunks::FileId;
///
/// let id = FileId::new("a.txt".to_owned(), 10, 5);
/// assert!(id.same_version(&FileId::new("a.txt".to_owned(), 10, 5)));
/// assert!(!id.same_version(&FileId::new("a.txt".to_owned(), 11, 5)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileId {
    /// Opaque to this crate. Whatever the backend can reopen the bytes with.
    pub key: String,
    /// Size at the moment the caller looked.
    pub size: u64,
    /// Seconds since the epoch; `0` when unknown.
    pub mtime: i64,
}

impl FileId {
    /// The identity of one file version: the key the backend reopens it with, and its size and mtime.
    #[must_use]
    pub fn new(key: String, size: u64, mtime: i64) -> Self {
        Self { key, size, mtime }
    }

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
