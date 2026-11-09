//! The slice store: one JSON slice per author key.
//!
//! The store holds the slice of each author. Only the author raises the version of its own
//! slice. The store knows keys and never nicknames.

/// The caps that bound a [`SliceStore`].
///
/// # Examples
///
/// ```
/// use habilis_network_doc::SliceLimits;
///
/// let limits = SliceLimits::default();
/// assert_eq!(limits.slice_bytes, 8 * 1024);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SliceLimits {
    /// The most bytes one serialized slice value can take.
    pub slice_bytes: usize,
    /// The writes one author can make each second, after the burst.
    pub writes_per_second: u32,
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
    ///
    /// let limits = SliceLimits::new(1024, 2, 16, 4);
    /// assert_eq!(limits.max_authors, 16);
    /// ```
    #[must_use]
    pub fn new(slice_bytes: usize, writes_per_second: u32, max_authors: usize, burst: u32) -> Self {
        Self {
            slice_bytes,
            writes_per_second,
            max_authors,
            burst,
        }
    }
}

impl Default for SliceLimits {
    fn default() -> Self {
        Self::new(8 * 1024, 1, 256, 5)
    }
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
#[non_exhaustive]
pub struct SliceStore {
    limits: SliceLimits,
}

impl SliceStore {
    /// Makes an empty store under `limits`.
    #[must_use]
    pub fn new(limits: SliceLimits) -> Self {
        Self { limits }
    }

    /// Returns the caps of this store.
    #[must_use]
    pub fn limits(&self) -> &SliceLimits {
        &self.limits
    }
}
