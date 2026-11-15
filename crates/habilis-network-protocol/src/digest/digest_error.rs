use std::error::Error;
use std::fmt;

/// Why a digest is refused: a field that is not a key or a hash, a page that does not check, a root
/// with no page, or a page with no row.
///
/// # Examples
///
/// A root with no page is refused.
///
/// ```
/// use habilis_network_protocol::ContentHash;
/// use habilis_network_protocol::digest::{DigestError, DigestRoot};
///
/// let refused = DigestRoot::new(ContentHash::of(b"root"), 0);
/// assert!(matches!(refused, Err(DigestError::NoPages)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum DigestError {
    /// The root has no page. A digest has at least one page.
    NoPages,
    /// The page has no row. A page holds at least one row.
    NoRows,
    /// A text field is not the hex of an author key.
    NotKey,
    /// A text field is not the hex of a hash.
    NotHash,
    /// The page hash does not match its entries.
    HashMismatch,
    /// The index is past the total number of pages.
    IndexPastTotal,
    /// The entries are not sorted by key and unique.
    Unsorted,
    /// An entry is outside the range of its page.
    OutsideRange,
    /// The range of the page breaks the contract of its place: the first page starts at the zero
    /// key, and the last page has no end key.
    BadRange,
}

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NoPages => "a digest has at least one page",
            Self::NoRows => "a page holds at least one row",
            Self::NotKey => "a key is not the hex of an author key",
            Self::NotHash => "a hash is not the hex of a hash",
            Self::HashMismatch => "the page hash does not match its entries",
            Self::IndexPastTotal => "the index is past the total",
            Self::Unsorted => "the entries are not sorted and unique",
            Self::OutsideRange => "an entry is outside the page range",
            Self::BadRange => {
                "the page range breaks the contract of its place: the first page starts at the zero key, and the last page has no end key"
            }
        };
        formatter.write_str(text)
    }
}

impl Error for DigestError {}
