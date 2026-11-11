use std::error::Error;
use std::fmt;

/// Why a digest is refused: a field that is not a hash, a page that does not check, or a root
/// with no page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum DigestError {
    /// The root has no page. A digest has at least one page.
    NoPages,
    /// A text field is not the hex of its type. The text names the field.
    NotHex(&'static str),
    /// The page hash does not match its entries.
    HashMismatch,
    /// The index is past the total number of pages.
    IndexPastTotal,
    /// The entries are not sorted by key and unique.
    Unsorted,
    /// An entry is outside the range of its page.
    OutsideRange,
}

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NoPages => "a digest has at least one page",
            Self::NotHex(field) => return write!(formatter, "{field} is not a hash"),
            Self::HashMismatch => "the page hash does not match its entries",
            Self::IndexPastTotal => "the index is past the total",
            Self::Unsorted => "the entries are not sorted and unique",
            Self::OutsideRange => "an entry is outside the page range",
        };
        formatter.write_str(text)
    }
}

impl Error for DigestError {}
