use serde::{Deserialize, Serialize};

use super::DigestError;
use crate::ContentHash;

/// The root of a store's digest: the hash of every entry, and the number of pages, at least one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(try_from = "RootWire", into = "RootWire")]
pub struct DigestRoot {
    root: ContentHash,
    total: usize,
}

impl DigestRoot {
    /// Makes the root of `root` over `total` pages.
    ///
    /// # Errors
    ///
    /// [`DigestError::NoPages`] when `total` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_protocol::ContentHash;
    /// use habilis_network_protocol::digest::{DigestError, DigestRoot};
    ///
    /// assert!(DigestRoot::new(ContentHash::of(b"root"), 1).is_ok());
    /// assert!(matches!(DigestRoot::new(ContentHash::of(b"root"), 0), Err(DigestError::NoPages)));
    /// ```
    pub fn new(root: ContentHash, total: usize) -> Result<Self, DigestError> {
        if total == 0 {
            return Err(DigestError::NoPages);
        }
        Ok(Self { root, total })
    }

    /// The hash of all entries, sorted by key.
    #[must_use]
    pub fn root(&self) -> ContentHash {
        self.root
    }

    /// The number of pages, at least one.
    #[must_use]
    pub fn total(&self) -> usize {
        self.total
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
    type Error = DigestError;

    fn try_from(wire: RootWire) -> Result<Self, Self::Error> {
        let root = ContentHash::decode_hex(&wire.root).ok_or(DigestError::NotHash)?;
        Self::new(root, wire.total)
    }
}

#[cfg(test)]
mod tests {
    use super::DigestRoot;
    use crate::ContentHash;
    use crate::digest::DigestError;

    #[test]
    fn a_digest_root_has_the_golden_wire_form() {
        let zeros = "0".repeat(64);
        let root = DigestRoot::new(ContentHash::decode_hex(&zeros).expect("a hash"), 2)
            .expect("a root with two pages");
        let text = serde_json::to_string(&root).expect("a root must serialize");
        assert_eq!(
            text,
            format!(r#"{{"root":"{zeros}","total":2}}"#),
            "the root wire form changed"
        );
    }

    #[test]
    fn a_digest_root_round_trips_through_its_wire_form() {
        let root = DigestRoot::new(ContentHash::of(b"root"), 1).expect("a root with one page");
        let text = serde_json::to_string(&root).expect("a root must serialize");
        let back: DigestRoot = serde_json::from_str(&text).expect("a root must parse");
        assert_eq!(back, root, "a root must come back equal from its wire form");
    }

    #[test]
    fn a_digest_root_with_zero_pages_is_refused() {
        let refused = DigestRoot::new(ContentHash::of(b"root"), 0);
        assert!(
            matches!(refused, Err(DigestError::NoPages)),
            "a digest has at least one page"
        );
    }
}
