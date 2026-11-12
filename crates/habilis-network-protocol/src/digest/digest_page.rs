use serde::{Deserialize, Serialize};

use super::{DigestEntry, DigestError};
use crate::{AuthorKey, ContentHash};

/// The bytes of a digest page around its rows: the index, the total, the range, the hash, and the
/// JSON around them.
pub const PAGE_WRAPPER: usize = 320;

/// The bytes of one page row at the longest version, `["<key hex>",18446744073709551615,"<hash
/// hex>"],`.
pub const PAGE_ROW: usize = 160;

/// One page of a store's digest. A page covers the keys from `first_key` up to `end_key`, not
/// included. A key of that range that the page does not list is absent at the sender.
///
/// The sync is pull-only. A peer reads the pages and pulls the keys it wants.
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
    /// Builds page `index` of `total` from `sorted` entries, `rows` to a page. The entries must be
    /// sorted by key and unique, as a store lists them.
    ///
    /// # Errors
    ///
    /// The refusals of the parser: no row, an index past the total, entries that are not sorted, and
    /// an entry outside the page range.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_protocol::digest::{DigestEntry, DigestError, DigestPage};
    /// use habilis_network_protocol::{AuthorKey, ContentHash};
    ///
    /// let entry = DigestEntry::new(AuthorKey::from([1; 32]), 1, ContentHash::of(b"row"));
    /// let page = DigestPage::build(&[entry], 1, 0, 1).expect("a page of one row");
    /// assert_eq!(page.entries().len(), 1);
    /// assert!(matches!(DigestPage::build(&[], 0, 0, 1), Err(DigestError::NoRows)));
    /// ```
    pub fn build(
        sorted: &[DigestEntry],
        rows: usize,
        index: usize,
        total: usize,
    ) -> Result<Self, DigestError> {
        if rows == 0 {
            return Err(DigestError::NoRows);
        }
        if index >= total {
            return Err(DigestError::IndexPastTotal);
        }
        if sorted.windows(2).any(|pair| {
            let (below, above) = (pair[0].key(), pair[1].key());
            below.as_bytes() >= above.as_bytes()
        }) {
            return Err(DigestError::Unsorted);
        }
        let start = index.saturating_mul(rows);
        let window = sorted.iter().skip(start).take(rows);
        let entries: Vec<DigestEntry> = window.cloned().collect();
        let first_key = if index == 0 {
            AuthorKey::from([0; 32])
        } else {
            entries
                .first()
                .map_or(AuthorKey::from([0; 32]), DigestEntry::key)
        };
        let end_key = sorted.get(start.saturating_add(rows)).map(DigestEntry::key);
        let hash = page_hash(&entries);
        let page = Self {
            index,
            total,
            first_key,
            end_key,
            entries,
            hash,
        };
        if !page.entries.iter().all(|entry| page.covers(&entry.key())) {
            return Err(DigestError::OutsideRange);
        }
        Ok(page)
    }

    /// Whether `key` is in the range of the page.
    #[must_use]
    pub fn covers(&self, key: &AuthorKey) -> bool {
        let after_first = key.as_bytes() >= self.first_key.as_bytes();
        let before_end = self
            .end_key
            .is_none_or(|end| key.as_bytes() < end.as_bytes());
        after_first && before_end
    }

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
    let (key, hash) = (entry.key(), entry.hash());
    (hex_text(&key.hex()), entry.version(), hex_text(&hash.hex()))
}

/// The text of a hex array.
fn hex_text(bytes: &[u8; 64]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

impl TryFrom<PageWire> for DigestPage {
    type Error = DigestError;

    fn try_from(wire: PageWire) -> Result<Self, Self::Error> {
        let first_key = AuthorKey::decode_hex(&wire.first_key).ok_or(DigestError::NotKey)?;
        let end_key = match wire.end_key {
            Some(text) => Some(AuthorKey::decode_hex(&text).ok_or(DigestError::NotKey)?),
            None => None,
        };
        let mut entries = Vec::with_capacity(wire.entries.len());
        for (key, version, hash) in wire.entries {
            let key = AuthorKey::decode_hex(&key).ok_or(DigestError::NotKey)?;
            let hash = ContentHash::decode_hex(&hash).ok_or(DigestError::NotHash)?;
            entries.push(DigestEntry::new(key, version, hash));
        }
        let hash = ContentHash::decode_hex(&wire.hash).ok_or(DigestError::NotHash)?;
        if page_hash(&entries) != hash {
            return Err(DigestError::HashMismatch);
        }
        if wire.index >= wire.total {
            return Err(DigestError::IndexPastTotal);
        }
        if entries.windows(2).any(|pair| {
            let (below, above) = (pair[0].key(), pair[1].key());
            below.as_bytes() >= above.as_bytes()
        }) {
            return Err(DigestError::Unsorted);
        }
        let page = DigestPage {
            index: wire.index,
            total: wire.total,
            first_key,
            end_key,
            entries,
            hash,
        };
        if !page.entries.iter().all(|entry| page.covers(&entry.key())) {
            return Err(DigestError::OutsideRange);
        }
        Ok(page)
    }
}

/// The hash of digest entries in the order given: each entry is its key, its version and its hash.
#[must_use]
pub fn page_hash(entries: &[DigestEntry]) -> ContentHash {
    let mut bytes = Vec::with_capacity(entries.len() * 72);
    for entry in entries {
        bytes.extend_from_slice(entry.key().as_bytes());
        bytes.extend_from_slice(&entry.version().to_be_bytes());
        bytes.extend_from_slice(entry.hash().as_bytes());
    }
    ContentHash::of(&bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        DigestEntry, DigestError, DigestPage, PAGE_ROW, PAGE_WRAPPER, page_hash, row_wire,
    };
    use crate::{AuthorKey, ContentHash};
    use serde_json::{Value, json};

    fn key(byte: u8) -> AuthorKey {
        AuthorKey::from([byte; 32])
    }

    fn entry(byte: u8) -> DigestEntry {
        DigestEntry::new(key(byte), 1, ContentHash::of(&[byte]))
    }

    #[test]
    fn build_refuses_unsorted_entries() {
        let mut rows = vec![entry(1), entry(2)];
        rows.reverse();
        let built = DigestPage::build(&rows, 2, 0, 1);
        assert!(
            matches!(built, Err(DigestError::Unsorted)),
            "build must refuse entries that are not sorted by key"
        );
    }

    #[test]
    fn build_refuses_an_index_past_the_total() {
        let built = DigestPage::build(&[entry(1)], 1, 3, 1);
        assert!(
            matches!(built, Err(DigestError::IndexPastTotal)),
            "build must refuse an index past the total"
        );
    }

    #[test]
    fn build_refuses_zero_rows() {
        let built = DigestPage::build(&[entry(1)], 0, 0, 1);
        assert!(
            matches!(built, Err(DigestError::NoRows)),
            "build must refuse a page with no rows"
        );
    }

    #[test]
    fn build_of_a_huge_index_lists_no_entries_and_does_not_overflow() {
        let page = DigestPage::build(&[entry(1)], 2, usize::MAX - 1, usize::MAX)
            .expect("an index below the total is a page");
        assert!(page.entries().is_empty(), "no entry sits past the end");
    }

    #[test]
    fn the_page_estimates_cover_the_measured_wrapper_and_row() {
        let empty = DigestPage::build(&[], 1, 0, 1).expect("a page the store would build");
        let wrapper = serde_json::to_string(&empty)
            .expect("a page must serialize")
            .len();
        assert!(
            PAGE_WRAPPER >= wrapper,
            "PAGE_WRAPPER must cover the measured {wrapper} bytes"
        );
        let row_entry = DigestEntry::new(key(1), u64::MAX, ContentHash::of(b"row"));
        let row = serde_json::to_string(&row_wire(&row_entry))
            .expect("a row must serialize")
            .len()
            + 1;
        assert!(
            PAGE_ROW >= row,
            "PAGE_ROW must cover the measured {row} bytes"
        );
    }

    #[test]
    fn a_digest_page_with_unsorted_entries_is_refused() {
        let rows = vec![entry(1), entry(2)];
        let page = DigestPage::build(&rows, 2, 0, 1).expect("a page of two sorted rows");
        let mut value: Value = serde_json::to_value(&page).expect("a page must serialize");
        value["entries"]
            .as_array_mut()
            .expect("a list of rows")
            .reverse();
        let parsed: Result<DigestPage, _> = serde_json::from_value(value);
        assert!(parsed.is_err(), "entries out of key order must be refused");
    }

    #[test]
    fn a_digest_page_past_its_total_is_refused() {
        let page = DigestPage::build(&[entry(1)], 1, 0, 1).expect("a page the store would build");
        let text = serde_json::to_string(&page).expect("a page must serialize");
        let mut value: Value = serde_json::from_str(&text).expect("a value");
        value["index"] = json!(5);
        let parsed: Result<DigestPage, _> = serde_json::from_value(value);
        assert!(parsed.is_err(), "an index past the total must be refused");
    }

    #[test]
    fn a_digest_page_round_trips_through_its_wire_form() {
        let page = DigestPage::build(&[entry(1)], 1, 0, 1).expect("a page the store would build");
        let text = serde_json::to_string(&page).expect("a page must serialize");
        let back: DigestPage = serde_json::from_str(&text).expect("a page must parse");
        assert_eq!(back, page, "a page must come back equal from its wire form");
        let unknown = text.replacen('{', "{\"extra\":1,", 1);
        let parsed: Result<DigestPage, _> = serde_json::from_str(&unknown);
        assert!(parsed.is_err(), "an unknown field must be refused");
    }

    #[test]
    fn a_page_with_a_wrong_hash_is_refused() {
        let page = DigestPage::build(&[entry(1)], 1, 0, 1).expect("a page the store would build");
        let text = serde_json::to_string(&page).expect("a page must serialize");
        let mut value: Value = serde_json::from_str(&text).expect("a value");
        value["hash"] = json!("0".repeat(64));
        let parsed: Result<DigestPage, _> = serde_json::from_value(value);
        assert!(
            parsed.is_err(),
            "a page whose hash does not match its entries must be refused"
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
        let page = DigestPage::build(&entries, 1, 0, 1).expect("a page the store would build");
        let hash = page_hash(&entries);
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
}
