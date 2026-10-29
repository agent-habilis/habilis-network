use std::fmt;

use crate::ChunkError;

/// The address of one chunk: `blake3` over its bytes and nothing else.
///
/// Position-independent on purpose. Two files holding the same 64 `KiB` at any
/// offset, in any share, produce the same address and share one stored copy.
///
/// # Example
///
/// ```
/// use habilis_network_chunks::{ChunkHash, chunk_hash};
///
/// let address: ChunkHash = chunk_hash(b"hello");
/// assert_eq!(address.to_hex().len(), 64);
/// assert_eq!(address, chunk_hash(b"hello"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkHash(pub(crate) [u8; 32]);

/// The name of a whole file: a commitment to its ordered leaf row.
///
/// A distinct type from [`ChunkHash`] rather than a bare `[u8; 32]`, because
/// the two are asked for in adjacent calls and swapping them would be a silent
/// bug — `get(root)` would simply find nothing rather than fail loudly.
///
/// # Example
///
/// ```
/// use habilis_network_chunks::ChunkMap;
///
/// let root = ChunkMap::build(b"a file").root();
/// assert_eq!(root.to_hex().len(), 64);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Root(pub(crate) [u8; 32]);

/// Lowercase hex of a digest, the form every backend keys records by.
fn digest_to_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Parse the hex form of a digest. `what` names the digest in the error.
fn digest_from_hex(text: &str, what: &str) -> Result<[u8; 32], ChunkError> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return Err(ChunkError::Malformed(format!(
            "a {what} is 64 hex digits, got {}",
            bytes.len()
        )));
    }
    // Decode from bytes, never by slicing the `&str`: the guard
    // above counts bytes, and a slice that lands inside a
    // multibyte char panics. Any non-hex byte is a plain error.
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let (Some(high), Some(low)) = (hex_nibble(pair[0]), hex_nibble(pair[1])) else {
            return Err(ChunkError::Malformed(format!("a {what} is hex")));
        };
        *slot = (high << 4) | low;
    }
    Ok(out)
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

/// Wrap raw digest bytes.
impl From<[u8; 32]> for ChunkHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Parse the form [`ChunkHash::to_hex`] writes.
///
/// # Errors
/// [`ChunkError::Malformed`] when the text is not exactly 64 hex digits, or is not hex.
impl TryFrom<&str> for ChunkHash {
    type Error = ChunkError;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        digest_from_hex(text, "chunk hash").map(Self)
    }
}

impl ChunkHash {
    /// The raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, the form every backend keys records by.
    #[must_use]
    pub fn to_hex(&self) -> String {
        digest_to_hex(&self.0)
    }
}

impl fmt::Display for ChunkHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// Wrap raw digest bytes.
impl From<[u8; 32]> for Root {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Parse the form [`Root::to_hex`] writes.
///
/// # Errors
/// [`ChunkError::Malformed`] when the text is not exactly 64 hex digits, or is not hex.
impl TryFrom<&str> for Root {
    type Error = ChunkError;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        digest_from_hex(text, "root").map(Self)
    }
}

impl Root {
    /// The raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, the form every backend keys records by.
    #[must_use]
    pub fn to_hex(&self) -> String {
        digest_to_hex(&self.0)
    }
}

impl fmt::Display for Root {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// Address one chunk's bytes.
///
/// # Example
///
/// ```
/// use habilis_network_chunks::chunk_hash;
///
/// let a = chunk_hash(b"same bytes");
/// let b = chunk_hash(b"same bytes");
/// assert_eq!(a, b);
/// ```
#[must_use]
pub fn chunk_hash(bytes: &[u8]) -> ChunkHash {
    ChunkHash(*blake3::hash(bytes).as_bytes())
}
