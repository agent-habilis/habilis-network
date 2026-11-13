//! The pointer that stands for a value too large for one slice.

use habilis_network_chunks::Root;
use serde::Deserialize;
use serde_json::{Value, json};

/// The key that only a chunk pointer may carry at the top of a slice value.
pub(crate) const CHUNKS_KEY: &str = "$chunks";

/// The root and the size of the chunked value that a slice stands for. The slice value is
/// `{"$chunks": {"root": <hex>, "size": <bytes>}}`, and nothing else.
///
/// # Examples
///
/// ```
/// use habilis_network_chunks::Root;
/// use habilis_network_doc::ChunkPointer;
///
/// let pointer = ChunkPointer::new(Root::from_bytes([7; 32]), 100_000);
/// assert_eq!(ChunkPointer::parse(&pointer.to_value()), Some(pointer));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ChunkPointer {
    root: Root,
    size: u64,
}

/// The inner object of the wire form. An unknown key is an error.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PointerWire {
    root: String,
    size: u64,
}

impl ChunkPointer {
    /// Makes a pointer to the chunked value with `root`, `size` bytes long.
    pub fn new(root: Root, size: u64) -> Self {
        Self { root, size }
    }

    /// The root of the chunk map of the value.
    #[must_use]
    pub fn root(&self) -> Root {
        self.root
    }

    /// The size of the value in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The pointer that `value` is, or `None` when `value` is not exactly one pointer.
    #[must_use]
    pub fn parse(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        if object.len() != 1 {
            return None;
        }
        let wire: PointerWire = serde_json::from_value(object.get(CHUNKS_KEY)?.clone()).ok()?;
        let root = Root::try_from(wire.root.as_str()).ok()?;
        Some(Self::new(root, wire.size))
    }

    /// The slice value of the pointer.
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({CHUNKS_KEY: {"root": self.root.to_hex(), "size": self.size}})
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_chunks::Root;
    use serde_json::json;

    use super::ChunkPointer;

    #[test]
    fn a_pointer_round_trips_through_its_value() {
        let pointer = ChunkPointer::new(Root::from_bytes([9; 32]), 1);
        assert_eq!(
            ChunkPointer::parse(&pointer.to_value()),
            Some(pointer),
            "the value of a pointer must parse back to it"
        );
    }

    #[test]
    fn parse_refuses_what_is_not_exactly_one_pointer() {
        let root = Root::from_bytes([9; 32]).to_hex();
        for value in [
            json!(null),
            json!({}),
            json!({"$chunks": 1}),
            json!({"$chunks": {"root": root, "size": -1}}),
            json!({"$chunks": {"root": root, "size": 1, "extra": 0}}),
            json!({"$chunks": {"root": "zz", "size": 1}}),
            json!({"$chunks": {"root": root, "size": 1}, "a": 1}),
        ] {
            assert_eq!(
                ChunkPointer::parse(&value),
                None,
                "this value is no pointer: {value}"
            );
        }
    }
}
