//! The pointer that stands for a value too large for one slice.

use habilis_network_chunks::Root;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::structure;

/// The key that only a chunk pointer may carry at the top of a slice value.
pub(crate) const CHUNKS_KEY: &str = "$chunks";

/// The root, the size and the structure units of the chunked value that a slice stands for. The slice value is
/// `{"$chunks": {"root": <hex>, "size": <bytes>, "units": <count>}}`, and nothing else.
///
/// The count of units is what [`structure_units`](crate::structure_units) returns for the bytes of the value. The
/// author signs it, so a member can refuse a value that is too complex before it fetches any chunk.
///
/// # Examples
///
/// ```
/// use habilis_network_chunks::Root;
/// use habilis_network_doc::ChunkPointer;
///
/// let pointer = ChunkPointer::new(Root::from_bytes([7; 32]), 100_000, 9);
/// assert_eq!(ChunkPointer::parse(&pointer.to_value()), Some(pointer));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct ChunkPointer {
    root: Root,
    size: u64,
    units: u64,
}

/// The inner object of the wire form. An unknown key is an error.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PointerWire {
    root: String,
    size: u64,
    units: u64,
}

impl ChunkPointer {
    /// Makes a pointer to the chunked value with `root`, `size` bytes long and `units` structure units.
    pub fn new(root: Root, size: u64, units: u64) -> Self {
        Self { root, size, units }
    }

    /// Makes a pointer to the chunked value of `bytes` with `root`. The size and the units come from the same bytes,
    /// so they agree.
    pub fn of(root: Root, bytes: &[u8]) -> Self {
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let units = u64::try_from(structure::structure_units(bytes)).unwrap_or(u64::MAX);
        Self::new(root, size, units)
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

    /// The count of structure units of the value.
    #[must_use]
    pub fn units(&self) -> u64 {
        self.units
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
        Some(Self::new(root, wire.size, wire.units))
    }

    /// The slice value of the pointer.
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({CHUNKS_KEY: {"root": self.root.to_hex(), "size": self.size, "units": self.units}})
    }
}

#[cfg(test)]
mod tests {
    use habilis_network_chunks::Root;
    use serde_json::json;

    use super::ChunkPointer;

    #[test]
    fn a_pointer_round_trips_through_its_value() {
        let pointer = ChunkPointer::new(Root::from_bytes([9; 32]), 1, 5);
        assert_eq!(
            ChunkPointer::parse(&pointer.to_value()),
            Some(pointer),
            "the value of a pointer must parse back to it"
        );
        assert_eq!(pointer.units(), 5, "the pointer must keep its units");
        assert_eq!(
            pointer.to_value()["$chunks"]["units"],
            5,
            "the value of a pointer must carry its units"
        );
    }

    #[test]
    fn parse_refuses_a_pointer_without_its_units() {
        let root = Root::from_bytes([9; 32]).to_hex();
        assert_eq!(
            ChunkPointer::parse(&json!({"$chunks": {"root": root, "size": 1}})),
            None,
            "the count of units is required: an author must not skip the check"
        );
    }

    #[test]
    fn parse_takes_a_pointer_with_its_units() {
        let root = Root::from_bytes([9; 32]).to_hex();
        assert!(
            ChunkPointer::parse(&json!({"$chunks": {"root": root, "size": 1, "units": 5}}))
                .is_some(),
            "a pointer with root, size and units must parse"
        );
    }

    #[test]
    fn parse_refuses_what_is_not_exactly_one_pointer() {
        let root = Root::from_bytes([9; 32]).to_hex();
        for value in [
            json!(null),
            json!({}),
            json!({"$chunks": 1}),
            json!({"$chunks": {"root": root, "size": -1, "units": 1}}),
            json!({"$chunks": {"root": root, "size": 1, "units": -1}}),
            json!({"$chunks": {"root": root, "size": 1, "units": 1, "extra": 0}}),
            json!({"$chunks": {"root": "zz", "size": 1, "units": 1}}),
            json!({"$chunks": {"root": root, "size": 1, "units": 1}, "a": 1}),
        ] {
            assert_eq!(
                ChunkPointer::parse(&value),
                None,
                "this value is no pointer: {value}"
            );
        }
    }
}
