//! The value of a held slice.

use serde_json::Value;

use crate::chunk_pointer::ChunkPointer;

/// What a slice holds: the value itself, a pointer to a chunked value that is not here yet, or a
/// chunked value with its pointer. An inline value is an object, or `null` for a tombstone.
#[derive(Debug)]
pub(crate) enum SliceValue {
    Inline(Value),
    Pointer(ChunkPointer),
    /// The value of a chunked slice, read whole. The signed frame of the slice names the pointer.
    Chunked {
        pointer: ChunkPointer,
        value: Value,
    },
}

impl SliceValue {
    /// Whether the slice is a tombstone.
    pub(crate) fn is_tombstone(&self) -> bool {
        matches!(self, Self::Inline(value) if value.is_null())
    }

    /// The value that a reader of the view sees. A pointer that is not resolved reads as its own
    /// value.
    pub(crate) fn to_value(&self) -> Value {
        match self {
            Self::Inline(value) | Self::Chunked { value, .. } => value.clone(),
            Self::Pointer(pointer) => pointer.to_value(),
        }
    }

    /// The value, when the slice holds it whole.
    pub(crate) fn resolved(&self) -> Option<&Value> {
        match self {
            Self::Inline(value) | Self::Chunked { value, .. } => Some(value),
            Self::Pointer(_) => None,
        }
    }

    /// The pointer, when the slice has one.
    pub(crate) fn pointer(&self) -> Option<&ChunkPointer> {
        match self {
            Self::Inline(_) => None,
            Self::Pointer(pointer) | Self::Chunked { pointer, .. } => Some(pointer),
        }
    }
}
