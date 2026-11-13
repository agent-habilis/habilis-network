//! The value of a held slice.

use serde_json::Value;

use crate::chunk_pointer::ChunkPointer;

/// What a slice holds: the value itself, or the pointer to a chunked value. An inline value is an
/// object, or `null` for a tombstone.
#[derive(Debug)]
pub(crate) enum SliceValue {
    Inline(Value),
    Pointer(ChunkPointer),
}

impl SliceValue {
    /// Whether the slice is a tombstone.
    pub(crate) fn is_tombstone(&self) -> bool {
        matches!(self, Self::Inline(value) if value.is_null())
    }

    /// The value that a reader of the view sees. A pointer reads as its own value.
    pub(crate) fn to_value(&self) -> Value {
        match self {
            Self::Inline(value) => value.clone(),
            Self::Pointer(pointer) => pointer.to_value(),
        }
    }
}
