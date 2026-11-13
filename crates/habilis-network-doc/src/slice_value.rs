//! The value of a held slice.

use serde_json::Value;

use crate::chunk_pointer::ChunkPointer;

/// What a slice holds: the value itself, a pointer to a chunked value that is not here yet, or a
/// chunked value with its pointer. An inline value is an object, or `null` for a tombstone.
#[derive(Debug)]
pub(crate) enum SliceValue {
    Inline(Value),
    /// A pointer to a chunked value that is not fetched yet. `last` is the last complete value of the author, which
    /// a reader keeps seeing until the new value is whole. It is `None` for the first version of an author, and a
    /// reader sees nothing of the author then.
    Pointer {
        pointer: ChunkPointer,
        last: Option<Value>,
    },
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

    /// The value that a reader of the view sees, or `None` when a reader sees nothing of the author: a pointer that
    /// is not fetched, and has no complete value before it.
    pub(crate) fn to_value(&self) -> Option<Value> {
        match self {
            Self::Inline(value) | Self::Chunked { value, .. } => Some(value.clone()),
            Self::Pointer { last, .. } => last.clone(),
        }
    }

    /// The value as the slice was signed: the value of an inline slice, and the pointer of a chunked one.
    pub(crate) fn signed(&self) -> Value {
        match self {
            Self::Inline(value) => value.clone(),
            Self::Pointer { pointer, .. } | Self::Chunked { pointer, .. } => pointer.to_value(),
        }
    }

    /// The value, when the slice holds it whole.
    pub(crate) fn resolved(&self) -> Option<&Value> {
        match self {
            Self::Inline(value) | Self::Chunked { value, .. } => Some(value),
            Self::Pointer { .. } => None,
        }
    }

    /// The pointer, when the slice has one.
    pub(crate) fn pointer(&self) -> Option<&ChunkPointer> {
        match self {
            Self::Inline(_) => None,
            Self::Pointer { pointer, .. } | Self::Chunked { pointer, .. } => Some(pointer),
        }
    }

    /// Takes the last complete value out of the slice, which a new version is about to replace. A tombstone has none.
    pub(crate) fn take_complete(&mut self) -> Option<Value> {
        let taken = match self {
            Self::Inline(value) | Self::Chunked { value, .. } => Some(value.take()),
            Self::Pointer { last, .. } => last.take(),
        };
        taken.filter(|value| !value.is_null())
    }
}
