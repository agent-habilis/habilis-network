use crate::protocol::{DedupKey, UnixSecs};

/// Where a message sits in the log's total order: its timestamp, then its id
/// key. Timestamps are whole seconds and a mesh puts hundreds of messages in one
/// second, so the timestamp alone cannot say which side of a window's edge a
/// message is on; the key breaks every tie.
pub(crate) type Bound = (UnixSecs, DedupKey);
