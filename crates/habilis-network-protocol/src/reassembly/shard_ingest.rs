//! The outcome of ingesting one shard of a multipart body.

use crate::messages::Authored;

/// What became of one ingested shard.
///
/// # Examples
///
/// A shard whose group is still incomplete is buffered.
///
/// ```
/// use habilis_network_protocol::reassembly::ShardIngest;
///
/// assert!(matches!(ShardIngest::Buffered, ShardIngest::Buffered));
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ShardIngest {
    /// Buffered; its group is still incomplete.
    Buffered,
    /// The shard completed its group: the synthesized logical message, with
    /// the group's budget already freed. Boxed — the completed arm is rare
    /// and the enum otherwise carries nothing (`large_enum_variant`).
    Complete(Box<Authored>),
    /// Dropped — a duplicate slot, a header mismatch, or a budget breach
    /// (which drops the whole group, fail closed).
    Dropped,
}
