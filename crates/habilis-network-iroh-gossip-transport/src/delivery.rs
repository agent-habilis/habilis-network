//! What became of a frame that arrived from the topic.

/// What became of a frame that arrived from the topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Delivery {
    /// Queued for iroh.
    Queued,
    /// Addressed to another member.
    NotForUs,
    /// Not a frame this build reads.
    Malformed,
    /// iroh is not reading fast enough, or has stopped.
    QueueFull,
}
