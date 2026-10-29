//! What became of a frame that arrived from the topic.

/// What became of a frame that arrived from the topic.
///
/// # Examples
///
/// A queued frame and a frame that found a full queue have different outcomes.
///
/// ```
/// use habilis_network_iroh_gossip_transport::Delivery;
///
/// assert_ne!(Delivery::Queued, Delivery::QueueFull);
/// ```
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
