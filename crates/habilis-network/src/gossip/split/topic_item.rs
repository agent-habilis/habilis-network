use iroh_gossip::api::{ApiError, Event};

/// What the topic yields: the item of `GossipReceiver::next()`.
pub(crate) type TopicItem = Result<Event, ApiError>;
