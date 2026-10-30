use crate::streams::Streams;
use std::fmt;

/// The opaque handle behind `habilis_network_streams *`.
pub struct HabilisNetworkStreams {
    pub(super) streams: Streams,
}

impl fmt::Debug for HabilisNetworkStreams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HabilisNetworkStreams")
            .finish_non_exhaustive()
    }
}
