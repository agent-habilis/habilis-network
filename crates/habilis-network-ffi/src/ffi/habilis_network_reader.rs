use crate::streams::ReadEnd;
use std::fmt;

/// The opaque handle behind `habilis_network_reader *`.
pub struct HabilisNetworkReader {
    pub(super) reader: ReadEnd,
}

impl fmt::Debug for HabilisNetworkReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HabilisNetworkReader")
            .finish_non_exhaustive()
    }
}
