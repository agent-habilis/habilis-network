use std::ffi::CString;
use std::fmt;

use crate::streams::Writer;

/// The opaque handle behind `habilis_network_producer *`, with a NUL-terminated copy of
/// the hash so [`habilis_network_stream_hash`](super::habilis_network_stream_hash) can lend it out.
pub struct HabilisNetworkProducer {
    pub(super) writer: Writer,
    pub(super) hash: CString,
}

impl fmt::Debug for HabilisNetworkProducer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HabilisNetworkProducer")
            .finish_non_exhaustive()
    }
}
