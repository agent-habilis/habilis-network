use std::ffi::CString;

use crate::streams::Writer;

/// The opaque handle behind `habilis_network_producer *`, with a NUL-terminated copy of
/// the hash so [`habilis_network_stream_hash`](super::habilis_network_stream_hash) can lend it out.
#[expect(
    missing_debug_implementations,
    reason = "wraps Writer, which holds a tokio Runtime and so has no Debug impl"
)]
pub struct HabilisNetworkProducer {
    pub(super) writer: Writer,
    pub(super) hash: CString,
}
