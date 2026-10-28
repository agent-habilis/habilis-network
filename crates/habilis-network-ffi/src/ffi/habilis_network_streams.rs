use crate::streams::Streams;

/// The opaque handle behind `habilis_network_streams *`.
#[expect(
    missing_debug_implementations,
    reason = "wraps Streams, which owns a tokio Runtime and so has no Debug impl"
)]
pub struct HabilisNetworkStreams {
    pub(super) streams: Streams,
}
