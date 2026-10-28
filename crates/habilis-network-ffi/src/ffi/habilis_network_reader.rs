use crate::streams::ReadEnd;

/// The opaque handle behind `habilis_network_reader *`.
#[expect(
    missing_debug_implementations,
    reason = "wraps ReadEnd, which holds a tokio Runtime and so has no Debug impl"
)]
pub struct HabilisNetworkReader {
    pub(super) reader: ReadEnd,
}
