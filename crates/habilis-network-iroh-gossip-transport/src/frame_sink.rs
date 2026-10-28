//! Where a frame goes.

use bytes::Bytes;

/// Where a frame goes: the mesh gossip topic, once the engine has joined it.
/// It never blocks. `false` means the frame was not accepted.
pub trait FrameSink: std::fmt::Debug + Send + Sync + 'static {
    /// Hand over one frame. It never blocks. Returns `false` if the frame was not accepted.
    fn try_send(&self, frame: Bytes) -> bool;

    /// Whether the sink can still carry a frame. A sink whose topic has closed
    /// says no, and the path is not valid until the next `attach`.
    fn is_alive(&self) -> bool {
        true
    }
}
