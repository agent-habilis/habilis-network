use crate::protocol::message::Authored;

/// An inbound `App` frame plus the surfacing decision already made by the
/// engine's generic prefix (join-horizon / third-party gating), passed to
/// [`NodeApp::on_app_frame`](super::NodeApp::on_app_frame).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InboundApp<'message> {
    /// The message as it was authored.
    pub message: &'message Authored,
    /// Whether the engine lets the frame surface.
    pub surfaceable: bool,
}
