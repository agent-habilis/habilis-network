//! The sessions the admission counts against the cap.


use habilis_network_iroh_webrtc_transport::WebRtcHandle;
use iroh::EndpointId;



/// What the table needs from a `WebRTC` hub. A trait so a test can stand in
/// for sessions, which cannot be negotiated inside a unit test.
pub(crate) trait Sessions: Send + Sync + 'static {
    fn has_session(&self, peer: &EndpointId) -> bool;
    /// The peers that hold a live session now.
    fn live_peers(&self) -> Vec<EndpointId>;
    /// End the session of `peer`. `true` if there was one.
    fn detach(&self, peer: &EndpointId) -> bool;
}

impl Sessions for WebRtcHandle {
    fn has_session(&self, peer: &EndpointId) -> bool {
        WebRtcHandle::has_session(self, peer)
    }

    fn live_peers(&self) -> Vec<EndpointId> {
        self.live_peer_ids().collect()
    }

    fn detach(&self, peer: &EndpointId) -> bool {
        WebRtcHandle::detach(self, peer)
    }
}
