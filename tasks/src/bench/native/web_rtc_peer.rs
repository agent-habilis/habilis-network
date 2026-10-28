use std::sync::Arc;

use habilis_network_iroh_webrtc_transport::WebRtcTransport;
use habilis_network_iroh_webrtc_transport::iroh::{Endpoint, EndpointId, SecretKey};

/// A native endpoint whose only transport is WebRTC.
pub(crate) struct WebRtcPeer {
    pub(crate) id: EndpointId,
    pub(crate) transport: Arc<WebRtcTransport>,
    pub(crate) endpoint: Endpoint,
}

impl WebRtcPeer {
    pub(crate) async fn bind() -> Result<Self, String> {
        let key = SecretKey::generate();
        let id = key.public();
        let transport = WebRtcTransport::new(id);
        let endpoint = Endpoint::builder(transport.preset())
            .secret_key(key)
            .bind()
            .await
            .map_err(|error| format!("bind failed: {error:#}"))?;
        Ok(Self {
            id,
            transport,
            endpoint,
        })
    }
}
