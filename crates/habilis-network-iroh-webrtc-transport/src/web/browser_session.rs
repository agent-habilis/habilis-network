use iroh_base::EndpointId;

/// A negotiated browser session attached into a [`BrowserHubTransport`](super::BrowserHubTransport).
///
/// # Examples
///
/// It holds a browser peer connection, so this is not compiled.
///
/// ```ignore
/// let session = BrowserSession::new(hub, peer);
/// ```
#[non_exhaustive]
pub struct BrowserSession {
    /// The endpoint id of the peer.
    pub remote: EndpointId,
}

impl std::fmt::Debug for BrowserSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserSession")
            .field("remote", &self.remote)
            .finish()
    }
}
