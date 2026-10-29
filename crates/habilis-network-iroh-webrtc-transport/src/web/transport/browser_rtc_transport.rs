use super::BrowserHubTransport;

/// Backward-compatible name used by the consume path and older docs.
///
/// # Examples
///
/// It is a browser transport type, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_webrtc_transport::BrowserRtcTransport;
///
/// # fn demo(transport: BrowserRtcTransport) {
/// drop(transport);
/// # }
/// ```
pub type BrowserRtcTransport = BrowserHubTransport;
