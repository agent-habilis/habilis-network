use super::BrowserHubTransport;

/// Backward-compatible name used by the consume path and older docs.
///
/// # Examples
///
/// It is a browser transport type, so this is not compiled.
///
/// ```ignore
/// let transport: BrowserRtcTransport = make_transport(local);
/// ```
pub type BrowserRtcTransport = BrowserHubTransport;
