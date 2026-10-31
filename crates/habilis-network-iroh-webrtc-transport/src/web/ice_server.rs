/// One `RTCIceServer` entry.
///
/// No `username`/`credential`: those exist only for TURN, which this crate
/// refuses (see [`crate::accept_ice_uri`]). Dropping the fields means a
/// credentialed server cannot be expressed, let alone configured.
///
/// # Examples
///
/// It is built for the browser's own peer connection, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_webrtc_transport::IceServer;
///
/// # fn demo(server: IceServer) -> Vec<String> {
/// server.urls
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IceServer {
    /// The STUN and TURN URLs of the server.
    pub urls: Vec<String>,
}
