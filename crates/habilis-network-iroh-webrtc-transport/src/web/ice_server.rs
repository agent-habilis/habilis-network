/// One `RTCIceServer` entry.
///
/// No `username`/`credential`: those exist only for TURN, which this crate
/// refuses (see [`crate::accept_ice_uri`]). Dropping the fields means a
/// credentialed server cannot be expressed, let alone configured.
///
/// # Examples
///
/// It is built for the browser's own peer connection, so this is not compiled.
///
/// ```ignore
/// let server = IceServer { urls: vec!["stun:stun.example.org".to_owned()] };
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IceServer {
    /// The STUN and TURN URLs of the server.
    pub urls: Vec<String>,
}
