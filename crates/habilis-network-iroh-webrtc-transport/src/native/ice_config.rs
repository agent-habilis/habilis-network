use std::time::Duration;

/// Which STUN servers to ask, and how long to wait.
///
/// Configurable rather than hardcoded because the useful answer differs by
/// deployment: a laptop on the open internet wants a public server, a private
/// network wants its own, and the test suite wants none at all.
///
/// # Examples
///
/// A host-only configuration uses no STUN server.
///
/// ```
/// use habilis_network_iroh_webrtc_transport::IceConfig;
///
/// let config = IceConfig::host_only();
/// assert!(config.stun_servers.is_empty());
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IceConfig {
    /// `host:port` STUN servers, all asked at once; the first well-formed
    /// answer wins. Resolved at gather time, so a hostname is fine.
    pub stun_servers: Vec<String>,
    /// The joint budget for the whole gather — resolving every name and
    /// waiting for a Binding Success — not a per-server wait, so one dead
    /// server costs nothing as long as another answers.
    pub stun_timeout: Duration,
}

impl IceConfig {
    /// No STUN: a host candidate only, which reaches the same machine and a
    /// flat LAN and nothing else. What the offline tests use.
    #[must_use]
    pub fn host_only() -> Self {
        Self {
            stun_servers: Vec::new(),
            stun_timeout: Duration::from_secs(2),
        }
    }
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            // See [`DEFAULT_STUN_HOSTS`](crate::DEFAULT_STUN_HOSTS) for why
            // these two and no others.
            stun_servers: crate::DEFAULT_STUN_HOSTS
                .iter()
                .map(|host| (*host).to_owned())
                .collect(),
            stun_timeout: Duration::from_secs(2),
        }
    }
}
