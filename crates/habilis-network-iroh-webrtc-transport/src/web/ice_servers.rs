use wasm_bindgen::prelude::JsValue;
use web_sys::RtcConfiguration;

use super::ice_server::IceServer;

use js_sys::Reflect;
/// ICE servers for the browser's own agent.
///
/// # Examples
///
/// A host-only set of ICE servers names none. The web module is private, so the doc test compiles it but does not run it.
///
/// ```
/// use habilis_network_iroh_webrtc_transport::IceServers;
///
/// assert!(IceServers::host_only().0.is_empty());
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IceServers(pub Vec<IceServer>);

impl Default for IceServers {
    fn default() -> Self {
        // See [`DEFAULT_STUN_HOSTS`](crate::DEFAULT_STUN_HOSTS) for why these
        // two and no others; the browser wants each as a `stun:` URI.
        Self(vec![IceServer {
            urls: crate::DEFAULT_STUN_HOSTS
                .iter()
                .map(|host| format!("stun:{host}"))
                .collect(),
        }])
    }
}

impl IceServers {
    /// No STUN or TURN server, so only host addresses are used.
    #[must_use]
    pub fn host_only() -> Self {
        Self(Vec::new())
    }

    pub(super) fn to_configuration(&self) -> RtcConfiguration {
        let config = RtcConfiguration::new();
        let servers = js_sys::Array::new();
        for server in &self.0 {
            let entry = js_sys::Object::new();
            let urls = js_sys::Array::new();
            // The enforcement point: anything `accept_ice_uri` refuses never
            // reaches the browser. TURN cannot be configured here even by
            // mistake, and a query string Safari would throw on is stripped
            // before it can take down the whole peer connection.
            for url in &server.urls {
                let Some(url) = crate::accept_ice_uri(url) else {
                    continue;
                };
                urls.push(&JsValue::from_str(&url));
            }
            if urls.length() == 0 {
                continue;
            }
            let _ = Reflect::set(&entry, &JsValue::from_str("urls"), &urls);
            servers.push(&entry);
        }
        config.set_ice_servers(&servers);
        config
    }
}
