//! Bind an endpoint to this host only.

use std::net::{Ipv4Addr, SocketAddrV4};

use iroh::endpoint::{Builder, InvalidSocketAddr, PortmapperConfig};

/// Bind the endpoint that `builder` builds to `127.0.0.1` on `port`, where `0` is any free port, and
/// turn its port mapper off.
///
/// An endpoint with no bind address listens on every interface of the machine, and any host on the
/// network can send it a handshake. This one listens on the loopback interface only, so the machine
/// is the only host that reaches it, and it advertises one address, `127.0.0.1`. The port mapper is
/// the one default that reaches the gateway of the LAN even with the relay off, so it goes too.
///
/// # Errors
/// An address that the endpoint cannot bind, which `127.0.0.1` is not on a host that has a
/// loopback interface.
///
/// # Examples
///
/// The endpoint listens on loopback sockets only.
///
/// ```
/// use habilis_network_iroh_transport_util::loopback;
/// use iroh::Endpoint;
/// use iroh::endpoint::presets;
///
/// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// let endpoint = loopback(Endpoint::builder(presets::Minimal), 0)?.bind().await?;
/// assert!(endpoint.bound_sockets().iter().all(|socket| socket.ip().is_loopback()));
/// # Ok(())
/// # }
/// ```
pub fn loopback(builder: Builder, port: u16) -> Result<Builder, InvalidSocketAddr> {
    let builder = builder.bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))?;
    Ok(builder.portmapper_config(PortmapperConfig::Disabled))
}
