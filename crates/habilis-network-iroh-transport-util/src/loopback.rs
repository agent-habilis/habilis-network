//! Bind an endpoint to this host only.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use iroh::endpoint::{BindOpts, Builder, InvalidSocketAddr, PortmapperConfig};

/// Bind the endpoint that `builder` builds to `127.0.0.1` on `port`, where `0` is any free port, and
/// turn its port mapper off.
///
/// An endpoint with no bind address listens on every interface of the machine, and any host on the
/// network can send it a handshake. This one listens on the loopback interfaces only, `127.0.0.1` and
/// `[::1]`, so the machine is the only host that reaches it. The port mapper is the one default that
/// reaches the gateway of the LAN even with the relay off, so it goes too.
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
    // A bind address replaces the default of its own family only. The default `[::]` listens on
    // every interface and stays unless it is replaced, so the IPv6 loopback replaces it. A host
    // without an IPv6 loopback still binds: that socket is not required.
    let builder = builder.bind_addr_with_opts(
        SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0),
        BindOpts::default().set_is_required(false),
    )?;
    Ok(builder.portmapper_config(PortmapperConfig::Disabled))
}
