//! Helpers for the tests that put a connection on a relay.

/// A local relay server: the one place two endpoints with no IP transport can
/// reach each other.
pub(crate) async fn relay_server() -> (iroh::RelayUrl, iroh_relay::server::Server) {
    let mut config = iroh_relay::server::ServerConfig::default();
    config.relay = Some(iroh_relay::server::RelayConfig::new((
        std::net::Ipv4Addr::LOCALHOST,
        0,
    )));
    config.quic = None;
    let server = iroh_relay::server::Server::spawn(config)
        .await
        .expect("spawn the relay");
    let addr = server.http_addr().expect("relay http address");
    let url = format!("http://{addr}/").parse().expect("relay url");
    (url, server)
}
