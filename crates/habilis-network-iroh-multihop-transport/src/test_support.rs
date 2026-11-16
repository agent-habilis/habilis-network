//! Helpers for the tests that put a connection on a relay.

use iroh_relay::server;
use std::net;
/// A local relay server: the one place two endpoints with no IP transport can
/// reach each other.
pub(crate) async fn relay_server() -> (iroh::RelayUrl, server::Server) {
    let mut config = server::ServerConfig::default();
    config.relay = Some(server::RelayConfig::new((net::Ipv4Addr::LOCALHOST, 0)));
    config.quic = None;
    let server = server::Server::spawn(config)
        .await
        .expect("spawn the relay");
    let address = server.http_addr().expect("relay http address");
    let url: iroh::RelayUrl = format!("http://{address}/").parse().expect("relay url");
    (url, server)
}
