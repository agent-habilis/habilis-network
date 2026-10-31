use super::TestRelayError;

use iroh_relay::server;
use std::net;
/// Spawn the relay; the URL is `http://127.0.0.1:<port>/`. Dropping the
/// server stops it.
///
/// # Errors
/// Binding or spawning the relay server fails.
#[cfg_attr(
    not(feature = "iroh-test-utils"),
    expect(
        unreachable_pub,
        reason = "`net` re-exports it only with `iroh-test-utils`"
    )
)]
pub async fn spawn_plain() -> Result<(iroh::RelayUrl, server::Server), TestRelayError> {
    let mut config = server::ServerConfig::default();
    config.relay = Some(server::RelayConfig::new((net::Ipv4Addr::LOCALHOST, 0)));
    config.quic = None;
    let server = server::Server::spawn(config)
        .await
        .map_err(TestRelayError::Spawn)?;
    let address = server.http_addr().ok_or(TestRelayError::NoHttpAddr)?;
    let url = format!("http://{address}/")
        .parse()
        .map_err(TestRelayError::BadUrl)?;
    Ok((url, server))
}
