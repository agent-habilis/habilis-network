use super::TestRelayError;

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
pub async fn spawn_plain() -> Result<(iroh::RelayUrl, iroh_relay::server::Server), TestRelayError> {
    let mut config = iroh_relay::server::ServerConfig::default();
    config.relay = Some(iroh_relay::server::RelayConfig::new((
        std::net::Ipv4Addr::LOCALHOST,
        0,
    )));
    config.quic = None;
    let server = iroh_relay::server::Server::spawn(config)
        .await
        .map_err(TestRelayError::Spawn)?;
    let address = server.http_addr().ok_or(TestRelayError::NoHttpAddr)?;
    let url = format!("http://{address}/")
        .parse()
        .map_err(TestRelayError::BadUrl)?;
    Ok((url, server))
}
