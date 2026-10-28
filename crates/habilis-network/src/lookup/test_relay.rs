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
pub async fn spawn_plain() -> anyhow::Result<(iroh::RelayUrl, iroh_relay::server::Server)> {
    use anyhow::Context as _;

    let mut config = iroh_relay::server::ServerConfig::default();
    config.relay = Some(iroh_relay::server::RelayConfig::new((
        std::net::Ipv4Addr::LOCALHOST,
        0,
    )));
    config.quic = None;
    let server = iroh_relay::server::Server::spawn(config)
        .await
        .context("spawning the local relay server")?;
    let addr = server
        .http_addr()
        .context("the local relay server bound no HTTP address")?;
    let url = format!("http://{addr}/")
        .parse()
        .context("the local relay address is not a relay URL")?;
    Ok((url, server))
}
