use std::time::Duration;

use fofoca_iroh_webrtc_transport::{
    IceConfig, WEBRTC_TRANSPORT_ID, WebRtcTransport, answer_with, custom_addr, offer_with,
};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr};

const ECHO_ALPN: &[u8] = b"fofoca-webrtc/test-echo/0";
const JSEP_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        tokio::io::copy(&mut recv, &mut send).await?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

#[tokio::test]
async fn quic_echo_over_webrtc() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let key_client = SecretKey::generate();
    let key_server = SecretKey::generate();
    let id_client = key_client.public();
    let id_server = key_server.public();

    let transport_client = WebRtcTransport::new(id_client);
    let transport_server = WebRtcTransport::new(id_server);

    // JSEP with the envelopes handed over in memory (the carrier is the
    // caller's concern by design).
    let (pending_offer, offer_env) = offer_with(id_client, &IceConfig::host_only()).await?;
    let (pending_answer, answer_env) =
        answer_with(id_server, &offer_env, &IceConfig::host_only()).await?;
    assert_eq!(offer_env.claimed_endpoint()?, id_client);
    assert_eq!(answer_env.claimed_endpoint()?, id_server);
    let (client_session, server_session) = tokio::join!(
        pending_offer.complete(&answer_env, JSEP_DEADLINE),
        pending_answer.complete(JSEP_DEADLINE),
    );
    transport_client.attach(id_server, client_session?)?;
    transport_server.attach(id_client, server_session?)?;
    assert!(transport_client.has_session(&id_server));
    assert!(transport_server.has_session(&id_client));

    let endpoint_server = Endpoint::builder(transport_server.preset())
        .secret_key(key_server)
        .bind()
        .await?;
    let router = Router::builder(endpoint_server)
        .accept(ECHO_ALPN, Echo)
        .spawn();

    let endpoint_client = Endpoint::builder(transport_client.preset())
        .secret_key(key_client)
        .bind()
        .await?;

    let server_addr =
        EndpointAddr::from_parts(id_server, [TransportAddr::Custom(custom_addr(id_server))]);
    let connection = endpoint_client.connect(server_addr, ECHO_ALPN).await?;

    // The only transport is WebRTC, but assert the selected path anyway so
    // a future regression can't silently reroute.
    let paths = connection.paths();
    let on_webrtc = paths.iter().any(|path| {
        matches!(
            path.remote_addr(),
            TransportAddr::Custom(addr) if addr.id() == WEBRTC_TRANSPORT_ID
        )
    });
    assert!(on_webrtc, "no WebRTC path on the connection: {paths:?}");

    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(b"hello over webrtc").await?;
    send.finish()?;
    let echoed = recv.read_to_end(64).await?;
    assert_eq!(echoed, b"hello over webrtc");

    connection.close(0u32.into(), b"done");
    router.shutdown().await?;
    endpoint_client.close().await;

    Ok(())
}

/// A detach must reach the far side at once. Aborting the driver sent
/// nothing, so the far side held a dead session, and one of its direct-peer
/// slots, until ICE consent timed out.
#[tokio::test]
async fn a_detach_ends_the_far_sides_session_too() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let id_client = SecretKey::generate().public();
    let id_server = SecretKey::generate().public();
    let transport_client = WebRtcTransport::new(id_client);
    let transport_server = WebRtcTransport::new(id_server);
    let (pending_offer, offer_env) = offer_with(id_client, &IceConfig::host_only()).await?;
    let (pending_answer, answer_env) =
        answer_with(id_server, &offer_env, &IceConfig::host_only()).await?;
    let (client_session, server_session) = tokio::join!(
        pending_offer.complete(&answer_env, JSEP_DEADLINE),
        pending_answer.complete(JSEP_DEADLINE),
    );
    transport_client.attach(id_server, client_session?)?;
    transport_server.attach(id_client, server_session?)?;

    assert!(transport_client.detach(&id_server));
    let started = std::time::Instant::now();
    while transport_server.has_session(&id_client) {
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the far side still holds the session"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

#[tokio::test]
async fn detach_then_reattach() -> anyhow::Result<()> {
    let key_client = SecretKey::generate();
    let key_server = SecretKey::generate();
    let id_client = key_client.public();
    let id_server = key_server.public();
    let transport_client = WebRtcTransport::new(id_client);

    let (pending_offer, offer_env) = offer_with(id_client, &IceConfig::host_only()).await?;
    let (pending_answer, answer_env) =
        answer_with(id_server, &offer_env, &IceConfig::host_only()).await?;
    let (client_session, server_session) = tokio::join!(
        pending_offer.complete(&answer_env, JSEP_DEADLINE),
        pending_answer.complete(JSEP_DEADLINE),
    );
    drop(server_session?);

    transport_client.attach(id_server, client_session?)?;
    assert!(transport_client.has_session(&id_server));

    // Second attach while live must fail.
    let (second_offer, second_env) = offer_with(id_client, &IceConfig::host_only()).await?;
    let (second_pending_answer, second_answer_env) =
        answer_with(id_server, &second_env, &IceConfig::host_only()).await?;
    let (second_client, second_server) = tokio::join!(
        second_offer.complete(&second_answer_env, JSEP_DEADLINE),
        second_pending_answer.complete(JSEP_DEADLINE),
    );
    drop(second_server?);
    let second_session = second_client?;
    assert!(transport_client.attach(id_server, second_session).is_err());

    assert!(transport_client.detach(&id_server));
    assert!(!transport_client.has_session(&id_server));
    assert_eq!(transport_client.session_count(), 0);
    Ok(())
}

/// A refused duplicate must not disturb the session that refused it.
///
/// `detach_then_reattach` above asserts the duplicate attach returns `Err`, but
/// not that the survivor survives — and that is the half that matters. The
/// browser hub used to fail exactly here: it installed the new channel's
/// handlers *before* checking for a duplicate, so the loser's `onclose` stayed
/// live on an orphan channel and later removed the winner's entry, killing a
/// working data path mid-transfer.
///
/// This pins the host behaviour that the browser side is being made to match.
/// Duplicates are ordinary here, not exotic: the mount lane and the mesh lane
/// share one registry, so either can reach a peer first.
#[tokio::test]
async fn a_refused_duplicate_leaves_the_live_session_working() -> anyhow::Result<()> {
    let key_client = SecretKey::generate();
    let key_server = SecretKey::generate();
    let id_client = key_client.public();
    let id_server = key_server.public();

    let transport_client = WebRtcTransport::new(id_client);
    let transport_server = WebRtcTransport::new(id_server);

    let (pending_offer, offer_env) = offer_with(id_client, &IceConfig::host_only()).await?;
    let (pending_answer, answer_env) =
        answer_with(id_server, &offer_env, &IceConfig::host_only()).await?;
    let (client_session, server_session) = tokio::join!(
        pending_offer.complete(&answer_env, JSEP_DEADLINE),
        pending_answer.complete(JSEP_DEADLINE),
    );
    transport_client.attach(id_server, client_session?)?;
    transport_server.attach(id_client, server_session?)?;

    let endpoint_server = Endpoint::builder(transport_server.preset())
        .secret_key(key_server)
        .bind()
        .await?;
    let router = Router::builder(endpoint_server)
        .accept(ECHO_ALPN, Echo)
        .spawn();
    let endpoint_client = Endpoint::builder(transport_client.preset())
        .secret_key(key_client)
        .bind()
        .await?;

    let server_addr =
        EndpointAddr::from_parts(id_server, [TransportAddr::Custom(custom_addr(id_server))]);
    echo_round_trip(&endpoint_client, &server_addr, b"before the duplicate").await?;

    // A second, fully negotiated session for the same pair — what the other
    // lane would hand us — offered to a registry that already has one.
    let (second_offer, second_env) = offer_with(id_client, &IceConfig::host_only()).await?;
    let (second_answer, second_answer_env) =
        answer_with(id_server, &second_env, &IceConfig::host_only()).await?;
    let (second_client, second_server) = tokio::join!(
        second_offer.complete(&second_answer_env, JSEP_DEADLINE),
        second_answer.complete(JSEP_DEADLINE),
    );
    assert!(
        transport_client.attach(id_server, second_client?).is_err(),
        "a duplicate attach must be refused"
    );
    assert!(
        transport_server.attach(id_client, second_server?).is_err(),
        "and refused from the other side too"
    );

    assert!(transport_client.has_session(&id_server));
    assert_eq!(transport_client.session_count(), 1);
    // The assertion this test exists for: the surviving session still carries
    // traffic. A duplicate that installed its handlers before checking would
    // have left an orphan channel whose `onclose` later removed this very
    // session, and the data path would die with it.
    echo_round_trip(&endpoint_client, &server_addr, b"after the duplicate").await?;

    router.shutdown().await?;
    endpoint_client.close().await;
    Ok(())
}

/// One echo exchange over a connection of its own.
///
/// A fresh connection each time on purpose: `Echo` serves a single bi-stream
/// and then parks on `connection.closed()`, so a second `open_bi` on the same
/// connection is never accepted. Dialling again also makes the assertion
/// stronger — it proves the session still routes a *new* connection, not just
/// one opened while it was known good.
async fn echo_round_trip(
    endpoint: &Endpoint,
    server: &EndpointAddr,
    payload: &[u8],
) -> anyhow::Result<()> {
    let connection = endpoint.connect(server.clone(), ECHO_ALPN).await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(payload).await?;
    send.finish()?;
    let echoed = recv.read_to_end(payload.len() + 64).await?;
    anyhow::ensure!(echoed == payload, "echo mismatch: {echoed:?}");
    connection.close(0u32.into(), b"done");
    Ok(())
}
