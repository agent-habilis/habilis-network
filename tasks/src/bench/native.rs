//! The native cells: iroh endpoints in this process, on loopback.
//!
//! Three shapes. Plain iroh on UDP is the ceiling. The engine-shaped endpoint
//! registers the WebRTC transport beside UDP and lets the path selector pick,
//! which is what two native fofoca peers do — and it picks UDP, so that cell
//! is a check that registering the transport costs nothing, not a WebRTC
//! number. The webrtc-only pair is str0m at both ends and the only native cell
//! that goes through the data channel at all.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fofoca_iroh_webrtc_transport::bench::{BENCH_ALPN, Bench, exchange, on_webrtc};
use fofoca_iroh_webrtc_transport::iroh::endpoint::{Builder, presets};
use fofoca_iroh_webrtc_transport::iroh::protocol::Router;
use fofoca_iroh_webrtc_transport::iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr,
};
use fofoca_iroh_webrtc_transport::{
    IceConfig, WebRtcHandle, WebRtcTransport, answer_with, custom_addr, offer_with,
};

use super::Args;
use super::run::{Measured, Outcome, Sample, TRANSFER_TIMEOUT};

/// A JSEP round on loopback is milliseconds; this is the stall bound.
pub(crate) const JSEP_DEADLINE: Duration = Duration::from_secs(30);

/// A native endpoint whose only transport is WebRTC.
pub(crate) struct WebRtcPeer {
    pub(crate) id: EndpointId,
    pub(crate) transport: Arc<WebRtcTransport>,
    pub(crate) endpoint: Endpoint,
}

impl WebRtcPeer {
    pub(crate) async fn bind() -> Result<Self, String> {
        let key = SecretKey::generate();
        let id = key.public();
        let transport = WebRtcTransport::new(id);
        let endpoint = Endpoint::builder(transport.preset())
            .secret_key(key)
            .bind()
            .await
            .map_err(|error| format!("bind failed: {error:#}"))?;
        Ok(Self {
            id,
            transport,
            endpoint,
        })
    }
}

fn path_of(connection: &fofoca_iroh_webrtc_transport::iroh::endpoint::Connection) -> String {
    if on_webrtc(connection) {
        return "webrtc".to_owned();
    }
    let on_ip = connection
        .paths()
        .iter()
        .any(|path| matches!(path.remote_addr(), TransportAddr::Ip(_)));
    if on_ip { "ip" } else { "other" }.to_owned()
}

/// Warm-up plus `rounds` transfers from `client` to `server` over one
/// connection, each timed from stream open to the last verified byte.
async fn rounds(
    client: &Endpoint,
    server: EndpointAddr,
    args: &Args,
) -> Result<Vec<Sample>, String> {
    let connection = client
        .connect(server, BENCH_ALPN)
        .await
        .map_err(|error| format!("connect failed: {error:#}"))?;
    let mut samples = Vec::with_capacity(args.rounds + 1);
    for _ in 0..=args.rounds {
        let path = path_of(&connection);
        let started = Instant::now();
        let bytes = tokio::time::timeout(
            TRANSFER_TIMEOUT,
            exchange(&connection, args.direction.protocol(), args.bytes),
        )
        .await
        .map_err(|_| format!("a transfer stalled past {TRANSFER_TIMEOUT:?}"))?
        .map_err(|error| format!("exchange failed: {error:#}"))?;
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        samples.push(Sample {
            bytes,
            elapsed_ms,
            path,
        });
    }
    connection.close(0u32.into(), b"done");
    Ok(samples)
}

/// The first `IPv4` socket the endpoint bound, as a dialable address.
fn ip_addr(endpoint: &Endpoint) -> Result<EndpointAddr, String> {
    let socket = endpoint
        .bound_sockets()
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| "the endpoint bound no IPv4 socket".to_owned())?;
    Ok(EndpointAddr::from_parts(
        endpoint.id(),
        [TransportAddr::Ip(socket)],
    ))
}

/// Plain iroh on loopback UDP, no relay: the base every native IP cell
/// builds on.
fn loopback_builder() -> Result<Builder, String> {
    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("a literal loopback address");
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind_addr(loopback)
        .map_err(|error| format!("bind address refused: {error:#}"))
}

/// str0m at both ends: JSEP in memory, then the data channel is the only path.
pub(crate) async fn fofoca_native_native_webrtc(args: &Args) -> Outcome {
    let run = async {
        let client = WebRtcPeer::bind().await?;
        let server = WebRtcPeer::bind().await?;
        let _router = Router::builder(server.endpoint.clone())
            .accept(BENCH_ALPN, Bench)
            .spawn();

        let started = Instant::now();
        let (pending_offer, offer) = offer_with(client.id, &IceConfig::host_only())
            .await
            .map_err(|error| format!("offer failed: {error:#}"))?;
        let (pending_answer, answer) = answer_with(server.id, &offer, &IceConfig::host_only())
            .await
            .map_err(|error| format!("answer failed: {error:#}"))?;
        let (client_session, server_session) = tokio::join!(
            pending_offer.complete(&answer, JSEP_DEADLINE),
            pending_answer.complete(JSEP_DEADLINE),
        );
        client
            .transport
            .attach(
                server.id,
                client_session.map_err(|error| format!("client complete failed: {error:#}"))?,
            )
            .map_err(|error| format!("client attach failed: {error:#}"))?;
        server
            .transport
            .attach(
                client.id,
                server_session.map_err(|error| format!("server complete failed: {error:#}"))?,
            )
            .map_err(|error| format!("server attach failed: {error:#}"))?;
        let negotiate_ms = started.elapsed().as_secs_f64() * 1000.0;

        let addr =
            EndpointAddr::from_parts(server.id, [TransportAddr::Custom(custom_addr(server.id))]);
        let samples = rounds(&client.endpoint, addr, args).await?;
        Measured::from_samples(negotiate_ms, samples)
    };
    Box::pin(run).await.into()
}

/// The engine's wiring for a native peer: UDP on loopback, the WebRTC
/// transport registered beside it, the selector that prefers direct IP.
async fn engine_shaped() -> Result<Endpoint, String> {
    let key = SecretKey::generate();
    let transport = WebRtcTransport::new(key.public());
    let handle = WebRtcHandle::new(Arc::clone(&transport));
    loopback_builder()?
        .secret_key(key)
        .add_custom_transport(transport)
        .path_selector(handle.path_selector())
        .bind()
        .await
        .map_err(|error| format!("bind failed: {error:#}"))
}

pub(crate) async fn fofoca_native_native(args: &Args) -> Outcome {
    ip_pair(args, engine_shaped).await
}

/// Plain iroh on loopback UDP, nothing registered.
async fn vanilla() -> Result<Endpoint, String> {
    loopback_builder()?
        .bind()
        .await
        .map_err(|error| format!("bind failed: {error:#}"))
}

pub(crate) async fn iroh_native_native(args: &Args) -> Outcome {
    ip_pair(args, vanilla).await
}

/// Two endpoints from `bind`, dialed by their IP address.
async fn ip_pair<F: Future<Output = Result<Endpoint, String>>>(
    args: &Args,
    bind: impl Fn() -> F,
) -> Outcome {
    let run = async {
        let client = bind().await?;
        let server = bind().await?;
        let addr = ip_addr(&server)?;
        let _router = Router::builder(server).accept(BENCH_ALPN, Bench).spawn();
        let samples = rounds(&client, addr, args).await?;
        Measured::from_samples(0.0, samples)
    };
    run.await.into()
}

#[cfg(test)]
mod tests {
    use super::{Args, BENCH_ALPN, Bench, Router, ip_addr, rounds, vanilla};
    use crate::bench::Direction;
    use fofoca_iroh_webrtc_transport::bench::MAX_TRANSFER_BYTES;

    /// An upload's throughput is the bulk it sent, not the token it got back.
    #[tokio::test]
    async fn an_upload_sample_counts_the_bulk_it_sent() {
        let args = Args {
            only: None,
            bytes: 64 * 1024,
            rounds: 1,
            direction: Direction::Up,
            list: false,
            json: None,
        };
        let client = vanilla().await.expect("bind the client");
        let server = vanilla().await.expect("bind the server");
        let addr = ip_addr(&server).expect("the server has an IPv4 socket");
        let _router = Router::builder(server).accept(BENCH_ALPN, Bench).spawn();

        let samples = rounds(&client, addr, &args).await.expect("the rounds run");

        let counted: Vec<usize> = samples.iter().map(|sample| sample.bytes).collect();
        assert!(
            counted.iter().all(|&bytes| bytes == args.bytes),
            "samples counted {counted:?} bytes, the upload sent {}",
            args.bytes
        );
    }

    /// Bulk both ways at once moves twice the bulk, and the rate counts both.
    #[tokio::test]
    async fn a_both_ways_sample_counts_both_directions() {
        let args = Args {
            only: None,
            bytes: 64 * 1024,
            rounds: 1,
            direction: Direction::Both,
            list: false,
            json: None,
        };
        let client = vanilla().await.expect("bind the client");
        let server = vanilla().await.expect("bind the server");
        let addr = ip_addr(&server).expect("the server has an IPv4 socket");
        let _router = Router::builder(server).accept(BENCH_ALPN, Bench).spawn();

        let samples = rounds(&client, addr, &args).await.expect("the rounds run");

        let counted: Vec<usize> = samples.iter().map(|sample| sample.bytes).collect();
        assert!(
            counted.iter().all(|&bytes| bytes == 2 * args.bytes),
            "samples counted {counted:?} bytes, both directions moved {}",
            2 * args.bytes
        );
    }

    /// The reply bytes a `Bench` server sends for one raw request header.
    async fn reply_to(mode: u8, wanted: u32) -> usize {
        let client = vanilla().await.expect("bind the client");
        let server = vanilla().await.expect("bind the server");
        let addr = ip_addr(&server).expect("the server has an IPv4 socket");
        let _router = Router::builder(server).accept(BENCH_ALPN, Bench).spawn();
        let connection = client.connect(addr, BENCH_ALPN).await.expect("connect");
        let (mut send, mut recv) = connection.open_bi().await.expect("open a stream");
        let mut head = vec![mode];
        head.extend_from_slice(&wanted.to_le_bytes());
        send.write_all(&head).await.expect("send the header");
        let _ = send.finish();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0;
        while let Ok(Some(read)) = recv.read(&mut buf).await {
            total += read;
        }
        total
    }

    #[tokio::test]
    async fn a_bench_server_refuses_an_unknown_mode() {
        assert_eq!(reply_to(7, 1024).await, 0);
    }

    #[tokio::test]
    async fn a_bench_server_refuses_a_reply_past_the_transfer_ceiling() {
        let past = u32::try_from(MAX_TRANSFER_BYTES + 1).expect("the ceiling fits in u32");
        assert_eq!(reply_to(0, past).await, 0);
    }
}
