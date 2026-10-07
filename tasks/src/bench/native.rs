//! The native cells: iroh endpoints in this process, on loopback.
//!
//! Three shapes. Plain iroh on UDP is the ceiling. The engine-shaped endpoint
//! registers the WebRTC transport beside UDP and lets the path selector pick,
//! which is what two native habilis-network peers do — and it picks UDP, so that cell
//! is a check that registering the transport costs nothing, not a WebRTC
//! number. The webrtc-only pair is str0m at both ends and the only native cell
//! that goes through the data channel at all.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use habilis_network_iroh_multihop_transport::MULTIHOP_TRANSPORT_ID;
use habilis_network_iroh_webrtc_transport::bench::{
    BENCH_ALPN, Bench, exchange, on_webrtc, rtt_samples,
};
use habilis_network_iroh_webrtc_transport::iroh::endpoint::{Builder, Connection, Path, presets};
use habilis_network_iroh_webrtc_transport::iroh::protocol::Router;
use habilis_network_iroh_webrtc_transport::iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr,
};
use habilis_network_iroh_webrtc_transport::{
    IceConfig, WEBRTC_TRANSPORT_ID, WebRtcHandle, WebRtcTransport, answer_with, custom_addr,
    offer_with,
};

use super::Args;
use super::run::{Measured, Outcome, Rtt, Sample, TRANSFER_TIMEOUT};

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

fn path_of(connection: &Connection) -> String {
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
    let samples = rounds_on(&connection, args, path_of).await?;
    connection.close(0u32.into(), b"done");
    Ok(samples)
}

/// The transfers of [`rounds`] over a connection that is already open, with
/// `path` naming what carried each one.
async fn rounds_on(
    connection: &Connection,
    args: &Args,
    path: impl Fn(&Connection) -> String,
) -> Result<Vec<Sample>, String> {
    let mut samples = Vec::with_capacity(args.rounds + 1);
    for _ in 0..=args.rounds {
        let path = path(connection);
        let started = Instant::now();
        let bytes = tokio::time::timeout(
            TRANSFER_TIMEOUT,
            exchange(connection, args.direction.protocol(), args.bytes),
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
    Ok(samples)
}

/// Probes sent and dropped before the timed ones: the first round trips pay
/// for the congestion window and for path setup.
const RTT_WARMUP: usize = 50;
/// Timed round trips per ladder cell.
const RTT_ROUNDS: usize = 1000;

/// The selected path of `connection`, named the way a cell expects it. The
/// selected path, not any path: a cell that claims a rung must have used it.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "`TransportAddr` is non-exhaustive: a rung this runner does not name is `other`"
)]
pub(crate) fn selected_path(connection: &Connection) -> String {
    connection
        .paths()
        .iter()
        .find(Path::is_selected)
        .map_or("other", |path| match path.remote_addr() {
            TransportAddr::Ip(_) => "ip",
            TransportAddr::Relay(_) => "relay",
            TransportAddr::Custom(addr) if addr.id() == WEBRTC_TRANSPORT_ID => "webrtc",
            TransportAddr::Custom(addr) if addr.id() == MULTIHOP_TRANSPORT_ID => "multihop",
            _ => "other",
        })
        .to_owned()
}

/// One ladder cell over one connection from `client` to `server`: the transfer
/// rounds, then the round trips, both on the selected path.
pub(super) async fn ladder_measure(
    client: &Endpoint,
    server: EndpointAddr,
    args: &Args,
    negotiate_ms: f64,
) -> Result<Measured, String> {
    let connection = client
        .connect(server, BENCH_ALPN)
        .await
        .map_err(|error| format!("connect failed: {error:#}"))?;
    let samples = rounds_on(&connection, args, selected_path).await?;
    let round_trips = tokio::time::timeout(
        TRANSFER_TIMEOUT,
        rtt_samples(&connection, RTT_WARMUP, RTT_ROUNDS),
    )
    .await
    .map_err(|_| format!("the round trips stalled past {TRANSFER_TIMEOUT:?}"))?
    .map_err(|error| format!("round trips failed: {error:#}"))?;
    connection.close(0u32.into(), b"done");
    let mut measured = Measured::from_samples(negotiate_ms, samples)?;
    measured.rtt = Rtt::from_samples(&round_trips);
    Ok(measured)
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

/// Two endpoints whose only transport is `WebRTC`, with the JSEP round done in
/// memory: the client, the server serving [`Bench`], and the round's
/// milliseconds. The server's router is returned so it stays alive.
async fn webrtc_pair() -> Result<(WebRtcPeer, WebRtcPeer, Router, f64), String> {
    let client = WebRtcPeer::bind().await?;
    let server = WebRtcPeer::bind().await?;
    let router = Router::builder(server.endpoint.clone())
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
    Ok((client, server, router, negotiate_ms))
}

fn webrtc_addr(server: &WebRtcPeer) -> EndpointAddr {
    EndpointAddr::from_parts(server.id, [TransportAddr::Custom(custom_addr(server.id))])
}

/// str0m at both ends: JSEP in memory, then the data channel is the only path.
pub(crate) async fn habilis_network_native_native_webrtc(args: &Args) -> Outcome {
    let run = async {
        let (client, server, _router, negotiate_ms) = Box::pin(webrtc_pair()).await?;
        let samples = rounds(&client.endpoint, webrtc_addr(&server), args).await?;
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

pub(crate) async fn habilis_network_native_native(args: &Args) -> Outcome {
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

/// The ladder's UDP cell: plain iroh on loopback, throughput and round trips.
pub(crate) async fn ladder_udp(args: &Args) -> Outcome {
    let run = async {
        let client = vanilla().await?;
        let server = vanilla().await?;
        let addr = ip_addr(&server)?;
        let _router = Router::builder(server).accept(BENCH_ALPN, Bench).spawn();
        ladder_measure(&client, addr, args, 0.0).await
    };
    run.await.into()
}

/// The ladder's `WebRTC` cell: str0m at both ends, the data channel the only
/// path, throughput and round trips.
pub(crate) async fn ladder_webrtc(args: &Args) -> Outcome {
    let run = async {
        let (client, server, _router, negotiate_ms) = Box::pin(webrtc_pair()).await?;
        ladder_measure(&client.endpoint, webrtc_addr(&server), args, negotiate_ms).await
    };
    Box::pin(run).await.into()
}

#[cfg(test)]
mod tests {
    use super::{
        Args, BENCH_ALPN, Bench, Outcome, Router, ip_addr, ladder_udp, ladder_webrtc, rounds,
        vanilla,
    };
    use crate::bench::Direction;
    use habilis_network_iroh_webrtc_transport::bench::MAX_TRANSFER_BYTES;

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

    fn small_args() -> Args {
        Args {
            only: None,
            bytes: 64 * 1024,
            rounds: 2,
            direction: Direction::Down,
            list: false,
            json: None,
        }
    }

    /// The ladder's UDP cell carries both measurements: the transfer rounds
    /// and the 1000 round trips after 50 warm-up probes, on the IP path.
    #[tokio::test]
    async fn the_ladder_udp_cell_measures_throughput_and_round_trips_on_ip() {
        let Outcome::Ok(measured) = ladder_udp(&small_args()).await else {
            panic!("the ladder udp cell did not measure");
        };

        assert_eq!(measured.path, "ip");
        let rtt = measured.rtt.expect("round-trip percentiles");
        assert!(rtt.p50_ms > 0.0 && rtt.p99_ms >= rtt.p50_ms);
    }

    /// The ladder's `WebRTC` cell is on the data channel, and measures both.
    #[tokio::test]
    async fn the_ladder_webrtc_cell_measures_throughput_and_round_trips_on_webrtc() {
        let Outcome::Ok(measured) = ladder_webrtc(&small_args()).await else {
            panic!("the ladder webrtc cell did not measure");
        };

        assert_eq!(measured.path, "webrtc");
        assert!(measured.rtt.is_some());
    }
}
