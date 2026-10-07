//! The bulk protocol the browser tests and `cargo task benchmark` share: one
//! request header, then bytes in whichever direction it names.
//!
//! It lives in the crate rather than in `tests/` because a wasm page and a
//! native runner cannot both include a test module, and two copies of a wire
//! format is how the JSEP envelope came to be written out twice upstream.
//! Behind the `bench` feature so a consumer that only wants the transport does
//! not link a protocol handler it never registers.

use crate::WEBRTC_TRANSPORT_ID;
use iroh::TransportAddr;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};

pub const BENCH_ALPN: &[u8] = b"habilis-network-webrtc/test-bench/0";

/// Bytes the plain bulk case asks for. Comfortably past one QUIC congestion
/// window and past the transport's own 256-datagram outbound queue, which is
/// the point: a burst that fits in the queue proves nothing about a burst that
/// does not.
pub const BULK_BYTES: usize = 1 << 20;

/// Ceiling on one transfer, so `read_to_end` has a bound that is not a memory
/// policy in disguise. Above any cell the matrix runs.
pub const MAX_TRANSFER_BYTES: usize = 64 << 20;

/// Which way the bulk flows in one exchange.
///
/// The consumer's stall was on `OP_READ` — a small request, a bulk reply — so
/// [`Self::Download`] is the shape that matters most and the one the regression
/// suite uses. The other two exist because "the send pump drops under load" and
/// "the receive path drops under load" are different claims, and an exchange
/// that is bulk in both directions cannot distinguish them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Small request, bulk reply — the `OP_READ` shape.
    Download,
    /// Bulk request, small reply — stresses the initiator's send pump.
    Upload,
    /// Bulk both ways at once.
    Both,
}

impl Direction {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Download => "down",
            Self::Upload => "up",
            Self::Both => "both",
        }
    }

    /// The inverse of [`Self::label`].
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        [Self::Download, Self::Upload, Self::Both]
            .into_iter()
            .find(|direction| direction.label() == label)
    }

    /// Bytes crossing the wire in one exchange of `size`, for the in-flight
    /// budget the matrix enforces.
    #[must_use]
    pub fn bytes_for(self, size: usize) -> usize {
        match self {
            Self::Download | Self::Upload => size,
            Self::Both => size * 2,
        }
    }
}

/// One exchange's request header: the mode, then the byte count wanted back.
///
/// Five bytes rather than four so the server can be told which direction to
/// play without a second stream or a second ALPN. `Upload` sets `wanted` to a
/// token reply size; the bulk is what follows on the request stream.
const HEADER_LEN: usize = 5;

/// The mode byte of an echo probe: the request carries `wanted` bytes and the
/// reply returns as many. A mode byte rather than a [`Direction`], because a
/// probe measures latency and not a direction of bulk.
const MODE_ECHO: u8 = 3;

fn header_with_mode(mode: u8, wanted: u32) -> [u8; HEADER_LEN] {
    let mut bytes = [0u8; HEADER_LEN];
    bytes[0] = mode;
    bytes[1..].copy_from_slice(&wanted.to_le_bytes());
    bytes
}

fn header(direction: Direction, wanted: u32) -> [u8; HEADER_LEN] {
    header_with_mode(
        match direction {
            Direction::Download => 0,
            Direction::Upload => 1,
            Direction::Both => 2,
        },
        wanted,
    )
}

/// The bulk peer: reads a header, then plays whichever direction it names.
///
/// Serves one exchange per bi-stream, as many streams as the client opens,
/// until the connection closes. A benchmark reuses one connection so only its
/// warm-up round pays the handshake and the congestion-window ramp.
#[derive(Debug, Clone)]
pub struct Bench;

impl ProtocolHandler for Bench {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // The client closing the connection is how every session ends, so an
        // `accept_bi` error is the normal exit, not a failure.
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            let mut head = [0u8; HEADER_LEN];
            recv.read_exact(&mut head)
                .await
                .map_err(AcceptError::from_err)?;
            let wanted = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
            // The peer names the reply size, so the ceiling `exchange` keeps
            // on its side has to hold here too, or one header asks for 4 GiB.
            if head[0] > MODE_ECHO || wanted > MAX_TRANSFER_BYTES {
                return Err(AcceptError::from_err(std::io::Error::other(format!(
                    "refused request: mode {}, {wanted} bytes wanted",
                    head[0]
                ))));
            }

            // Anything after the header on the request stream is the client's
            // bulk upload. Drained and verified before replying, so a corrupted
            // upload fails as an upload rather than as a mismatched reply.
            if matches!(head[0], 1 | 2 | MODE_ECHO) {
                let uploaded = recv
                    .read_to_end(MAX_TRANSFER_BYTES)
                    .await
                    .map_err(AcceptError::from_err)?;
                if !is_payload(&uploaded) {
                    return Err(AcceptError::from_err(std::io::Error::other(
                        "uploaded body did not match the expected pattern",
                    )));
                }
            }

            // One write of the whole reply: handing QUIC the entire body at
            // once is what produces the burst the outbound pump has to survive.
            // Feeding it in small pieces would pace the sender for it and hide
            // the defect.
            send.write_all(&payload(wanted))
                .await
                .map_err(AcceptError::from_err)?;
            send.finish().map_err(AcceptError::from_err)?;
        }
        Ok(())
    }
}

/// One period of [`payload`]. A prime length, so the pattern does not line
/// up with any power-of-two buffer or packet size.
const BLOCK: [u8; 251] = {
    let mut block = [0u8; 251];
    let mut index = 0;
    while index < block.len() {
        #[expect(clippy::cast_possible_truncation, reason = "index < 251")]
        {
            block[index] = index as u8;
        }
        index += 1;
    }
    block
};

/// A recognisable, position-dependent body, so a truncated or misordered
/// transfer fails on content rather than only on length.
#[must_use]
pub fn payload(len: usize) -> Vec<u8> {
    let mut body = BLOCK.repeat(len.div_ceil(BLOCK.len()));
    body.truncate(len);
    body
}

/// Verify a body against [`payload`] **without building it**.
///
/// The matrix runs 8 `MiB` cells at concurrency 4; materialising an expected
/// vector per check would double the tab's peak memory for no benefit, and an
/// OOM-killed tab is not a transport finding.
#[must_use]
pub fn is_payload(body: &[u8]) -> bool {
    body.chunks(BLOCK.len())
        .all(|chunk| chunk == &BLOCK[..chunk.len()])
}

/// Does any path of this connection ride the `WebRTC` transport?
///
/// A cell that claims to be `WebRTC` asserts this, so a future regression
/// cannot silently reroute onto IP and call it a pass.
#[must_use]
pub fn on_webrtc(connection: &Connection) -> bool {
    connection.paths().iter().any(|path| {
        matches!(
            path.remote_addr(),
            TransportAddr::Custom(addr) if addr.id() == WEBRTC_TRANSPORT_ID
        )
    })
}

/// A browser endpoint whose only transport is `hub`, with no relay, so a
/// run that claims to be browser↔browser can be shown to be one.
///
/// # Errors
/// The endpoint cannot bind.
#[cfg(all(feature = "web", not(feature = "native")))]
pub async fn browser_endpoint(
    key: iroh::SecretKey,
    hub: &crate::WebRtcHandle,
) -> anyhow::Result<iroh::Endpoint> {
    Ok(iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(key)
        .relay_mode(iroh::RelayMode::Disabled)
        .add_custom_transport(hub.transport())
        .path_selector(hub.path_selector())
        .bind()
        .await?)
}

/// One exchange in `direction`, sized `bulk`, over an already-open
/// `connection` to a [`Bench`] server. Returns the bulk bytes that crossed the
/// wire once the reply is verified: `bulk`, or twice it for
/// [`Direction::Both`] (see [`Direction::bytes_for`]).
///
/// No deadline inside: a stall is silent and indefinite, so callers wrap this
/// in whichever timeout their runtime has, and a benchmark times exactly this
/// call.
///
/// # Errors
/// A `bulk` past [`MAX_TRANSFER_BYTES`], a stream or write failure, a short
/// reply, or a reply whose bytes do not match [`payload`].
pub async fn exchange(
    connection: &Connection,
    direction: Direction,
    bulk: usize,
) -> anyhow::Result<usize> {
    // A token reply, small enough that the `Upload` case is unambiguously
    // measuring one direction. Not zero: a reply of nothing would let a
    // completely dead return path pass.
    const TOKEN: usize = 32;

    anyhow::ensure!(
        bulk <= MAX_TRANSFER_BYTES,
        "{bulk} bytes is past the {MAX_TRANSFER_BYTES}-byte transfer ceiling"
    );
    let reply = match direction {
        Direction::Download | Direction::Both => bulk,
        Direction::Upload => TOKEN,
    };
    let upload = match direction {
        Direction::Upload | Direction::Both => bulk,
        Direction::Download => 0,
    };

    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&header(direction, u32::try_from(reply)?))
        .await?;
    if upload > 0 {
        send.write_all(&payload(upload)).await?;
    }
    send.finish()?;
    let body = recv.read_to_end(reply + 64).await?;

    anyhow::ensure!(
        body.len() == reply,
        "short reply: wanted {reply} bytes, got {}",
        body.len()
    );
    anyhow::ensure!(is_payload(&body), "reply body did not match");
    Ok(direction.bytes_for(bulk))
}

/// Bytes of one round-trip probe: a 1 `KiB` request and a 1 `KiB` echo.
pub const RTT_PROBE_BYTES: usize = 1024;

/// Round-trip time of `rounds` probes after `warmup` discarded ones, over an
/// already-open `connection` to a [`Bench`] server.
///
/// # Errors
/// A stream or write failure, or a reply that is not the probe.
pub async fn rtt_samples(
    connection: &Connection,
    warmup: usize,
    rounds: usize,
) -> anyhow::Result<Vec<std::time::Duration>> {
    let probe = payload(RTT_PROBE_BYTES);
    let head = header_with_mode(MODE_ECHO, u32::try_from(RTT_PROBE_BYTES)?);
    let mut samples = Vec::with_capacity(rounds);
    for round in 0..warmup + rounds {
        let started = std::time::Instant::now();
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(&head).await?;
        send.write_all(&probe).await?;
        send.finish()?;
        let echo = recv.read_to_end(RTT_PROBE_BYTES + 64).await?;
        let elapsed = started.elapsed();
        anyhow::ensure!(echo == probe, "the echo is not the probe");
        if round >= warmup {
            samples.push(elapsed);
        }
    }
    Ok(samples)
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use std::net::SocketAddr;

    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::{Endpoint, EndpointAddr, RelayMode, TransportAddr};

    use super::{BENCH_ALPN, Bench, rtt_samples};

    async fn loopback_endpoint() -> Endpoint {
        let loopback: SocketAddr = "127.0.0.1:0".parse().expect("a literal loopback address");
        Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind_addr(loopback)
            .expect("a loopback bind address")
            .bind()
            .await
            .expect("bind a loopback endpoint")
    }

    #[tokio::test]
    async fn rtt_samples_returns_one_timed_probe_per_round() {
        let server = loopback_endpoint().await;
        let _router = Router::builder(server.clone())
            .accept(BENCH_ALPN, Bench)
            .spawn();
        let socket = server
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .expect("an IPv4 socket");
        let client = loopback_endpoint().await;
        let connection = client
            .connect(
                EndpointAddr::from_parts(server.id(), [TransportAddr::Ip(socket)]),
                BENCH_ALPN,
            )
            .await
            .expect("connect over loopback");

        let samples = rtt_samples(&connection, 3, 20).await.expect("rtt samples");

        assert_eq!(samples.len(), 20);
        assert!(samples.iter().all(|sample| !sample.is_zero()));
        connection.close(0u32.into(), b"done");
    }
}
