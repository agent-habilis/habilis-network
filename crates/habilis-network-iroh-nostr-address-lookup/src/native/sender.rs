//! One `WebSocket` to one relay, reduced to "send a text frame" and "receive the
//! next text frame". Native only for now; the browser backend lands with the
//! wasm phase.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use futures_util::{SinkExt as _, StreamExt as _, stream};
use n0_future::time;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_websockets::{ClientBuilder, Limits, Message, WebSocketStream};
use url::{Host, Url};

use rustls::crypto::ring;
/// A plain or TLS stream behind one type, so the socket type does not depend on
/// the URL scheme.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type Socket = WebSocketStream<Box<dyn Io>>;

/// A signalling event is a few kilobytes, and the engine caps a `WebRTC` envelope at
/// 64 kilobytes. A larger frame is a broken or hostile relay: the read fails and the
/// socket is dropped, rather than the frame buffered.
const MAX_FRAME: usize = 128 * 1024;

/// A write that takes longer than this means the relay has stopped reading. The
/// task that awaits it takes no command meanwhile, so it must give up and let
/// the caller reconnect.
const WRITE_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_secs(1)
} else {
    Duration::from_secs(10)
};

pub(crate) struct Sender(stream::SplitSink<Socket, Message>);
pub(crate) struct Receiver(stream::SplitStream<Socket>);

impl Sender {
    pub(crate) async fn send(&mut self, text: String) -> Result<()> {
        let write = self.0.send(Message::text(text));
        time::timeout(WRITE_TIMEOUT, write)
            .await
            .context("websocket send timed out")?
            .context("websocket send")
    }

    pub(crate) async fn close(mut self) {
        let _ = self.0.close().await;
    }
}

impl Receiver {
    /// The next text frame. `None` when the socket is gone. Pings, pongs and
    /// binary frames are skipped; tokio-websockets answers pings itself.
    pub(crate) async fn next(&mut self) -> Option<String> {
        loop {
            let message = self.0.next().await?.ok()?;
            if message.is_close() {
                return None;
            }
            if let Some(text) = message.as_text() {
                return Some(text.to_owned());
            }
        }
    }
}

pub(crate) async fn connect(url: &Url) -> Result<(Sender, Receiver)> {
    // `host_str` keeps the brackets of an IPv6 literal, which no socket address
    // and no TLS name takes.
    let parsed_host = url.host().context("relay URL has no host")?;
    let host = match parsed_host {
        Host::Domain(name) => name.to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };
    let port = url
        .port_or_known_default()
        .context("relay URL has no port")?;
    let tcp = connect_tcp(&host, port).await?;
    let io: Box<dyn Io> = match url.scheme() {
        "ws" => Box::new(tcp),
        "wss" => {
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .context("relay host is not a valid TLS name")?;
            let tls = tokio_rustls::TlsConnector::from(tls_config())
                .connect(name, tcp)
                .await
                .context("TLS handshake")?;
            Box::new(tls)
        }
        other => bail!("relay URL scheme must be ws or wss, not {other}"),
    };
    let builder = ClientBuilder::new()
        .uri(url.as_str())
        .context("relay URL is not a valid URI")?;
    let limits = Limits::default().max_payload_len(Some(MAX_FRAME));
    let (socket, _response) = builder
        .limits(limits)
        .connect_on(io)
        .await
        .context("websocket handshake")?;
    let (sink, stream) = socket.split();
    Ok((Sender(sink), Receiver(stream)))
}

/// A TCP connection to the relay, with Nagle's algorithm off: a frame is written in parts, and
/// Nagle holds the second part until the peer acks the first.
async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connect to {host}:{port}"))?;
    tcp.set_nodelay(true).context("set TCP_NODELAY")?;
    Ok(tcp)
}

// One config for the process, shared by every dial.
fn tls_config() -> Arc<rustls::ClientConfig> {
    // Built once for the whole process, then shared by each dial.
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    // Each caller gets a handle on the one config.
    Arc::clone(CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        // The builder takes the provider as a shared handle.
        let provider = Arc::new(ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default TLS versions");
        let config = builder.with_root_certificates(roots).with_no_client_auth();
        // The connectors share the config, so it lives behind a handle.
        Arc::new(config)
    }))
}

#[cfg(all(test, feature = "test-relay"))]
mod tests {
    use std::future;
    use std::time::Duration;

    use tokio::net::TcpListener;
    use tokio::time;
    use tokio_websockets::ServerBuilder;
    use url::Url;

    /// A server that finishes the handshake, then never reads again.
    async fn accept_and_stall(listener: TcpListener) {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok((_request, _socket)) = ServerBuilder::new().accept(stream).await else {
            return;
        };
        let () = future::pending().await;
    }

    /// A relay that stops reading leaves the write pending for good, and the
    /// task that awaits it cannot take a `Reconnect`. The write gives up.
    #[tokio::test]
    async fn a_write_to_a_relay_that_stops_reading_gives_up() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("a local address");
        let stalled = tokio::spawn(accept_and_stall(listener));
        let url: Url = format!("ws://{address}").parse().expect("a valid URL");
        let (mut sender, _receiver) = super::connect(&url).await.expect("the handshake works");

        let fill = async {
            loop {
                if sender.send("x".repeat(60_000)).await.is_err() {
                    return;
                }
            }
        };
        let outcome = time::timeout(Duration::from_secs(15), fill).await;
        stalled.abort();
        assert!(
            outcome.is_ok(),
            "the write waited 15 s on a relay that reads nothing"
        );
    }

    /// A `WebSocket` frame is written in parts. With Nagle on, the second part waits for the ACK of
    /// the first, which the peer delays by about 40 ms on Linux: one connection then sends about
    /// 25 small frames a second, and the data lane asks for 200.
    #[tokio::test]
    async fn the_relay_connection_sends_small_writes_at_once() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("a local address");
        let accepted = tokio::spawn(async move { listener.accept().await });
        let tcp = super::connect_tcp("127.0.0.1", address.port())
            .await
            .expect("the dial works");
        assert!(
            tcp.nodelay().expect("the option reads"),
            "TCP_NODELAY is on"
        );
        accepted.abort();
    }

    /// `host_str` keeps the brackets of an `IPv6` literal, which no socket
    /// address takes: the dial uses the address inside them.
    #[tokio::test]
    async fn a_bracketed_ipv6_relay_dials() {
        let Ok(listener) = TcpListener::bind("[::1]:0").await else {
            return;
        };
        let address = listener.local_addr().expect("a local address");
        let stalled = tokio::spawn(accept_and_stall(listener));
        let url: Url = format!("ws://{address}").parse().expect("a valid URL");
        let dialed = super::connect(&url).await;
        stalled.abort();
        assert!(
            dialed.is_ok(),
            "an IPv6 literal URL dials: {:?}",
            dialed.err()
        );
    }
}
