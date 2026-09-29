//! One `WebSocket` to one relay, reduced to "send a text frame" and "receive the
//! next text frame". Native only for now; the browser backend lands with the
//! wasm phase.

use std::sync::{Arc, OnceLock};

use anyhow::{Context as _, Result, bail};
use futures_util::{SinkExt as _, StreamExt as _, stream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_websockets::{ClientBuilder, Limits, Message, WebSocketStream};
use url::Url;

/// A plain or TLS stream behind one type, so the socket type does not depend on
/// the URL scheme.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type Socket = WebSocketStream<Box<dyn Io>>;

/// A signalling event is a few kilobytes, and the engine caps a `WebRTC` envelope at
/// 64 kilobytes. A larger frame is a broken or hostile relay: the read fails and the
/// socket is dropped, rather than the frame buffered.
const MAX_FRAME: usize = 128 * 1024;

pub(crate) struct Sender(stream::SplitSink<Socket, Message>);
pub(crate) struct Receiver(stream::SplitStream<Socket>);

impl Sender {
    pub(crate) async fn send(&mut self, text: String) -> Result<()> {
        self.0
            .send(Message::text(text))
            .await
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
    let host = url.host_str().context("relay URL has no host")?.to_owned();
    let port = url
        .port_or_known_default()
        .context("relay URL has no port")?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("connect to {host}:{port}"))?;
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
    let (socket, _response) = ClientBuilder::new()
        .uri(url.as_str())
        .context("relay URL is not a valid URI")?
        .limits(Limits::default().max_payload_len(Some(MAX_FRAME)))
        .connect_on(io)
        .await
        .context("websocket handshake")?;
    let (sink, stream) = socket.split();
    Ok((Sender(sink), Receiver(stream)))
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}
