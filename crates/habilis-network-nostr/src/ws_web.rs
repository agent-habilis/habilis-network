//! The browser's `WebSocket`, behind the same two halves as the native
//! backend: "send a text frame" and "receive the next text frame".

use anyhow::{Result, anyhow, bail};
use futures_util::{SinkExt as _, StreamExt as _, stream};
use url::Url;
use ws_stream_wasm::{WsMessage, WsMeta, WsStream};

/// The same ceiling as the native backend. A browser offers no payload limit
/// before delivery, so an oversized frame is refused after it: the socket is
/// dropped all the same.
const MAX_FRAME: usize = 128 * 1024;

pub(crate) struct Sender(stream::SplitSink<WsStream, WsMessage>);

pub(crate) struct Receiver {
    stream: stream::SplitStream<WsStream>,
    /// Kept for the socket's lifetime. The stream closes the socket when
    /// both halves drop; this handle has no `Drop` of its own.
    _meta: WsMeta,
}

impl Sender {
    pub(crate) async fn send(&mut self, text: String) -> Result<()> {
        self.0
            .send(WsMessage::Text(text))
            .await
            .map_err(|error| anyhow!("websocket send: {error}"))
    }

    pub(crate) async fn close(mut self) {
        let _ = self.0.close().await;
    }
}

impl Receiver {
    /// The next text frame. `None` when the socket is gone or sent a frame
    /// over the ceiling. Binary frames are skipped.
    pub(crate) async fn next(&mut self) -> Option<String> {
        loop {
            match self.stream.next().await? {
                WsMessage::Text(text) if text.len() > MAX_FRAME => return None,
                WsMessage::Text(text) => return Some(text),
                WsMessage::Binary(_) => {}
            }
        }
    }
}

pub(crate) async fn connect(url: &Url) -> Result<(Sender, Receiver)> {
    if !matches!(url.scheme(), "ws" | "wss") {
        bail!("relay URL scheme must be ws or wss, not {}", url.scheme());
    }
    let (meta, socket) = WsMeta::connect(url.as_str(), None)
        .await
        .map_err(|error| anyhow!("websocket connect: {error}"))?;
    let (sink, stream) = socket.split();
    Ok((
        Sender(sink),
        Receiver {
            stream,
            _meta: meta,
        },
    ))
}
