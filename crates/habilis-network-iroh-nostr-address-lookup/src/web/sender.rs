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

pub(crate) struct Sender {
    sink: stream::SplitSink<WsStream, WsMessage>,
    // Reads the browser's count of bytes queued and not yet sent: the socket itself is split.
    buffered: Box<dyn Fn() -> u32>,
}

pub(crate) struct Receiver {
    stream: stream::SplitStream<WsStream>,
    /// Kept for the socket's lifetime. The stream closes the socket when
    /// both halves drop; this handle has no `Drop` of its own.
    _meta: WsMeta,
}

impl Sender {
    pub(crate) async fn send(&mut self, text: String) -> Result<()> {
        self.sink
            .send(WsMessage::Text(text))
            .await
            .map_err(|error| anyhow!("websocket send: {error}"))
    }

    /// The bytes the browser has queued on this socket and not yet sent. Data frames are
    /// dropped past a bound ([`crate::data_queue::over_buffer_bound`]), since the browser's own
    /// queue has none.
    pub(crate) fn buffered(&self) -> usize {
        usize::try_from((self.buffered)()).unwrap_or(usize::MAX)
    }

    pub(crate) async fn close(mut self) {
        let _ = self.sink.close().await;
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
    let handle = socket.wrapped().clone();
    let (sink, stream) = socket.split();
    Ok((
        Sender {
            sink,
            buffered: Box::new(move || handle.buffered_amount()),
        },
        Receiver {
            stream,
            _meta: meta,
        },
    ))
}
