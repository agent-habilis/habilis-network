//! A fofoca mesh peer for the browser: [`fofoca::membership`] behind one
//! wasm-bindgen class.
//!
//! Everything crosses the JS boundary as a JSON string — options in, messages,
//! events, roster and state out — because a `js_sys::Function` is neither
//! `Send` nor `Sync` and could never be held by the engine's sink; the JS
//! side polls [`MeshPeer::next_msg`] / [`MeshPeer::next_event`] instead
//! (the same shape `packages/fofoca-api` was designed around). One in-flight
//! call per queue: the receivers are behind async mutexes, so a second
//! concurrent `nextMsg()` waits rather than panics.

mod stream;

use std::cell::RefCell;

use fofoca::membership::{Inbound, MAX_MSG, MembershipApp, Opts, Request, json_sink};
use fofoca::runtime::Node;
use tokio::sync::{Mutex, mpsc, oneshot};
use wasm_bindgen::prelude::*;

/// One mesh membership, held by a tab.
#[expect(
    missing_debug_implementations,
    reason = "Node's Debug is manual and says nothing a caller wants; the identity a reader would look for is in `id`/`nick` already"
)]
#[wasm_bindgen]
pub struct MeshPeer {
    /// `Some` until [`MeshPeer::close`]; `Drop` aborts the loop either way.
    node: RefCell<Option<Node<MembershipApp>>>,
    sender: mpsc::Sender<Request>,
    inbound: Mutex<mpsc::Receiver<Inbound>>,
    events: Mutex<mpsc::UnboundedReceiver<String>>,
    id: String,
    nick: String,
    name: String,
}

#[wasm_bindgen]
impl MeshPeer {
    /// Join (or create) the mesh `opts_json` selects — a JSON encoding of
    /// `fofoca::membership::Opts`, the same object `fofoca-ffi` takes. Resolves to
    /// the live peer once the mesh is set up.
    ///
    /// # Errors
    /// The options fail to parse or select an unreachable mesh (a loopback
    /// mesh, say — a browser cannot reach one), or setup itself fails.
    pub async fn open(opts_json: String) -> Result<MeshPeer, JsValue> {
        console_error_panic_hook::set_once();
        let opts: Opts = serde_json::from_str(&opts_json)
            .map_err(|error| to_js_error(&format!("invalid options: {error}")))?;
        let (sink, events) = json_sink();
        let membership = fofoca::membership::join(&opts, sink)
            .await
            .map_err(|error| to_js_error(&format!("{error:#}")))?;
        let node = membership.node;
        Ok(MeshPeer {
            id: node.mesh_id().to_string(),
            nick: node.nickname().to_string(),
            name: node.name().to_string(),
            sender: node.sender(),
            inbound: Mutex::new(membership.inbound),
            events: Mutex::new(events),
            node: RefCell::new(Some(node)),
        })
    }

    /// The mesh id — what another peer joins with.
    #[must_use]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// The nickname the engine settled on, not necessarily the one asked for.
    #[must_use]
    pub fn nick(&self) -> String {
        self.nick.clone()
    }

    /// The mesh name.
    #[must_use]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// The longest message in bytes that always fits one frame. Most text
    /// fits well past it; a send that does not fit is refused, not split.
    #[wasm_bindgen(js_name = maxMsg)]
    #[must_use]
    pub fn max_msg(&self) -> usize {
        MAX_MSG
    }

    /// Send one message — broadcast with `to` absent, directed at that
    /// nickname otherwise.
    ///
    /// # Errors
    /// The message does not fit one frame, the addressee is not a valid
    /// nickname, the event loop has stopped, or the engine refused the frame
    /// (a directed frame held for a direct path, say).
    pub async fn send(&self, to: Option<String>, text: String) -> Result<(), JsValue> {
        let to =
            fofoca::membership::parse_to(to.as_deref()).map_err(|error| to_js_error(&error))?;
        let body = fofoca::membership::msg_body(&text).map_err(|error| to_js_error(&error))?;
        let (reply, answer) = oneshot::channel();
        self.request(Request::Send { to, body, reply }).await?;
        answer
            .await
            .map_err(|_| to_js_error("mesh event loop has stopped"))?
            .map_err(|error| to_js_error(&error))
    }

    /// The next inbound message, as JSON: `{"nick","directed","text"}`.
    /// `null` once the mesh is gone and the queue is drained.
    #[wasm_bindgen(js_name = nextMsg)]
    pub async fn next_msg(&self) -> Option<String> {
        let msg = self.inbound.lock().await.recv().await?;
        Some(msg_json(&msg))
    }

    /// The next surfaced node event (`fofoca::membership::MembershipEvent`),
    /// as JSON.
    /// `null` once the mesh is gone and the queue is drained.
    #[wasm_bindgen(js_name = nextEvent)]
    pub async fn next_event(&self) -> Option<String> {
        self.events.lock().await.recv().await
    }

    /// The roster snapshot, as JSON — each peer with `reach` and `transport`
    /// (`"relay-only"` names a peer payload cannot reach yet).
    ///
    /// # Errors
    /// The event loop has stopped.
    #[wasm_bindgen(js_name = peersJson)]
    pub async fn peers_json(&self) -> Result<String, JsValue> {
        let (reply, answer) = oneshot::channel();
        self.request(Request::Peers { reply }).await?;
        answer
            .await
            .map_err(|_| to_js_error("mesh event loop has stopped"))
    }

    /// How many peers besides this one are in the roster.
    ///
    /// # Errors
    /// The event loop has stopped.
    #[wasm_bindgen(js_name = peerCount)]
    pub async fn peer_count(&self) -> Result<usize, JsValue> {
        let (reply, answer) = oneshot::channel();
        self.request(Request::PeerCount { reply }).await?;
        answer
            .await
            .map_err(|_| to_js_error("mesh event loop has stopped"))
    }

    /// The shared state document, as JSON.
    ///
    /// # Errors
    /// The event loop has stopped.
    #[wasm_bindgen(js_name = stateJson)]
    pub async fn state_json(&self) -> Result<String, JsValue> {
        let (reply, answer) = oneshot::channel();
        self.request(Request::StateJson { reply }).await?;
        answer
            .await
            .map_err(|_| to_js_error("mesh event loop has stopped"))
    }

    /// Apply an RFC 7386 merge document to the shared state and gossip the
    /// change; resolves with the resulting state JSON.
    ///
    /// # Errors
    /// `patch_json` is not a JSON object, the merge is unrepresentable, or
    /// the event loop has stopped.
    #[wasm_bindgen(js_name = stateMerge)]
    pub async fn state_merge(&self, patch_json: String) -> Result<String, JsValue> {
        let merge: serde_json::Value = serde_json::from_str(&patch_json)
            .map_err(|error| to_js_error(&format!("invalid merge document: {error}")))?;
        let (reply, answer) = oneshot::channel();
        self.request(Request::StateMerge { merge, reply }).await?;
        answer
            .await
            .map_err(|_| to_js_error("mesh event loop has stopped"))?
            .map_err(|error| to_js_error(&error))?;
        self.state_json().await
    }

    /// Broadcast `Left` and wind the loop down. The peer is unusable after.
    ///
    /// # Errors
    /// The event loop already stopped, or shutdown itself failed.
    pub async fn close(&self) -> Result<(), JsValue> {
        // The borrow is released before the await: `take()` moves the node
        // out synchronously.
        let node = self.node.borrow_mut().take();
        let Some(node) = node else {
            return Ok(());
        };
        fofoca::membership::depart(node)
            .await
            .map_err(|error| to_js_error(&format!("{error:#}")))
    }

    async fn request(&self, request: Request) -> Result<(), JsValue> {
        self.sender
            .send(request)
            .await
            .map_err(|_| to_js_error("mesh event loop has stopped"))
    }
}

fn msg_json(msg: &Inbound) -> String {
    serde_json::json!({
        "nick": msg.nick,
        "directed": msg.directed,
        "text": msg.text,
    })
    .to_string()
}

pub(crate) fn to_js_error(message: &(impl std::fmt::Display + ?Sized)) -> JsValue {
    JsValue::from_str(&message.to_string())
}

/// Route the engine's `tracing` lines — the mesh census, `relay-only path
/// refused`, per-peer path readings — to the browser console. `filter` is an
/// `EnvFilter` string (`fofoca=info,fofoca::lifecycle=debug`); an invalid
/// one falls back to `info`. One-shot: a second call is a no-op, so a page
/// can call it unconditionally.
#[wasm_bindgen(js_name = initTracing)]
pub fn init_tracing(filter: &str) {
    use tracing_subscriber::fmt::format::FmtSpan;
    let env_filter = tracing_subscriber::EnvFilter::try_new(filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    // The default fmt timer reads `std::time::SystemTime`, which panics on
    // wasm32-unknown; `without_time` sidesteps it.
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_span_events(FmtSpan::NONE)
        .with_writer(console_writer::MakeConsoleWriter)
        .with_env_filter(env_filter)
        .try_init();
}

/// A `MakeWriter` that hands each formatted line to `console.log`.
mod console_writer {
    use std::io;

    pub(crate) struct MakeConsoleWriter;

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeConsoleWriter {
        type Writer = ConsoleWriter;

        fn make_writer(&'a self) -> Self::Writer {
            ConsoleWriter(Vec::new())
        }
    }

    /// Buffers one event's bytes; the flush on drop is what reaches the
    /// console, because `fmt` writes an event in several small writes.
    pub(crate) struct ConsoleWriter(Vec<u8>);

    impl io::Write for ConsoleWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.0.is_empty() {
                return Ok(());
            }
            let text = String::from_utf8_lossy(&self.0);
            web_sys::console::log_1(&text.trim_end().into());
            self.0.clear();
            Ok(())
        }
    }

    impl Drop for ConsoleWriter {
        fn drop(&mut self) {
            let _ = io::Write::flush(self);
        }
    }
}
