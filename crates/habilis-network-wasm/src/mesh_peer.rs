use std::cell::RefCell;

use habilis_network::membership::{Inbound, MAX_MSG, MembershipApp, JoinOptions, Request, json_sink};
use habilis_network::runtime::Node;
use tokio::sync::{Mutex, mpsc, oneshot};
use wasm_bindgen::prelude::{JsValue, wasm_bindgen};
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
    /// `habilis_network::membership::JoinOptions`, the same object `habilis-network-ffi` takes. Resolves to
    /// the live peer once the mesh is set up.
    ///
    /// # Errors
    /// The options fail to parse or select an unreachable mesh (a loopback
    /// mesh, say — a browser cannot reach one), or setup itself fails.
    pub async fn open(opts_json: String) -> Result<MeshPeer, JsValue> {
        console_error_panic_hook::set_once();
        let opts: JoinOptions = serde_json::from_str(&opts_json)
            .map_err(|error| to_js_error(&format!("invalid options: {error}")))?;
        let (sink, events) = json_sink();
        let membership = habilis_network::membership::join(&opts, sink)
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
        let to = habilis_network::membership::parse_to(to.as_deref())
            .map_err(|error| to_js_error(&error))?;
        let body =
            habilis_network::membership::msg_body(&text).map_err(|error| to_js_error(&error))?;
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

    /// The next surfaced node event (`habilis_network::membership::MembershipEvent`),
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
        habilis_network::membership::depart(node)
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
