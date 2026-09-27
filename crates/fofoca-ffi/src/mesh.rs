//! The blocking handle a foreign caller drives from one thread. Owns the tokio
//! runtime the event loop runs on, and calls `block_on` once per method.
//!
//! The portable half — the join ritual, the `msg` driver, the roster and the
//! state — is [`fofoca::membership`], shared verbatim with the browser peer in
//! `packages/fofoca-wasm`. A tab and a terminal are on one mesh only because
//! there is one copy of that contract. Only what cannot cross to wasm32 stayed
//! here.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use fofoca::embed::SilentSink;
use fofoca::membership::{Membership, MembershipApp, Request};
use fofoca::runtime::Node;
use tokio::sync::{mpsc, oneshot};

// Re-exported rather than re-imported at every use site, so the C shim next
// door names `crate::mesh::…` only.
pub use fofoca::membership::{Inbound, MAX_MSG, Opts};

/// A live mesh membership, driven synchronously from a foreign caller's thread.
/// Owns the tokio runtime the event loop runs on.
#[expect(
    missing_debug_implementations,
    reason = "a tokio Runtime has no Debug impl; the fields a reader would want (id, nickname) are exposed as accessors"
)]
pub struct Mesh {
    runtime: tokio::runtime::Runtime,
    /// `None` after [`Mesh::close`] has taken it — `Node::leave` consumes it.
    node: Option<Node<MembershipApp>>,
    inbound: mpsc::Receiver<Inbound>,
    /// A message the caller's buffer was too small for, kept for the retry.
    pending: Option<Inbound>,
    fofoca_id: String,
    nickname: String,
    name: String,
}

impl Mesh {
    /// Resolve `opts`, stand up the mesh, and spawn the event loop.
    ///
    /// # Errors
    /// An unparseable id/topic/nickname, conflicting selectors, or a failure
    /// standing up the endpoint and gossip overlay.
    pub fn open(opts: &Opts) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("building the mesh runtime")?;

        // `SilentSink`: a C caller has no callback to hand a surfacing to, so it
        // learns about joins, leaves and state changes by polling the roster and
        // the document. The browser peer passes `json_sink()`'s here instead,
        // which is the one thing that differs between the two.
        let Membership { node, inbound } =
            runtime.block_on(fofoca::membership::join(opts, Arc::new(SilentSink)))?;

        Ok(Self {
            fofoca_id: node.mesh_id().as_str().to_owned(),
            nickname: node.nickname().to_string(),
            name: node.name().as_str().to_owned(),
            runtime,
            node: Some(node),
            inbound,
            pending: None,
        })
    }

    #[must_use]
    pub fn fofoca_id(&self) -> &str {
        &self.fofoca_id
    }

    #[must_use]
    pub fn nickname(&self) -> &str {
        &self.nickname
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Send one message — broadcast when `to` is `None`, directed at that peer
    /// otherwise.
    ///
    /// # Errors
    /// The message does not fit one frame, the addressee is not a nickname, the
    /// event loop has stopped, or the engine refused the frame.
    pub fn send(&self, to: Option<&str>, text: &str) -> Result<()> {
        let to = fofoca::membership::parse_to(to)?;
        let body = fofoca::membership::msg_body(text)?;
        let (reply, answer) = oneshot::channel();
        self.dispatch(Request::Send { to, body, reply })?;
        self.await_reply(answer)?
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    /// Take the next inbound message, waiting at most `timeout`. `Ok(None)` on
    /// timeout.
    ///
    /// # Errors
    /// The event loop has stopped and the queue is drained.
    pub fn recv(&mut self, timeout: Duration) -> Result<Option<Inbound>> {
        if let Some(pending) = self.pending.take() {
            return Ok(Some(pending));
        }
        let inbound = &mut self.inbound;
        self.runtime.block_on(async move {
            match tokio::time::timeout(timeout, inbound.recv()).await {
                Err(_elapsed) => Ok(None),
                Ok(Some(msg)) => Ok(Some(msg)),
                Ok(None) => Err(anyhow::anyhow!("mesh event loop has stopped")),
            }
        })
    }

    /// Put back a message the caller could not take, so the next
    /// [`recv`](Self::recv) returns it first.
    pub fn keep(&mut self, msg: Inbound) {
        self.pending = Some(msg);
    }

    /// Apply an RFC 7386 merge document to the shared `state` channel and gossip
    /// the resulting automerge change.
    ///
    /// # Errors
    /// `json` is not a JSON object, the merge is unrepresentable, the resulting
    /// frame is oversize, or the event loop has stopped.
    pub fn state_merge(&self, json: &str) -> Result<()> {
        let merge: serde_json::Value =
            serde_json::from_str(json).context("parsing the merge document")?;
        let (reply, answer) = oneshot::channel();
        self.dispatch(Request::StateMerge { merge, reply })?;
        self.await_reply(answer)?
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    /// The merged shared `state` document as JSON.
    ///
    /// # Errors
    /// The event loop has stopped.
    pub fn state_json(&self) -> Result<String> {
        let (reply, answer) = oneshot::channel();
        self.dispatch(Request::StateJson { reply })?;
        self.await_reply(answer)
    }

    /// The live peer roster as JSON (the `agent-gossip peers` shape).
    ///
    /// # Errors
    /// The event loop has stopped.
    pub fn peers_json(&self) -> Result<String> {
        let (reply, answer) = oneshot::channel();
        self.dispatch(Request::Peers { reply })?;
        self.await_reply(answer)
    }

    /// How many peers other than us are in the mesh right now — the cheap
    /// question a caller waiting for company actually has, without a JSON
    /// round-trip through [`Mesh::peers_json`].
    ///
    /// # Errors
    /// The event loop has stopped.
    pub fn peer_count(&self) -> Result<usize> {
        let (reply, answer) = oneshot::channel();
        self.dispatch(Request::PeerCount { reply })?;
        self.await_reply(answer)
    }

    /// Broadcast `Left` and wind the loop down, after the departure grace
    /// [`fofoca::membership::depart`] holds.
    ///
    /// # Errors
    /// The event loop returned an error or panicked.
    pub fn close(&mut self) -> Result<()> {
        let Some(node) = self.node.take() else {
            return Ok(());
        };
        self.runtime.block_on(fofoca::membership::depart(node))
    }

    fn dispatch(&self, req: Request) -> Result<()> {
        let Some(node) = self.node.as_ref() else {
            anyhow::bail!("this mesh handle is closed");
        };
        self.runtime.block_on(node.send(req))
    }

    fn await_reply<T>(&self, answer: oneshot::Receiver<T>) -> Result<T> {
        self.runtime
            .block_on(answer)
            .map_err(|_| anyhow::anyhow!("mesh event loop dropped the request"))
    }
}
