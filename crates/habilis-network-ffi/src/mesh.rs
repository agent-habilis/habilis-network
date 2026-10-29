//! The blocking handle a foreign caller drives from one thread. Owns the tokio
//! runtime the event loop runs on, and calls `block_on` once per method.
//!
//! The portable half — the join ritual, the `msg` driver, the roster and the
//! state — is [`habilis_network::membership`], shared verbatim with the browser peer in
//! `packages/habilis-network-wasm`. A tab and a terminal are on one mesh only because
//! there is one copy of that contract. Only what cannot cross to wasm32 stayed
//! here.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use habilis_network::embed::SilentSink;
use habilis_network::membership::{Membership, MembershipApp, Request};
use habilis_network::runtime::Node;
use tokio::sync::{mpsc, oneshot};

// Re-exported rather than re-imported at every use site, so the C shim next
// door names `crate::mesh::…` only.
pub(crate) use habilis_network::membership::{Inbound, JoinOptions, MAX_MSG};

/// A live mesh membership, driven synchronously from a foreign caller's thread.
/// Owns the tokio runtime the event loop runs on.
pub(crate) struct Mesh {
    runtime: tokio::runtime::Runtime,
    /// `None` after [`Mesh::close`] has taken it — `Node::leave` consumes it.
    node: Option<Node<MembershipApp>>,
    inbound: mpsc::Receiver<Inbound>,
    /// A message the caller's buffer was too small for, kept for the retry.
    pending: Option<Inbound>,
    habilis_network_id: String,
    nickname: String,
    name: String,
}

impl Mesh {
    /// Resolve `opts`, stand up the mesh, and spawn the event loop.
    ///
    /// # Errors
    /// An unparseable id/topic/nickname, conflicting selectors, or a failure
    /// standing up the endpoint and gossip overlay.
    pub(crate) fn open(options: &JoinOptions) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("building the mesh runtime")?;

        // `SilentSink`: a C caller has no callback to hand a surfacing to, so it
        // learns about joins, leaves and state changes by polling the roster and
        // the document. The browser peer passes `json_sink()`'s here instead,
        // which is the one thing that differs between the two.
        let Membership { node, inbound, .. } = runtime.block_on(
            // join takes the sink as a shared handle, and the event loop keeps it
            habilis_network::membership::join(options, Arc::new(SilentSink::default())),
        )?;

        let habilis_network_id = node.mesh_id().as_str().to_owned();
        let nickname = node.nickname().to_string();
        let name = node.name().as_str().to_owned();
        Ok(Self {
            habilis_network_id,
            nickname,
            name,
            runtime,
            node: Some(node),
            inbound,
            pending: None,
        })
    }

    /// The id of the mesh.
    #[must_use]
    pub(crate) fn habilis_network_id(&self) -> &str {
        &self.habilis_network_id
    }

    /// The nickname of this member.
    #[must_use]
    pub(crate) fn nickname(&self) -> &str {
        &self.nickname
    }

    /// The name of the mesh.
    #[must_use]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Send one message — broadcast when `to` is `None`, directed at that peer
    /// otherwise.
    ///
    /// # Errors
    /// The message does not fit one frame, the addressee is not a nickname, the
    /// event loop has stopped, or the engine refused the frame.
    pub(crate) fn send(&self, to: Option<&str>, text: &str) -> Result<()> {
        let to = habilis_network::membership::parse_to(to)?;
        let body = habilis_network::membership::msg_body(text)?;
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
    pub(crate) fn recv(&mut self, timeout: Duration) -> Result<Option<Inbound>> {
        if let Some(pending) = self.pending.take() {
            return Ok(Some(pending));
        }
        let inbound = &mut self.inbound;
        self.runtime.block_on(async move {
            match tokio::time::timeout(timeout, inbound.recv()).await {
                Err(_elapsed) => Ok(None),
                Ok(Some(message)) => Ok(Some(message)),
                Ok(None) => Err(anyhow::anyhow!("mesh event loop has stopped")),
            }
        })
    }

    /// Put back a message the caller could not take, so the next
    /// [`recv`](Self::recv) returns it first.
    pub(crate) fn keep(&mut self, message: Inbound) {
        self.pending = Some(message);
    }

    /// Apply an RFC 7386 merge document to the shared `state` channel and gossip
    /// the resulting automerge change.
    ///
    /// # Errors
    /// `json` is not a JSON object, the merge is unrepresentable, the resulting
    /// frame is oversize, or the event loop has stopped.
    pub(crate) fn state_merge(&self, json: &str) -> Result<()> {
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
    pub(crate) fn state_json(&self) -> Result<String> {
        let (reply, answer) = oneshot::channel();
        self.dispatch(Request::StateJson { reply })?;
        self.await_reply(answer)
    }

    /// The live peer roster as JSON (the `agent-gossip peers` shape).
    ///
    /// # Errors
    /// The event loop has stopped.
    pub(crate) fn peers_json(&self) -> Result<String> {
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
    pub(crate) fn peer_count(&self) -> Result<usize> {
        let (reply, answer) = oneshot::channel();
        self.dispatch(Request::PeerCount { reply })?;
        self.await_reply(answer)
    }

    /// Broadcast `Left` and wind the loop down, after the departure grace
    /// [`habilis_network::membership::depart`] holds.
    ///
    /// # Errors
    /// The event loop returned an error or panicked.
    pub(crate) fn close(&mut self) -> Result<()> {
        let Some(node) = self.node.take() else {
            return Ok(());
        };
        self.runtime
            .block_on(habilis_network::membership::depart(node))
            .map_err(anyhow::Error::from)
    }

    fn dispatch(&self, request: Request) -> Result<()> {
        let Some(node) = self.node.as_ref() else {
            anyhow::bail!("this mesh handle is closed");
        };
        self.runtime
            .block_on(node.send(request))
            .map_err(anyhow::Error::from)
    }

    fn await_reply<T>(&self, answer: oneshot::Receiver<T>) -> Result<T> {
        self.runtime
            .block_on(answer)
            .map_err(|_| anyhow::anyhow!("mesh event loop dropped the request"))
    }
}
