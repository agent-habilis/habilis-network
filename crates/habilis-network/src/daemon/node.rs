use std::fmt;
use std::time::Duration;

// `n0_future::task` is `tokio::task` verbatim off wasm32, and a
// `wasm-bindgen-futures` shim in a browser — where there is no runtime to
// `block_on` and `tokio::spawn` would panic. Its `JoinHandle` carries `abort()`
// on both, so `Drop` below needs no target-specific handling.
use n0_future::task::JoinHandle;
use tokio::sync::{broadcast, mpsc};

use crate::daemon::app::NodeDriver;
use crate::daemon::config::{DriverMode, EventLoopConfig};
use crate::protocol::mesh::MeshName;
use crate::protocol::{MeshId, Message, Nickname};
use crate::util::tuning::{NODE_LEAVE_SECS, SESSION_REQUEST_CAP};

/// A live in-process membership over a background event loop, generic over the
/// application driver `A`. Drop it (or call [`Node::leave`]) to wind the loop
/// down.
pub struct Node<A: NodeDriver> {
    mesh_id: MeshId,
    name: MeshName,
    nickname: Nickname,
    req_tx: mpsc::Sender<A::Session>,
    quit_tx: mpsc::Sender<()>,
    task: Option<JoinHandle<anyhow::Result<()>>>,
    /// The ports this node's endpoint is bound on, for a test that names which
    /// nodes to cut from which. Read once at spawn: the ports do not change.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    bound_ports: Vec<u16>,
    /// The id and bound ports of this node's multihop underlay endpoint, `None`
    /// when multihop is off. For a test that blocks IP on the underlay.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    underlay: Option<(iroh::EndpointId, Vec<u16>)>,
    /// What a test needs to make this node die as a process does: its sessions
    /// and its endpoint.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    crash_handles: (
        habilis_network_iroh_webrtc_transport::WebRtcHandle,
        iroh::Endpoint,
    ),
}

// `A::Session` need not be `Debug`, and the channels/handle aren't useful in a
// log line — surface the identity fields a reader cares about.
impl<A: NodeDriver> fmt::Debug for Node<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Node")
            .field("mesh_id", &self.mesh_id)
            .field("name", &self.name)
            .field("nickname", &self.nickname)
            .finish_non_exhaustive()
    }
}

impl<A: NodeDriver + 'static> Node<A> {
    /// Wire the in-process driver channels into `cfg`, spawn the event loop with
    /// `app`, and return the handle. `handle_signals` registers the process-wide
    /// ctrl-c / SIGTERM listeners (pass `true` for a foreground command that owns
    /// the process, `false` for a session nested inside one that does — see
    /// [`DriverMode::InProcess`]).
    ///
    /// `push` is the caller's inbound fan-out, or `None` for a consumer that
    /// drains frames some other way (a poll-only session, or an app that
    /// consumes every frame inside the loop). `None` is not merely a saved
    /// allocation: with a sender wired, the receive path calls
    /// `broadcast::Sender::receiver_count()` — which takes a mutex — on **every**
    /// inbound frame, only to discover nobody is listening.
    #[must_use]
    pub fn spawn(
        mut cfg: EventLoopConfig,
        app: A,
        push: Option<broadcast::Sender<Message>>,
        handle_signals: bool,
    ) -> Self {
        let (req_tx, req_rx) = mpsc::channel::<A::Session>(SESSION_REQUEST_CAP);
        let (quit_tx, quit_rx) = mpsc::channel::<()>(1);
        cfg.driver = DriverMode::InProcess {
            msg_tx: push,
            quit_rx,
            handle_signals,
        };
        let mesh_id = cfg.mesh.clone();
        let name = cfg.name.clone();
        let nickname = cfg.author.clone();
        #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
        let bound_ports = cfg
            .endpoint
            .bound_sockets()
            .iter()
            .map(std::net::SocketAddr::port)
            .collect();
        #[cfg(all(
            feature = "iroh-test-utils",
            feature = "host",
            not(target_arch = "wasm32")
        ))]
        let underlay = cfg
            .multihop
            .as_ref()
            .map(|handle| (handle.underlay_id(), handle.underlay_ports()));
        #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
        let crash_handles = (cfg.webrtc_handle(), cfg.endpoint.clone());
        let task = n0_future::task::spawn(crate::daemon::run(cfg, app, Some(req_rx), None));
        Self {
            mesh_id,
            name,
            nickname,
            req_tx,
            quit_tx,
            task: Some(task),
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            bound_ports,
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            underlay,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            crash_handles,
        }
    }

    /// Tests only: make this node die as a process does. The loop is aborted
    /// with no `Left`, the `WebRTC` sessions are aborted with no close, so their
    /// far ends find out when ICE consent times out (about 22 s), and the
    /// endpoint is closed so nothing answers a later dial. Dropping the node
    /// does only the first, and leaves its sessions answering ICE consent.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub async fn crash(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let (webrtc, endpoint) = &self.crash_handles;
        let _ = webrtc.abort_sessions();
        endpoint.close().await;
    }

    /// Tests only: the ports this node's endpoint is bound on. A test that cuts
    /// one group of nodes from another gives each node the other group's ports
    /// (`Request::BlockIpTo`).
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    #[must_use]
    pub fn bound_ports(&self) -> &[u16] {
        &self.bound_ports
    }

    /// Tests only: the id of this node's member endpoint. A test that reads
    /// the log for one pair of nodes matches its lines by these ids.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    #[must_use]
    pub fn endpoint_id(&self) -> iroh::EndpointId {
        self.crash_handles.1.id()
    }

    /// Tests only: the id of this node's multihop underlay endpoint, or `None`
    /// when multihop is off. The underlay has a key of its own, so a test that
    /// matches it to a member goes through `MultihopHandle::app_id_of`.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    #[must_use]
    pub fn underlay_id(&self) -> Option<iroh::EndpointId> {
        self.underlay.as_ref().map(|(id, _)| *id)
    }

    /// Tests only: the ports this node's multihop underlay endpoint is bound on,
    /// empty when multihop is off. Like [`bound_ports`](Self::bound_ports), but
    /// for the underlay: blocking IP on it is what forces cells onto a hop.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    #[must_use]
    pub fn underlay_ports(&self) -> &[u16] {
        self.underlay
            .as_ref()
            .map_or(&[], |(_, ports)| ports.as_slice())
    }

    /// The resolved mesh id.
    #[must_use]
    pub fn mesh_id(&self) -> &MeshId {
        &self.mesh_id
    }

    /// The mesh's human-readable name (decoded from the id).
    #[must_use]
    pub fn name(&self) -> &MeshName {
        &self.name
    }

    /// Our nickname in this mesh.
    #[must_use]
    pub fn nickname(&self) -> &Nickname {
        &self.nickname
    }

    /// Push one typed session request to the driver's
    /// [`handle_session`](NodeDriver::handle_session).
    ///
    /// # Errors
    /// Fails if the event loop has stopped (its receiver dropped).
    pub async fn send(&self, req: A::Session) -> anyhow::Result<()> {
        self.req_tx
            .send(req)
            .await
            .map_err(|_| anyhow::anyhow!("mesh event loop has stopped"))
    }

    /// A cloneable handle to the same request channel [`Self::send`] uses.
    ///
    /// `send` borrows the node, which forces a caller that keeps its `Node`
    /// behind a `RefCell` — as the browser peer must, since wasm-bindgen cannot
    /// hand out `self` by value — to hold that borrow across the await. Any
    /// re-entrant `borrow_mut` during it then panics. Taking a sender first
    /// lets the borrow end before anything is awaited.
    #[must_use]
    pub fn sender(&self) -> mpsc::Sender<A::Session> {
        self.req_tx.clone()
    }

    /// Ask the loop to broadcast `Left` and wind down, waiting up to
    /// [`NODE_LEAVE_SECS`]. On
    /// timeout returns `Ok(())` and the task detaches.
    ///
    /// # Errors
    /// Returns an error if the event-loop task panicked or returned an error.
    pub async fn leave(mut self) -> anyhow::Result<()> {
        let _ = self.quit_tx.send(()).await;
        if let Some(task) = self.task.take() {
            let timeout = n0_future::time::sleep(Duration::from_secs(NODE_LEAVE_SECS));
            tokio::select! {
                joined = task => {
                    joined
                        .map_err(|error| anyhow::anyhow!("mesh task panicked: {error}"))?
                        .map_err(|error| anyhow::anyhow!("mesh loop error: {error}"))?;
                }
                () = timeout => {}
            }
        }
        Ok(())
    }
}

impl<A: NodeDriver> Drop for Node<A> {
    fn drop(&mut self) {
        // Fallback if `leave()` was never called: abort the loop so it doesn't leak.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
