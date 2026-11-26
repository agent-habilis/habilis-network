use std::fmt;

// `n0_future::task` is `tokio::task` verbatim off wasm32, and a
// `wasm-bindgen-futures` shim in a browser — where there is no runtime to
// `block_on` and `tokio::spawn` would panic. Its `JoinHandle` carries `abort()`
// on both, so `Drop` below needs no target-specific handling.
use n0_future::task::JoinHandle;
use tokio::sync::{broadcast, mpsc};

use crate::daemon::app::NodeDriver;
use crate::daemon::config::{DriverMode, EventLoopConfig};
use crate::protocol::meshes::MeshName;
use crate::protocol::messages::Authored;
use crate::protocol::{MeshId, Nickname};
use crate::util::tuning::{NODE_LEAVE, SESSION_REQUEST_CAP};

use crate::{daemon, transport};
use n0_future::{task, time};
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use std::net;
use std::time::Duration;
/// Whether a session registers the process-wide ctrl-c and SIGTERM listeners.
///
/// # Examples
///
/// A node either handles a signal itself, or it leaves the mesh when the signal comes.
///
/// ```
/// use habilis_network::runtime::SignalHandling;
///
/// assert_ne!(SignalHandling::Handle, SignalHandling::Leave);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignalHandling {
    /// Register the listeners: a foreground command that owns the process.
    Handle,
    /// Register nothing: a session nested inside a host that owns the signals.
    Leave,
}

/// A live in-process membership over a background event loop, generic over the
/// application driver `A`. Drop it (or call [`Node::leave`]) to wind the loop
/// down.
///
/// # Examples
///
/// A node is a running member of a mesh, and it names its mesh and its nickname. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::NodeDriver;
/// use habilis_network::runtime::Node;
///
/// # async fn demo<Driver: NodeDriver + 'static>(node: &Node<Driver>) {
/// let _mesh = node.mesh_id();
/// let _nick = node.nickname();
/// # }
/// ```
#[must_use]
pub struct Node<Driver: NodeDriver> {
    mesh_id: MeshId,
    name: MeshName,
    nickname: Nickname,
    req_tx: mpsc::Sender<Driver::Session>,
    quit_tx: mpsc::Sender<()>,
    task: Option<JoinHandle<Result<(), super::event_loop::EventLoopError>>>,
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
impl<Driver: NodeDriver> fmt::Debug for Node<Driver> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("Node");
        debug.field("mesh_id", &self.mesh_id);
        debug.field("name", &self.name);
        debug.field("nickname", &self.nickname);
        debug.finish_non_exhaustive()
    }
}

impl<Driver: NodeDriver + 'static> Node<Driver> {
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
    pub fn spawn(
        mut config: EventLoopConfig,
        app: Driver,
        push: Option<broadcast::Sender<Authored>>,
        handle_signals: SignalHandling,
    ) -> Self {
        let (req_tx, req_rx): (
            mpsc::Sender<Driver::Session>,
            mpsc::Receiver<Driver::Session>,
        ) = mpsc::channel(SESSION_REQUEST_CAP);
        let (quit_tx, quit_rx): (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel(1);
        config.runtime.driver = DriverMode::InProcess {
            msg_tx: push,
            quit_rx,
            handle_signals,
        };
        let mesh_id = config.mesh.mesh.clone();
        let name = config.mesh.name.clone();
        let nickname = config.mesh.author.clone();
        #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
        let bound_ports: Vec<u16> = config
            .endpoints
            .endpoint
            .bound_sockets()
            .iter()
            .map(net::SocketAddr::port)
            .collect();
        #[cfg(all(
            feature = "iroh-test-utils",
            feature = "host",
            not(target_arch = "wasm32")
        ))]
        let multihop = config.transports.multihop.as_ref();
        #[cfg(all(
            feature = "iroh-test-utils",
            feature = "host",
            not(target_arch = "wasm32")
        ))]
        let underlay = multihop.map(|handle| {
            let ports: Vec<_> = handle.underlay_ports().collect();
            (handle.underlay_id().get(), ports)
        });
        #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
        let crash_handles = (config.webrtc_handle(), config.endpoints.endpoint.clone());
        let task = task::spawn(daemon::run(config, app, Some(req_rx), None));
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
            // `abort` only marks the task. On a multi-thread runtime the loop can run once more
            // and read the end of its gossip stream, which the close below causes, as a fault.
            let _ = task.await;
        }
        let (webrtc, endpoint) = &self.crash_handles;
        let _ = webrtc.abort_sessions();
        endpoint.close().await;
    }

    /// Tests only: the ports this node's endpoint is bound on. A test that cuts
    /// one group of nodes from another gives each node the other group's ports
    /// (`Blocking::BlockIpTo`).
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
    pub async fn send(&self, request: Driver::Session) -> Result<(), transport::SendError> {
        self.req_tx
            .send(request)
            .await
            .map_err(|_| transport::SendError::Stopped)
    }

    /// A cloneable handle to the same request channel [`Self::send`] uses.
    ///
    /// `send` borrows the node, which forces a caller that keeps its `Node`
    /// behind a `RefCell` — as the browser peer must, since wasm-bindgen cannot
    /// hand out `self` by value — to hold that borrow across the await. Any
    /// re-entrant `borrow_mut` during it then panics. Taking a sender first
    /// lets the borrow end before anything is awaited.
    #[must_use]
    pub fn sender(&self) -> mpsc::Sender<Driver::Session> {
        self.req_tx.clone()
    }

    /// Ask the loop to broadcast `Left` and wind down, waiting up to
    /// [`NODE_LEAVE`]. `Ok(())` means that the loop ended and the node is closed. When the loop
    /// does not end in that time, the loop task is aborted and the result is an error that says
    /// the node was not closed. The abort drops the endpoints open, and iroh logs an ERROR for
    /// that: it is right for a state that must not occur, so do not remove the abort to hide it.
    ///
    /// The loop closes the endpoint that setup bound for this node, with its
    /// router and multi-hop underlay. It does not close an endpoint that the
    /// caller injected (`SetupParams::endpoint`); that one stays open for the
    /// caller's own protocols, and the caller closes it.
    ///
    /// # Errors
    /// Returns an error if the event-loop task panicked or returned an error.
    pub async fn leave(mut self) -> Result<(), transport::SendError> {
        let _ = self.quit_tx.send(()).await;
        match self.task.take() {
            Some(task) => wait_for_loop(task, NODE_LEAVE).await,
            None => Ok(()),
        }
    }
}

/// Waits for the event loop task to end, up to `bound`. `Ok` means that the task ended. On the
/// bound the task is aborted and the error says that the node is not closed.
async fn wait_for_loop(
    mut task: JoinHandle<Result<(), super::event_loop::EventLoopError>>,
    bound: Duration,
) -> Result<(), transport::SendError> {
    let timeout = time::sleep(bound);
    tokio::select! {
        joined = &mut task => {
            joined
                .map_err(|error| transport::SendError::internal(anyhow::anyhow!("mesh task panicked: {error}")))?
                .map_err(transport::SendError::EventLoop)
        }
        () = timeout => {
            task.abort();
            Err(transport::SendError::internal(anyhow::anyhow!(
                "the node was not closed in {:.1} s",
                bound.as_secs_f64()
            )))
        }
    }
}

impl<Driver: NodeDriver> Drop for Node<Driver> {
    fn drop(&mut self) {
        // Fallback if `leave()` was never called: abort the loop so it doesn't leak.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::future::{self, Pending};
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use n0_future::{task, time};

    use super::super::event_loop::EventLoopError;
    use crate::daemon::node;

    /// Sets the flag when the task that owns it is dropped: the task ended or was aborted.
    // the flag is shared between the test and the task that it watches
    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_leave_that_returns_ok_has_ended_the_loop_task() {
        // the flag is shared between the test and the task that sets it
        let ended = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ended);
        let loop_task = task::spawn(async move {
            time::sleep(Duration::from_millis(300)).await;
            flag.store(true, Ordering::SeqCst);
            Ok(())
        });
        let outcome = node::wait_for_loop(loop_task, Duration::from_millis(50)).await;
        assert!(
            outcome.is_err() || ended.load(Ordering::SeqCst),
            "the wait returned Ok while the loop task still ran: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_task_that_never_ends_gives_an_error_and_is_aborted() {
        // the flag is shared between the test and the task that owns the guard
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&dropped));
        let loop_task = task::spawn(async move {
            let _guard = guard;
            let forever: Pending<()> = future::pending();
            forever.await;
            Ok(())
        });
        let outcome = node::wait_for_loop(loop_task, Duration::from_millis(50)).await;
        time::sleep(Duration::from_millis(100)).await;
        assert!(
            outcome.is_err(),
            "the bound passed: the wait must say that the node is not closed, not Ok"
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "the loop task still runs after the bound: it must be aborted"
        );
    }

    #[tokio::test]
    async fn a_task_that_ends_in_time_gives_ok_after_it_ended() {
        // the flag is shared between the test and the task that sets it
        let ended = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ended);
        let loop_task = task::spawn(async move {
            time::sleep(Duration::from_millis(100)).await;
            flag.store(true, Ordering::SeqCst);
            Ok(())
        });
        let outcome = node::wait_for_loop(loop_task, Duration::from_secs(5)).await;
        assert!(
            outcome.is_ok(),
            "a loop that ended in time is a clean leave: {outcome:?}"
        );
        assert!(
            ended.load(Ordering::SeqCst),
            "Ok came before the loop task ended: the wait returned early"
        );
    }

    #[tokio::test]
    async fn a_loop_error_comes_back_to_the_caller() {
        let loop_task = task::spawn(async {
            Err(EventLoopError::Internal(Box::new(io::Error::other(
                "the loop failed",
            ))))
        });
        let outcome = node::wait_for_loop(loop_task, Duration::from_secs(5)).await;
        assert!(
            outcome.is_err(),
            "the error of the loop must reach the caller"
        );
    }
}
