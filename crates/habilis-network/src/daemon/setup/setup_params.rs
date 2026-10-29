use super::InjectedEndpoint;
use crate::gossip::event::NodeSink;
use std::path::PathBuf;

use crate::protocol::Nickname;

use crate::daemon::CoHostPolicy;

use std::sync::atomic;

/// The per-session inputs to [`setup_mesh`](super::setup_mesh) that are independent of the
/// [`SetupKind`](super::SetupKind): this member's identity/io/tuning and the localhost
/// binding request. Bundled so the one-shot assembly stays within the
/// argument budget.
///
/// # Examples
///
/// The parameters of a setup carry what the node needs to start. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::SetupParams;
///
/// # fn demo(params: SetupParams) {
/// let _ = params;
/// # }
/// ```
#[non_exhaustive]
pub struct SetupParams {
    /// This member's nickname, the author of every message it sends.
    pub author: Nickname,
    /// G: the gossip active-view cap. `0` takes `tuning::GOSSIP_ACTIVE_VIEW_CAPACITY`.
    pub max_peers: usize,
    /// C: the ceiling of direct connections. `0` takes [`crate::transport::MAX_DIRECT_PEERS`].
    pub max_direct: usize,
    /// The consumer's per-user runtime base (see
    /// [`runtime_base`](crate::util::runtime_base)) — the root the socket, the
    /// default state file, and the default log dir live under. Supplied rather
    /// than derived: the engine is embedded by more than one binary and must not
    /// claim a `/tmp` path under any single one's name. `None` for an embedder
    /// that writes no files and binds no control socket.
    pub runtime_base: Option<PathBuf>,
    /// Where the daemon writes its identity and readiness JSON. `None` writes none.
    pub state_file: Option<PathBuf>,
    /// Where the node emits its events (`NodeEvent`).
    pub sink: std::sync::Arc<dyn NodeSink>,
    /// Share the caller's endpoint instead of minting one. `None` ⇒ the mesh
    /// builds its own, which is right for a standalone peer and wrong for a
    /// process that also speaks its own protocol.
    pub endpoint: Option<InjectedEndpoint>,
    /// ALPNs the caller wants served on the mesh's Router.
    ///
    /// Required rather than optional when sharing an endpoint: `Router::spawn`
    /// *overrides* the endpoint's ALPN list, and two `accept()` loops on one
    /// endpoint race for the same queue. One Router owns accept; everything
    /// else registers here.
    pub protocols: habilis_network_iroh_transport_util::ProtocolSet,
    /// This node's own paths, narrowed to the mesh's list in `setup_mesh`.
    /// The shipped surfaces pass the default. Narrowing it by hand is the test
    /// harness's lever to force a relay-only path. Never part of the mesh id —
    /// see the type.
    pub transports: crate::lookup::TransportOpts,
    /// The `meta` channel's per-peer write gate, when the application keeps a
    /// per-peer map there (see [`crate::doc::SelfWriteGate`]). `None` leaves the
    /// channel free-form.
    pub per_peer_gate: Option<crate::doc::SelfWriteGate>,
    /// Override the co-host policy the [`SetupKind`](super::SetupKind) would imply. `None` keeps
    /// the derived one; a directory session passes its own (see
    /// [`DIRECTORY_ADVERTISER_COHOST`](crate::daemon::config::DIRECTORY_ADVERTISER_COHOST)).
    pub cohost: Option<CoHostPolicy>,
    /// The shared live-peer counter a directory advertiser re-broadcasts from.
    /// Supplied up front rather than patched onto the returned config, so the
    /// config is complete the moment it exists.
    pub live_count: Option<LiveCount>,
}

impl SetupParams {
    /// The params of one member with every other field at its default: the engine's own caps, no
    /// runtime files, no shared endpoint, no ALPNs, and the default transports.
    #[must_use]
    pub fn new<S: NodeSink + 'static>(author: Nickname, sink: S) -> Self {
        Self {
            author,
            max_peers: 0,
            max_direct: 0,
            runtime_base: None,
            state_file: None,
            // trait object: the loop and the setup share the sink through this Arc
            sink: std::sync::Arc::new(sink),
            endpoint: None,
            protocols: habilis_network_iroh_transport_util::ProtocolSet::default(),
            transports: crate::lookup::TransportOpts::default(),
            per_peer_gate: None,
            cohost: None,
            live_count: None,
        }
    }

    /// Set the ceiling of peers in the mesh.
    #[must_use]
    pub fn with_max_peers(self, max_peers: usize) -> Self {
        Self { max_peers, ..self }
    }

    /// Set the ceiling of direct connections.
    #[must_use]
    pub fn with_max_direct(self, max_direct: usize) -> Self {
        Self { max_direct, ..self }
    }

    /// Set the per-user runtime base.
    #[must_use]
    pub fn with_runtime_base(self, runtime_base: PathBuf) -> Self {
        Self {
            runtime_base: Some(runtime_base),
            ..self
        }
    }

    /// Set the default state file.
    #[must_use]
    pub fn with_state_file(self, state_file: PathBuf) -> Self {
        Self {
            state_file: Some(state_file),
            ..self
        }
    }

    /// Share the caller's endpoint instead of minting one.
    #[must_use]
    pub fn with_endpoint(self, endpoint: InjectedEndpoint) -> Self {
        Self {
            endpoint: Some(endpoint),
            ..self
        }
    }

    /// Serve these ALPNs on the mesh's Router.
    #[must_use]
    pub fn with_protocols(
        self,
        protocols: habilis_network_iroh_transport_util::ProtocolSet,
    ) -> Self {
        Self { protocols, ..self }
    }

    /// Narrow this node's own paths.
    #[must_use]
    pub fn with_transports(self, transports: crate::lookup::TransportOpts) -> Self {
        Self { transports, ..self }
    }

    /// Set the `meta` channel's per-peer write gate.
    #[must_use]
    pub fn with_per_peer_gate(self, per_peer_gate: crate::doc::SelfWriteGate) -> Self {
        Self {
            per_peer_gate: Some(per_peer_gate),
            ..self
        }
    }

    /// Override the co-host policy the [`SetupKind`](super::SetupKind) would imply.
    #[must_use]
    pub fn with_cohost(self, cohost: CoHostPolicy) -> Self {
        Self {
            cohost: Some(cohost),
            ..self
        }
    }

    /// Set the shared live-peer counter a directory advertiser re-broadcasts from.
    #[must_use]
    pub fn with_live_count(self, live_count: LiveCount) -> Self {
        Self {
            live_count: Some(live_count),
            ..self
        }
    }
}

impl std::fmt::Debug for SetupParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupParams").finish_non_exhaustive()
    }
}

/// The shared live-peer count. The loop mirrors its roster size into it, and a directory advertiser
/// re-broadcasts from it. Clones share one counter.
///
/// # Examples
///
/// A live count is the number of members that a setup sees as live. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::LiveCount;
///
/// # fn demo(count: LiveCount) {
/// let _ = count;
/// # }
/// ```
#[derive(Debug, Default)]
// the counter is shared by the setup and the caller, which reads it
pub struct LiveCount(std::sync::Arc<atomic::AtomicUsize>);

impl Clone for LiveCount {
    fn clone(&self) -> Self {
        Self(std::sync::Arc::clone(&self.0))
    }
}

impl std::ops::Deref for LiveCount {
    type Target = atomic::AtomicUsize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
