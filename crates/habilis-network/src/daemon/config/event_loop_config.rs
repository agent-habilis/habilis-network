//! The configuration the event loop starts from.

use super::co_host_policy::CoHostPolicy;
use super::driver_mode::DriverMode;
use super::endpoint_owner::EndpointOwner;
use crate::daemon::setup::LiveCount;
#[cfg(feature = "host")]
use crate::daemon::shutdown::{Owner, OwnerPidError};

use crate::transport::UdpTransport;
use std::path::PathBuf;

use iroh::Endpoint;
use iroh::protocol::Router;
use iroh_gossip::api::GossipTopic;
use tokio::sync::{mpsc, watch};

use crate::gossip::event::NodeSink;
use crate::protocol::mesh::{Mesh, MeshName};
use crate::protocol::{MeshId, Nickname};

use crate::beacon;

use crate::protocol::{crypto, identity};
#[cfg(feature = "multihop")]
use crate::transport::underlay_webrtc;
use iroh::address_lookup::memory;

use crate::{doc, lookup, protocol, transport};
use iroh_gossip::net;
use std::{fmt, sync};
/// Configuration for the event loop, shared by `create` and `join`.
/// The driver-specific channels live in [`DriverMode`].
/// Opaque to consumers: built whole by
/// [`setup_mesh`](crate::daemon::setup::setup_mesh) and handed to
/// [`Node::spawn`](crate::daemon::node::Node::spawn) or [`run`](crate::daemon::run) unmodified. The
/// fields are crate-private both because most are `iroh` types the surface must
/// not expose, and because three of them used to be patched in after
/// construction — a window in which the value was knowingly wrong.
///
/// # Examples
///
/// An event loop config names the owner process and the author of the node. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::EventLoopConfig;
///
/// # fn demo(config: &EventLoopConfig) {
/// let _owner = config.owner_pid();
/// let _author = config.author();
/// # }
/// ```
pub struct EventLoopConfig {
    pub(crate) topic: GossipTopic,
    /// The gossip frontend the topic was subscribed on. Held by the
    /// event loop so it can **re-subscribe** after the topic stream
    /// terminally ends (for example when the actor drops the
    /// subscription; a lag does not end it); without this handle the
    /// daemon would stay permanently deaf (review finding H1).
    pub(crate) gossip: net::Gossip,
    pub(crate) author: Nickname,
    /// This member's signing identity (Ed25519), minted in `setup_mesh`.
    /// In-process / ephemeral for now (see [`crate::protocol::identity`]).
    pub(crate) identity: sync::Arc<identity::Identity>,
    pub(crate) mesh: MeshId,
    /// Decoded mesh name (from the mesh id). Carried so the
    /// shutdown path can print `left #NAME` without re-parsing
    /// the id.
    pub(crate) name: MeshName,
    /// The raw string a topic mesh was derived from; `None` for create/join.
    /// The derived `name` is lossy (URL scheme and query stripped, truncated),
    /// so this is what the joined/left lines, the state file, and `leave`'s
    /// report show for a topic gossip.
    pub(crate) topic_string: Option<String>,
    /// The raw mesh password, retained for the process lifetime when the
    /// mesh is password-protected (`None` otherwise). Needed at blob-offload
    /// time to key blob tickets with the same password — the Argon2id stretch
    /// takes the raw password string, which cannot be recovered from
    /// `mesh_key`. `Password`'s `Debug`/`Display` redact to `***`.
    pub(crate) mesh_password: Option<crypto::Password>,
    /// The Argon2id-stretched mesh key (`Mesh::mesh_key`), retained to
    /// derive the per-channel keys that encrypt the `state`/`meta` docs and
    /// broadcast chat. `None` for a passwordless mesh — those stay plaintext.
    /// Wiped on drop.
    pub(crate) mesh_key: Option<protocol::SymmetricKey>,
    /// Per-loop generic event sink (the tapped `Output`, wrapped as a
    /// [`NodeSink`]). The engine emits `NodeEvent`s through it and hands a clone
    /// to every handler, so multiple in-process sessions each have their own and
    /// never race a shared global.
    pub(crate) sink: sync::Arc<dyn NodeSink>,
    /// The invite-only **creator's** mesh, retained (in-memory, secrets and
    /// all) so the `invite` command can mint from its issuer key + root. `Some`
    /// only on the creator of an invite-only mesh; `None` everywhere else (a
    /// joiner holds no issuer key, so it could never mint).
    pub(crate) mint_mesh: Option<Mesh>,
    pub(crate) endpoint: Endpoint,
    /// Who bound `endpoint`. The loop closes only an endpoint it owns: a shared
    /// one carries the caller's protocols too.
    pub(crate) endpoint_owner: EndpointOwner,
    /// iroh router whose accept loop routes inbound gossip
    /// connections. Must be held alive for the whole event loop —
    /// dropping it kills the accept task and makes the daemon
    /// unreachable to new peers.
    pub(crate) router: Router,
    pub(crate) max_peers: usize,
    /// Inputs for (re)building the co-hosted rendezvous endpoint.
    /// `rendezvous_params.id` doubles as the bootstrap-cache heal
    /// anchor and the peer-side neighbor-filter id;
    /// `beacon::ensure` is called with these on startup and every
    /// heal tick (claim-if-free in private mode).
    pub(crate) rendezvous_params: beacon::RendezvousParams,
    /// Receives the bootstrap relay rung chosen off the event loop — by
    /// the backgrounded startup probe and the beacon's liveness
    /// self-monitor (`rendezvous_params.rung_tx` is the sending half). On
    /// a change the loop re-registers the rendezvous and re-homes the
    /// beacon, so the ladder walk never runs on the sole loop.
    pub(crate) rung_rx: watch::Receiver<Option<iroh::RelayUrl>>,
    /// The backgrounded startup probe behind `rung_rx`, released on the way
    /// out with the rendezvous. `None` for an empty ladder.
    pub(crate) rung_probe: Option<lookup::StoppableTask>,
    /// When this member may serve the rendezvous (beacon role).
    pub(crate) cohost: CoHostPolicy,
    /// The consumer's per-user runtime base — the root the control socket, the
    /// default state file, and the default log dir live under. Carried from
    /// [`SetupParams`](crate::daemon::setup::SetupParams) rather than derived here; see
    /// [`runtime_base`](crate::util::runtime_base) for why it is supplied.
    /// `None` for an embedder that writes no files and binds no socket.
    pub(crate) runtime_base: Option<PathBuf>,
    /// When set, the daemon writes peer count changes to this file.
    pub(crate) state_file: Option<PathBuf>,
    /// The multi-hop transport handle when the mesh policy registered it on the
    /// peer endpoint; `run()` moves it into `EventLoopState::multihop`.
    /// `None` when multihop is off. Built in `setup_mesh`.
    ///
    /// Host-only: multihop forwards real UDP packets, so the crate that provides
    /// `MultihopHandle` is not in the wasm dependency table at all. The *field*
    /// has to disappear rather than just hold `None` — its type does not exist
    /// there.
    #[cfg(feature = "multihop")]
    pub(crate) multihop: Option<habilis_network_iroh_multihop_transport::MultihopHandle>,
    /// The `WebRTC` leg of the multihop underlay; `run()` moves it into
    /// `EventLoopState::underlay_webrtc`. `None` when multihop is off, and on an
    /// injected endpoint, whose underlay the caller built.
    #[cfg(feature = "multihop")]
    pub(crate) underlay_webrtc: Option<underlay_webrtc::UnderlayWebRtc>,
    /// The members of this mesh that the LAN announces, read by the event loop. `None` when the
    /// endpoint has no mDNS handle: there is no LAN arm then.
    pub(crate) lan_contacts: Option<mpsc::Receiver<lookup::LanEvent>>,
    /// This peer's `WebRTC` transport handle. Portable: it is the browser's
    /// only direct path onto the mesh, and an extra candidate path for a native
    /// peer. `run()` moves it into `EventLoopState::webrtc`.
    pub(crate) webrtc: habilis_network_iroh_webrtc_transport::WebRtcHandle,
    /// `TransportOpts::webrtc`: off, the handle above is detached — not on
    /// the endpoint, answering nothing — and the loop negotiates no session.
    pub(crate) webrtc_enabled: bool,
    /// See `EventLoopState::local_udp_transport`. With `relay_transport` it
    /// also decides `EventLoopState::rendezvous_graft_needs_session`.
    pub(crate) local_udp_transport: UdpTransport,
    /// The negotiation-slot table this peer's Router acceptor was built with.
    /// `run()` moves it into `EventLoopState::webrtc_admission`, so the dialing
    /// side and the answering side share one direct-peer ceiling.
    pub(crate) webrtc_admission: transport::SignalAdmission,
    /// The address book of the member endpoint. `run()` moves it into
    /// `EventLoopState::address_book`, where the addresses of the peers are registered.
    pub(crate) address_book: memory::MemoryLookup,
    /// How far ICE may reach when gathering — host-only on a loopback mesh.
    /// `run()` moves it into `EventLoopState::webrtc_ice`.
    pub(crate) webrtc_ice: transport::IceProfile,
    /// Inbound unicast frames from the `UNICAST_ALPN` acceptor. The event loop
    /// drains this into `gossip::ingest` (the same path as gossip), so both
    /// transports share signature-verify + dedup. Built in `setup_mesh`.
    pub(crate) unicast_rx: mpsc::Receiver<bytes::Bytes>,
    /// When advertising (`create --advertise`), the shared counter the
    /// directory re-broadcast task reads the live peer count from. Supplied
    /// up front through `SetupParams::live_count`, so the config is complete
    /// when it is built; `run` stores it before the first advertisement.
    pub(crate) live_count: Option<LiveCount>,
    /// `TransportPolicy::relay`, read from the mesh config — never from a
    /// per-node option, so every member agrees.
    pub(crate) relay_transport: transport::PayloadPath,
    /// Who drives the loop (CLI / in-process) and the channels that driver
    /// needs. Assigned by [`Node::spawn`](crate::daemon::node::Node::spawn) for an in-process
    /// consumer; a config handed straight to [`run`](crate::daemon::run) keeps the CLI
    /// default. Crate-private, so it cannot be the wrong variant in a window
    /// visible to a consumer.
    pub(crate) driver: DriverMode,
    /// The `meta` channel's per-peer write gate, when the application keeps a
    /// per-peer map there (see [`crate::doc::SelfWriteGate`]). `None` leaves the
    /// channel free-form.
    pub(crate) per_peer_gate: Option<doc::SelfWriteGate>,
    /// The process a CLI daemon lives for, set by
    /// [`set_owner_pid`](Self::set_owner_pid). `None` keeps the parent watch.
    #[cfg(feature = "host")]
    pub(crate) owner: Option<Owner>,
}

impl EventLoopConfig {
    /// Live for `pid` instead of for the parent process: a CLI daemon quits
    /// gracefully once that process exits, and the state file names it as
    /// `owner_pid`. For a daemon started detached, whose parent is init. An
    /// in-process driver has no process to exit and ignores it.
    ///
    /// # Errors
    /// `pid` is 0 or 1, the daemon's own pid, or no live process has it. The
    /// message is one line.
    #[cfg(feature = "host")]
    pub fn set_owner_pid(mut self, pid: u32) -> Result<Self, OwnerPidError> {
        self.owner = Some(Owner::try_new(pid)?);
        Ok(self)
    }

    /// The pid set by [`owner_pid`](Self::owner_pid).
    #[cfg(feature = "host")]
    #[must_use]
    pub fn owner_pid(&self) -> Option<u32> {
        self.owner.map(Owner::pid)
    }

    /// The resolved mesh id. Available before the loop starts, for a consumer
    /// that must name the mesh at setup time (a log attach, a directory ad).
    #[must_use]
    pub fn mesh_id(&self) -> &MeshId {
        &self.mesh
    }

    /// This peer's `WebRTC` transport handle.
    ///
    /// Handed out so a consumer can read its own live direct-peer count
    /// (`transport().session_count()`) with no request/response hop into the
    /// event loop — the loop owns `EventLoopState` exclusively, but the
    /// transport is shared by design. Cheap to clone; every clone shares one
    /// session registry.
    #[must_use]
    pub fn webrtc_handle(&self) -> habilis_network_iroh_webrtc_transport::WebRtcHandle {
        self.webrtc.clone()
    }

    /// The Router serving this endpoint's ALPNs — gossip, unicast, the mesh
    /// JSEP signal, and any protocol the caller registered.
    ///
    /// Handed out so a caller sharing its endpoint can keep the accept loop
    /// alive past `Node::spawn`, which consumes the config. Hold the clone;
    /// dropping every one aborts the accept task and the process stops
    /// answering. Avoid `Router::shutdown` unless you mean it — it closes the
    /// endpoint, which on a shared endpoint takes the caller's protocol down
    /// too.
    #[must_use]
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// This member's nickname, as resolved by setup.
    #[must_use]
    pub fn author(&self) -> &Nickname {
        &self.author
    }
}

impl fmt::Debug for EventLoopConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventLoopConfig").finish_non_exhaustive()
    }
}
