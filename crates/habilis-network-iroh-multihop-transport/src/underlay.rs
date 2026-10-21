//! The forwarding **underlay**: a dedicated iroh endpoint that carries opaque
//! QUIC packets hop-by-hop between adjacent relays.
//!
//! The underlay is deliberately a *separate* endpoint from the application
//! endpoint whose packets it relays — the application endpoint is busy being the
//! end-to-end QUIC peer, and could not recursively carry itself. Adjacent hops
//! are link-state neighbours, so their underlay endpoints reach each other over a
//! normal direct/relay path.
//!
//! Outbound: one long-lived writer task per next-hop drains a channel of cells
//! onto a single uni-stream. Inbound ([`ForwardAcceptor`]): each accepted
//! uni-stream is read frame-by-frame; a cell is either forwarded to its next hop
//! or, if this node is the destination, delivered to the local transport — but
//! only after the cell proves it belongs here, since `FORWARD_ALPN` accepts a
//! connection from anyone and an unchecked relay is an amplifying reflector.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Context;
use habilis_network_iroh_transport_util::{Rung, custom_rung, is_blocked_to, remote_id_of};
use iroh::endpoint::Connection;
use iroh::endpoint::transports::Addr;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use iroh_base::CustomAddr;
use n0_future::time::{Duration, Instant, MissedTickBehavior};
#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use crate::addr::{Route, RouteHop};
use crate::role::{AppId, UnderlayId};
use crate::topology::Topology;
use crate::wire::{Cell, read_cell, write_cell};

/// ALPN for the multihop underlay's hop-to-hop forwarding protocol.
pub(crate) const FORWARD_ALPN: &[u8] = b"iroh-multihop/forward/1";

/// Per-next-hop outbound cell queue depth. Dropping past this bounds memory the
/// way a UDP socket's send buffer does — QUIC treats the loss as any other.
/// This is a burst limit; [`FORWARD_QUEUE_BYTES`] is the real ceiling.
const WRITER_QUEUE: usize = 128;

/// Concurrent next-hop writers. A node's honest next-hop set is its direct
/// underlay neighbours, so this is far above any real fan-out; it exists because
/// the map is keyed on a hop id a remote peer chose.
const MAX_WRITERS: usize = 64;

/// Total bytes queued across every writer. Without it the per-hop queue depth is
/// the only bound, and it multiplies by the writer count instead of capping it.
const FORWARD_QUEUE_BYTES: usize = 32 * 1024 * 1024;

/// Hops of delivered cells that the forwarder remembers, so that a reply along a reversed route
/// can tell its first hop. The ids come off the wire, so the set has a ceiling.
const HEARD_HOPS_CAP: usize = 1024;

/// Hops without a vector that get a log line of their own. The ids come off the wire, so the map
/// that remembers them has a ceiling.
const UNRESOLVED_SEEN_CAP: usize = 128;

/// The hops that named a cell this node delivered, newest last. Past [`HEARD_HOPS_CAP`] hops
/// the oldest is forgotten.
#[derive(Debug, Default)]
struct HeardHops {
    order: VecDeque<UnderlayId>,
    set: HashSet<UnderlayId>,
}

/// Dial attempts before a writer task gives up on an unreachable next hop.
const DIAL_ATTEMPTS: usize = 4;

/// A packet that reached its destination on this node, ready for the local
/// transport's `poll_recv` to surface to iroh.
#[derive(Debug)]
pub(crate) struct Delivered {
    /// The sender's return address (a reversed route), reported to iroh as the
    /// remote of this packet so replies route back.
    pub(crate) remote: CustomAddr,
    pub(crate) packet: Vec<u8>,
}

/// How long a reading of a connection's paths stands. The path moves
/// rarely, and asking for it on every cell would cost more than the cell.
const PATH_RECHECK: Duration = Duration::from_millis(250);

/// The open paths of a connection, each with whether it is the selected one.
fn paths_of(connection: &Connection) -> Vec<(TransportAddr, bool)> {
    connection
        .paths()
        .iter()
        .map(|path| (path.remote_addr().clone(), path.is_selected()))
        .collect()
}

/// Whether a writer sends on a selected path that is not the relay.
/// Nothing selected is not trusted: the engine's own rule for payload
/// (`payload_allowed_on`) refuses until a path is selected.
fn direct_for_writer<'a>(paths: impl IntoIterator<Item = &'a (TransportAddr, bool)>) -> bool {
    paths
        .into_iter()
        .any(|(addr, selected)| *selected && !matches!(addr, TransportAddr::Relay(_)))
}

/// Whether a connection that we accepted has an open path that is not the relay.
/// iroh opens paths only from the dialling end. After the dialler's hole-punch
/// round prunes its redundant IP paths, the accepting end chooses no path of its
/// own on this connection: its IP path is open but not selected, and the
/// relay path too. The cells then arrive on the path that the dialler selected,
/// so the selected path here says nothing about them. The cost: a cell that really
/// came over the relay is admitted while an IP path is also open. The dialler's
/// writer gate refuses relay cells, and iroh shows no path per datagram.
fn direct_for_inbound<'a>(paths: impl IntoIterator<Item = &'a (TransportAddr, bool)>) -> bool {
    paths
        .into_iter()
        .any(|(addr, _)| !matches!(addr, TransportAddr::Relay(_)))
}

/// The paths that a test has not taken from this node: `blocked` names the ones it took.
///
/// A test cut changes what the selector may select, and iroh selects again only when a path
/// opens or closes. A connection that stood on a path before the cut keeps it selected, and
/// the gate would read a direct path for ever: the cut would not reach a live writer. So the
/// gate leaves the blocked paths out of what it reads.
fn unblocked(
    paths: &[(TransportAddr, bool)],
    blocked: impl Fn(&TransportAddr) -> bool,
) -> impl Iterator<Item = &(TransportAddr, bool)> {
    paths.iter().filter(move |entry| !blocked(&entry.0))
}

/// Whether a test took `path` away from the endpoint `local`: the question that the selector
/// of the underlay asks of its paths. Without the `test-hooks` of
/// `habilis-network-iroh-transport-util` nothing is ever blocked, so a build without them reads
/// every path as before.
fn blocked_by_test(local: EndpointId, path: &TransportAddr) -> bool {
    let (rung, ip_remote, remote_id) = match path {
        TransportAddr::Ip(remote) => (Rung::Ip, Some(*remote), None),
        TransportAddr::Relay(_) => (Rung::Relay, None, None),
        TransportAddr::Custom(custom) => (
            custom_rung(custom.id()),
            None,
            remote_id_of(&Addr::Custom(custom.clone())),
        ),
        _ => (Rung::Other, None, None),
    };
    is_blocked_to(local, rung, ip_remote, remote_id)
}

/// Which end of a connection a gate stands on.
#[derive(Debug, Clone, Copy)]
enum GateRole {
    /// The end that dialled and writes the cells.
    Writer,
    /// The end that accepted the connection and reads the cells.
    Inbound,
}

/// The paths of a connection as text, a star on the selected one.
fn path_list(paths: impl IntoIterator<Item = (TransportAddr, bool)>) -> String {
    paths
        .into_iter()
        .map(|(addr, selected)| format!("{addr:?}{}", if selected { "*" } else { "" }))
        .collect::<Vec<_>>()
        .join(" ")
}

/// What the relay may do for cells, set by the mesh policy.
#[derive(Debug, Clone, Copy)]
struct RelayRule {
    /// Whether the relay may carry cells (the mesh's `relay_transport`).
    allow_relay: bool,
    /// How long a hop may stay refused before it is no longer a link.
    stuck_after: Duration,
}

/// Keeps cells off a connection unless it sends on a selected path that is not
/// the relay, unless the mesh lets the relay carry payload. The relay is for
/// lookup alone: a connection starts on it until a direct path opens, and the
/// cells of other peers' traffic must not ride it meanwhile.
struct RelayGate {
    allow_relay: bool,
    /// The underlay endpoint that the gate stands on: the node whose blocks a test may set.
    local: EndpointId,
    role: GateRole,
    /// The paths at the last reading. A test cut is applied to them on every call.
    reading: Option<(Instant, Vec<(TransportAddr, bool)>)>,
    /// The verdict of the last call, so that the log text is built when it changes.
    last_admitted: Option<bool>,
    /// The path list at the last refusal, so that the log says it once per change.
    last_refused_paths: Option<String>,
}

impl RelayGate {
    fn new(allow_relay: bool, local: EndpointId, role: GateRole) -> Self {
        Self {
            allow_relay,
            local,
            role,
            reading: None,
            last_admitted: None,
            last_refused_paths: None,
        }
    }

    /// Whether a cell may cross `connection` now.
    fn admits(&mut self, connection: &Connection) -> bool {
        self.admits_paths(|| paths_of(connection))
    }

    /// `admits`, with the paths of the connection read by `read_paths`, which runs only when
    /// the last reading is old.
    fn admits_paths(&mut self, read_paths: impl FnOnce() -> Vec<(TransportAddr, bool)>) -> bool {
        if self.allow_relay {
            return true;
        }
        let now = Instant::now();
        let fresh =
            matches!(&self.reading, Some((at, _)) if now.duration_since(*at) < PATH_RECHECK);
        if !fresh {
            self.reading = Some((now, read_paths()));
        }
        let paths = self
            .reading
            .as_ref()
            .map_or(&[][..], |(_, paths)| paths.as_slice());
        let direct = unblocked(paths, |path| blocked_by_test(self.local, path));
        let admitted = match self.role {
            GateRole::Writer => direct_for_writer(direct),
            GateRole::Inbound => direct_for_inbound(direct),
        };
        // The cell path allocates nothing: the text of the paths is built only when the
        // reading is new or the verdict changed.
        let changed = !fresh || self.last_admitted != Some(admitted);
        self.last_admitted = Some(admitted);
        if !admitted && changed {
            let paths = path_list(paths.iter().cloned());
            if self.last_refused_paths.as_deref() != Some(paths.as_str()) {
                match self.role {
                    GateRole::Writer => {
                        tracing::debug!(%paths, "multihop underlay: no direct path is selected");
                    }
                    GateRole::Inbound => {
                        tracing::debug!(%paths, "multihop underlay: no open path is not the relay");
                    }
                }
                self.last_refused_paths = Some(paths);
            }
        }
        admitted
    }
}

/// How one next hop's underlay is doing under the relay rule.
///
/// The entry lives as long as the hop's writer: a retiring writer calls
/// `forget`, which clears a stuck mark too. A hop that is still on the relay is
/// then advertised again until its next writer has been refused for the
/// deadline: one retry each time a writer dies, not a loop.
#[derive(Debug)]
struct HopHealth {
    /// The hop's application id: what a link-vector names.
    app_id: AppId,
    /// Since when the gate has refused this hop without a break.
    refused_since: Option<Instant>,
    /// Refused for longer than the deadline: not advertised as a link.
    stuck: bool,
}

/// The outbound writer set and its shared byte budget.
///
/// Split out from [`Forwarder`] so a writer task can hold exactly what it needs
/// to retire itself and release its own queued bytes, without a self-reference
/// back into the forwarder.
#[derive(Debug, Default)]
struct WriterPool {
    /// One outbound writer channel per next-hop underlay endpoint id.
    writers: Mutex<HashMap<UnderlayId, mpsc::Sender<Cell>>>,
    /// Bytes queued across every writer.
    queued_bytes: AtomicUsize,
    /// Cells a writer dropped because its connection was not on a direct path.
    refused_on_relay: AtomicU64,
    /// The relay rule's verdict per next hop, keyed like `writers`.
    health: Mutex<HashMap<UnderlayId, HopHealth>>,
    /// Woken when the gate starts to refuse a hop, and when it admits one that it
    /// refused: the moments at which the best first hop to a peer can change.
    route_wake: Arc<tokio::sync::Notify>,
    /// The connection of each live writer, keyed like `writers`, for a test that reads its paths.
    #[cfg(feature = "test-hooks")]
    connections: Mutex<HashMap<UnderlayId, Connection>>,
}

impl WriterPool {
    /// Drop `key`'s entry, but only if it is still `sender`'s. A writer that has
    /// already been replaced must not delete its successor's channel — that race
    /// is how a sibling transport grew a permanent phantom session.
    fn retire(&self, key: UnderlayId, sender: &mpsc::Sender<Cell>) {
        let mut writers = self.writers.lock().expect("writers mutex poisoned");
        if writers
            .get(&key)
            .is_some_and(|live| live.same_channel(sender))
        {
            writers.remove(&key);
        }
    }

    fn release(&self, cost: usize) {
        self.queued_bytes.fetch_sub(cost, Ordering::Relaxed);
    }

    fn track(&self, underlay: UnderlayId, app_id: AppId) {
        self.health.lock().expect("health mutex poisoned").insert(
            underlay,
            HopHealth {
                app_id,
                refused_since: None,
                stuck: false,
            },
        );
    }

    fn forget(&self, underlay: UnderlayId) {
        self.health
            .lock()
            .expect("health mutex poisoned")
            .remove(&underlay);
        #[cfg(feature = "test-hooks")]
        self.connections
            .lock()
            .expect("connections mutex poisoned")
            .remove(&underlay);
    }

    /// The gate refused this hop just now. Past the deadline the hop is stuck,
    /// said once in the log.
    fn note_refused(&self, underlay: UnderlayId, stuck_after: Duration) {
        let mut health = self.health.lock().expect("health mutex poisoned");
        let Some(hop) = health.get_mut(&underlay) else {
            return;
        };
        if hop.refused_since.is_none() {
            self.route_wake.notify_one();
        }
        let since = *hop.refused_since.get_or_insert_with(Instant::now);
        if !hop.stuck && since.elapsed() >= stuck_after {
            hop.stuck = true;
            tracing::warn!(
                hop = %underlay.fmt_short(),
                app_id = %hop.app_id.fmt_short(),
                "multihop underlay stays on the relay: this hop is not advertised as a link"
            );
        }
    }

    /// The gate admitted this hop: it is a link again.
    fn note_admitted(&self, underlay: UnderlayId) {
        let mut health = self.health.lock().expect("health mutex poisoned");
        let Some(hop) = health.get_mut(&underlay) else {
            return;
        };
        if hop.refused_since.take().is_some() {
            self.route_wake.notify_one();
        }
        if std::mem::take(&mut hop.stuck) {
            tracing::info!(
                hop = %underlay.fmt_short(),
                app_id = %hop.app_id.fmt_short(),
                "multihop underlay is direct again: this hop is a link"
            );
        }
    }

    /// The hops that the gate refuses now, stuck or not.
    fn refusing_app_ids(&self) -> Vec<AppId> {
        self.health
            .lock()
            .expect("health mutex poisoned")
            .values()
            .filter(|hop| hop.refused_since.is_some())
            .map(|hop| hop.app_id)
            .collect()
    }

    fn stuck_app_ids(&self) -> Vec<AppId> {
        self.health
            .lock()
            .expect("health mutex poisoned")
            .values()
            .filter(|hop| hop.stuck)
            .map(|hop| hop.app_id)
            .collect()
    }
}

/// Routes cells outbound to next hops and delivers terminal cells locally.
#[derive(Debug)]
pub(crate) struct Forwarder {
    underlay: Endpoint,
    /// This node's application-layer id, the other half of the identity a cell's
    /// current hop must name.
    self_app_id: AppId,
    /// The runtime that spawns the writers. `enqueue` runs inside `poll_send`, which
    /// iroh calls from the socket's send path (`Transports::poll_send` in iroh's
    /// `socket/transports.rs`). It is kept so that a native spawn never depends on
    /// that caller being inside the runtime; nothing here shows that it is ever
    /// outside. A browser has no runtime and spawns on its one thread.
    #[cfg(not(target_arch = "wasm32"))]
    runtime: Handle,
    pool: Arc<WriterPool>,
    /// Terminal deliveries destined for the local application endpoint.
    inbound: mpsc::Sender<Delivered>,
    /// Cells refused by the gates in [`Forwarder::handle_cell`] or by a budget.
    dropped: AtomicU64,
    /// Cells passed on to a next hop for other nodes. Our own sends are not counted.
    forwarded: AtomicU64,
    /// Cells that ended here and went into the inbox of the local transport.
    delivered: AtomicU64,
    /// What the relay may do for cells.
    rule: RelayRule,
    /// Where the dial address of a next hop comes from: a route names a hop by two ids,
    /// and the address is the one that the hop signed in its link vector.
    topology: Arc<RwLock<Topology>>,
    /// Hops that a writer was spawned for with no vector in the topology: a hop without a vector.
    unresolved_hops: AtomicU64,
    /// The hops that got a log line, and whether it was a warning: see [`UNRESOLVED_SEEN_CAP`].
    unresolved_seen: Mutex<HashMap<UnderlayId, bool>>,
    /// The hops that named a cell this node delivered: the sender and the hops of its route. A
    /// reply goes back along that route reversed, so these are the hops that can lack a vector
    /// for a normal reason: see [`HEARD_HOPS_CAP`].
    heard_hops: Mutex<HeardHops>,
}

impl Forwarder {
    pub(crate) fn new(
        underlay: Endpoint,
        self_app_id: AppId,
        inbound: mpsc::Sender<Delivered>,
        allow_relay: bool,
        stuck_after: Duration,
        topology: Arc<RwLock<Topology>>,
    ) -> Self {
        Self {
            underlay,
            self_app_id,
            #[cfg(not(target_arch = "wasm32"))]
            runtime: Handle::current(),
            pool: Arc::new(WriterPool::default()),
            inbound,
            dropped: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            rule: RelayRule {
                allow_relay,
                stuck_after,
            },
            topology,
            unresolved_hops: AtomicU64::new(0),
            unresolved_seen: Mutex::new(HashMap::new()),
            heard_hops: Mutex::new(HeardHops::default()),
        }
    }

    /// How many writers were spawned for a hop without a vector in the topology.
    #[cfg(test)]
    pub(crate) fn unresolved_hops(&self) -> u64 {
        self.unresolved_hops.load(Ordering::Relaxed)
    }

    /// The address to dial for `hop`: the one that its node signed in its link vector, if the
    /// vector names the same underlay endpoint as the hop. A hop without a vector is dialed
    /// by its id alone, never at an address that a cell carries, and counted: it may still be reachable by what iroh
    /// knows of the id, and if it is not, the cells are lost like any other.
    ///
    /// Logged at debug when the hop is explained. A cell that this node delivered named it: a
    /// reply goes back along the reversed route of a cell, and the sender's first link-vector
    /// arrives some 15 s after it starts. Or it is a link of this node: the origin of a route
    /// saw the vector of a new neighbor before this node did, and the link reaches it. Or this
    /// node held the vector and removed it, because the peer left or the vector expired: the
    /// cells in flight to the peer still name it, and the origin of the route is behind. Any
    /// other hop without a vector is a warning.
    fn dial_addr(&self, hop: &RouteHop) -> EndpointAddr {
        let (known, gone) = {
            let topology = self.topology.read().expect("topology lock poisoned");
            let known = topology
                .underlay_of(hop.app_id)
                .filter(|addr| UnderlayId::new(addr.id) == hop.underlay_id);
            (known, topology.is_gone(hop.app_id))
        };
        known.unwrap_or_else(|| {
            let total = self.unresolved_hops.fetch_add(1, Ordering::Relaxed) + 1;
            let explained =
                gone || self.heard_hop(hop.underlay_id) || self.is_link_of_ours(hop.app_id);
            if self.line_is_due(hop.underlay_id, total, explained) {
                if gone {
                    tracing::debug!(
                        total,
                        hop = %hop.underlay_id.fmt_short(),
                        app_id = %hop.app_id.fmt_short(),
                        "multihop forwarder: hop whose vector is gone, dialing it by id"
                    );
                } else if explained {
                    tracing::debug!(
                        total,
                        hop = %hop.underlay_id.fmt_short(),
                        app_id = %hop.app_id.fmt_short(),
                        "multihop forwarder: hop without a vector, dialing it by id"
                    );
                } else {
                    tracing::warn!(
                        total,
                        hop = %hop.underlay_id.fmt_short(),
                        app_id = %hop.app_id.fmt_short(),
                        "multihop forwarder: hop without a vector that no delivered cell named, dialing it by id"
                    );
                }
            }
            EndpointAddr::new(hop.underlay_id.get())
        })
    }

    /// Whether `app_id` is a link in the vector that this node published of itself.
    fn is_link_of_ours(&self, app_id: AppId) -> bool {
        self.topology
            .read()
            .expect("topology lock poisoned")
            .links_of(self.self_app_id)
            .is_some_and(|links| links.contains(&app_id))
    }

    /// Whether a cell that this node delivered named the hop `underlay_id`.
    fn heard_hop(&self, underlay_id: UnderlayId) -> bool {
        self.heard_hops
            .lock()
            .expect("heard hops poisoned")
            .set
            .contains(&underlay_id)
    }

    /// Remember the hops of the reply route of a delivered cell. Past [`HEARD_HOPS_CAP`] hops
    /// the oldest is forgotten.
    fn note_heard(&self, reply_route: &Route) {
        let mut heard = self.heard_hops.lock().expect("heard hops poisoned");
        for hop in reply_route.hops() {
            if !heard.set.insert(hop.underlay_id) {
                continue;
            }
            heard.order.push_back(hop.underlay_id);
            if heard.order.len() > HEARD_HOPS_CAP
                && let Some(oldest) = heard.order.pop_front()
            {
                heard.set.remove(&oldest);
            }
        }
    }

    /// Whether a log line is due for the hop `underlay_id`, found without a vector for the
    /// `total`-th time, `explained` or not: one line per distinct hop, and one warning per hop,
    /// which a hop that was explained the first time still gets when it is not any more. The ids
    /// come off the wire, so the map that remembers them is bounded; past [`UNRESOLVED_SEEN_CAP`]
    /// hops the rule is one line in 256.
    fn line_is_due(&self, underlay_id: UnderlayId, total: u64, explained: bool) -> bool {
        let mut seen = self
            .unresolved_seen
            .lock()
            .expect("unresolved set poisoned");
        if let Some(warned) = seen.get_mut(&underlay_id) {
            if *warned || explained {
                return false;
            }
            *warned = true;
            return true;
        }
        if seen.len() < UNRESOLVED_SEEN_CAP {
            seen.insert(underlay_id, !explained);
            return true;
        }
        total.is_multiple_of(256)
    }

    /// How many cells this node passed on for other nodes.
    pub(crate) fn forwarded_cells(&self) -> u64 {
        self.forwarded.load(Ordering::Relaxed)
    }

    /// The counters of the data path: what was passed on, refused, dropped and delivered.
    pub(crate) fn counters(&self) -> crate::MultihopCounters {
        crate::MultihopCounters {
            forwarded: self.forwarded.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            refused_on_relay: self.pool.refused_on_relay.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
        }
    }

    /// The local transport dropped a packet that did not fit the buffer that iroh handed it.
    pub(crate) fn note_oversized(&self, len: usize, capacity: usize) {
        if let Some(total) = self.count_drop() {
            tracing::warn!(
                total,
                len,
                capacity,
                reason = "packet larger than the receive buffer",
                "multihop transport dropping packets"
            );
        }
    }

    /// The application ids of the hops stuck on the relay past the deadline.
    pub(crate) fn stuck_hops(&self) -> Vec<AppId> {
        self.pool.stuck_app_ids()
    }

    /// Woken when the gate starts to refuse a hop, and when it admits one that it
    /// refused.
    pub(crate) fn route_wake(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.pool.route_wake)
    }

    /// The application ids of the hops that the gate refuses now, stuck or not.
    pub(crate) fn refusing_hops(&self) -> Vec<AppId> {
        self.pool.refusing_app_ids()
    }

    /// Mark a hop as refused now, without the deadline having passed, as a test of
    /// the choice of a route needs it.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn refuse_hop_for_test(&self, underlay: UnderlayId, app_id: AppId) {
        self.pool.track(underlay, app_id);
        self.pool.note_refused(underlay, Duration::from_mins(1));
    }

    /// The open paths of the connection that our writer holds toward the underlay `hop`, now,
    /// each with whether it is the selected one: the reading that the gate takes.
    #[cfg(feature = "test-hooks")]
    pub(crate) fn writer_paths(&self, hop: UnderlayId) -> Option<Vec<(TransportAddr, bool)>> {
        let connection = self
            .pool
            .connections
            .lock()
            .expect("connections mutex poisoned")
            .get(&hop)
            .cloned()?;
        Some(paths_of(&connection))
    }

    /// Rate-limited visibility for a refused cell. Whoever is sending them sets
    /// the rate, so logging every one hands them a second amplifier.
    fn note_drop(&self, reason: &str) {
        if let Some(total) = self.count_drop() {
            tracing::warn!(total, reason, "multihop forwarder refusing cells");
        }
    }

    /// The refusal of a cell that came in over `connection` from `hop`, with what
    /// the log needs to tell whose path it was: the hop, this node, and the paths.
    fn note_inbound_refusal(&self, hop: UnderlayId, connection: &Connection) {
        if let Some(total) = self.count_drop() {
            tracing::warn!(
                total,
                reason = "cell arrived over the relay",
                hop = %hop.fmt_short(),
                node = %self.underlay.id().fmt_short(),
                paths = %path_list(paths_of(connection)),
                "multihop forwarder refusing cells"
            );
        }
    }

    /// Count a refused cell. The total when it is to be logged: the first, then
    /// every 256th.
    fn count_drop(&self) -> Option<u64> {
        let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        (total == 1 || total.is_multiple_of(256)).then_some(total)
    }

    /// Hand a cell to the writer for `hop`, spawning one if none is live. Never
    /// blocks: a full or dead queue drops the cell (QUIC recovers).
    pub(crate) fn enqueue(&self, hop: &RouteHop, cell: Cell) {
        let cost = cell.packet.len();
        if self.pool.queued_bytes.fetch_add(cost, Ordering::Relaxed) + cost > FORWARD_QUEUE_BYTES {
            self.pool.release(cost);
            self.note_drop("forwarding byte budget exhausted");
            return;
        }
        let key = hop.underlay_id;
        // First attempt on any existing writer.
        if let Some(sender) = self.writer_for(key)
            && sender.try_send(cell.clone()).is_ok()
        {
            return;
        }
        // Stale or absent: (re)spawn a writer, then try once more.
        let Some(sender) = self.spawn_writer(hop) else {
            self.pool.release(cost);
            return;
        };
        if sender.try_send(cell).is_err() {
            self.pool.release(cost);
        }
    }

    /// Deliver a cell that terminated here to the local transport.
    fn deliver(&self, cell: Cell) {
        let Some(route) = Route::reverse_from(cell.path.hops(), cell.source) else {
            self.note_drop("return route is not a legal route");
            return;
        };
        self.note_heard(&route);
        let delivered = Delivered {
            remote: route.encode(),
            packet: cell.packet,
        };
        // A full inbox drops the packet, as a saturated NIC would. It is counted and the first
        // drop is logged: an inbox that nobody drains is a silent black hole otherwise.
        if self.inbound.try_send(delivered).is_ok() {
            self.delivered.fetch_add(1, Ordering::Relaxed);
        } else {
            self.note_drop("inbox of the local transport is full");
        }
    }

    /// Whether `hop` is this node — both identities, since the two endpoints
    /// carry different keys and a cell should not be able to pair our underlay
    /// with somebody else's application id.
    fn is_self(&self, hop: &RouteHop) -> bool {
        hop.underlay_id == UnderlayId::new(self.underlay.id()) && hop.app_id == self.self_app_id
    }

    /// The hop that should have sent us this cell: our predecessor on the route,
    /// or the original sender when we are the first hop.
    fn expected_upstream(cell: &Cell) -> Option<&RouteHop> {
        match cell.pos.checked_sub(1) {
            None => Some(&cell.source),
            Some(previous) => cell.path.hop_at(previous as usize),
        }
    }

    /// Process one received cell: forward to the next hop, or deliver if we are
    /// the destination.
    ///
    /// `from` is the authenticated id of the connection the cell arrived on.
    /// Requiring it to be the route's preceding hop is what stops a stranger
    /// injecting a cell at a position it does not occupy — the structural
    /// invariants on [`Route`] bound what a route may look like, but only this
    /// binds a cell to the path it claims to be travelling.
    pub(crate) fn handle_cell(&self, cell: Cell, from: UnderlayId) {
        let Some(here) = cell.current_hop() else {
            self.note_drop("position past the end of the route");
            return;
        };
        if !self.is_self(here) {
            self.note_drop("position does not name this node");
            return;
        }
        let is_expected_upstream =
            Self::expected_upstream(&cell).is_some_and(|hop| hop.underlay_id == from);
        if !is_expected_upstream {
            self.note_drop("cell did not arrive from its preceding hop");
            return;
        }
        match cell.next_hop() {
            Some(next) => {
                let next = next.clone();
                self.forwarded.fetch_add(1, Ordering::Relaxed);
                self.enqueue(&next, cell.advanced());
            }
            None => self.deliver(cell),
        }
    }

    fn writer_for(&self, key: UnderlayId) -> Option<mpsc::Sender<Cell>> {
        let writers = self.pool.writers.lock().expect("writers mutex poisoned");
        writers.get(&key).cloned()
    }

    /// Insert and spawn a fresh writer task for `dst`, replacing any dead entry.
    /// `None` once [`MAX_WRITERS`] are live.
    ///
    /// Refusing rather than evicting is deliberate: the next-hop id comes off the
    /// wire, so evicting would let a flood of invented hops walk the real
    /// neighbours out of the map. A refused flood instead clears itself, because
    /// each spawned writer gives up after [`DIAL_ATTEMPTS`] and removes its own
    /// entry on the way out.
    fn spawn_writer(&self, hop: &RouteHop) -> Option<mpsc::Sender<Cell>> {
        let dst = self.dial_addr(hop);
        let key = UnderlayId::new(dst.id);
        let app_id = hop.app_id;
        let (tx, rx) = mpsc::channel(WRITER_QUEUE);
        {
            let mut writers = self.pool.writers.lock().expect("writers mutex poisoned");
            if writers.len() >= MAX_WRITERS && !writers.contains_key(&key) {
                drop(writers);
                self.note_drop("next-hop writer ceiling reached");
                return None;
            }
            writers.insert(key, tx.clone());
        }
        self.pool.track(key, app_id);
        let writer = writer_task(
            self.underlay.clone(),
            dst,
            rx,
            tx.clone(),
            Arc::clone(&self.pool),
            self.rule,
        );
        #[cfg(not(target_arch = "wasm32"))]
        self.runtime.spawn(writer);
        #[cfg(target_arch = "wasm32")]
        n0_future::task::spawn(writer);
        Some(tx)
    }
}

/// Drain `rx` onto a single uni-stream to `dst`. Exits on dial failure or a
/// write error, retiring its own entry so the map does not accumulate one dead
/// writer per next-hop id a peer ever named, and releasing whatever it still had
/// queued so a dead hop cannot hold the shared byte budget hostage.
async fn writer_task(
    underlay: Endpoint,
    dst: EndpointAddr,
    mut rx: mpsc::Receiver<Cell>,
    handle: mpsc::Sender<Cell>,
    pool: Arc<WriterPool>,
    rule: RelayRule,
) {
    let outcome = drain_to_hop(&underlay, &dst, &mut rx, &pool, rule).await;
    if let Err(error) = outcome {
        tracing::debug!(hop = %dst.id.fmt_short(), %error, "multihop underlay writer stopping");
    }
    let key = UnderlayId::new(dst.id);
    pool.retire(key, &handle);
    pool.forget(key);
    // Whatever never made it onto the wire is still charged to the budget.
    rx.close();
    while let Ok(cell) = rx.try_recv() {
        pool.release(cell.packet.len());
    }
}

async fn drain_to_hop(
    underlay: &Endpoint,
    dst: &EndpointAddr,
    rx: &mut mpsc::Receiver<Cell>,
    pool: &WriterPool,
    rule: RelayRule,
) -> anyhow::Result<()> {
    let conn = dial_with_retry(underlay, dst)
        .await
        .context("underlay dial gave up")?;
    #[cfg(feature = "test-hooks")]
    pool.connections
        .lock()
        .expect("connections mutex poisoned")
        .insert(UnderlayId::new(dst.id), conn.clone());
    let mut send = conn.open_uni().await.context("open underlay uni-stream")?;
    let mut gate = RelayGate::new(rule.allow_relay, underlay.id(), GateRole::Writer);
    // Looks at the path once a second even when no cell comes, so a hop that was
    // withdrawn for staying on the relay (and so carries no cells) is a link
    // again once a direct path opens.
    let mut recheck = n0_future::time::interval(Duration::from_secs(1));
    recheck.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            // A connection that ended under us ends the writer. Without this arm a
            // dead connection with no cell in flight is read by the tick below as
            // a connection with no direct path: the hop would be marked stuck and
            // the writer would never retire.
            reason = conn.closed() => {
                anyhow::bail!("underlay connection closed: {reason}");
            }
            next = rx.recv() => {
                let Some(cell) = next else { break };
                let cost = cell.packet.len();
                if gate.admits(&conn) {
                    pool.note_admitted(UnderlayId::new(dst.id));
                } else {
                    // Dropped like any other loss: QUIC above retransmits, and a
                    // direct path takes over once one opens.
                    pool.release(cost);
                    pool.refused_on_relay.fetch_add(1, Ordering::Relaxed);
                    pool.note_refused(UnderlayId::new(dst.id), rule.stuck_after);
                    continue;
                }
                let written = write_cell(&mut send, &cell).await;
                pool.release(cost);
                written.context("underlay write failed")?;
            }
            _ = recheck.tick(), if !rule.allow_relay => {
                if gate.admits(&conn) {
                    pool.note_admitted(UnderlayId::new(dst.id));
                } else {
                    pool.note_refused(UnderlayId::new(dst.id), rule.stuck_after);
                }
            }
        }
    }
    let _ = send.finish();
    Ok(())
}

async fn dial_with_retry(underlay: &Endpoint, dst: &EndpointAddr) -> Option<Connection> {
    for attempt in 0..DIAL_ATTEMPTS {
        match underlay.connect(dst.clone(), FORWARD_ALPN).await {
            Ok(conn) => return Some(conn),
            Err(error) => {
                tracing::trace!(hop = %dst.id.fmt_short(), attempt, %error, "underlay dial attempt failed");
                // Linear backoff; adjacent hops that are momentarily busy settle fast.
                n0_future::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
            }
        }
    }
    None
}

/// The `FORWARD_ALPN` accept side: read cells off each incoming uni-stream and
/// hand them to the [`Forwarder`].
#[derive(Debug, Clone)]
pub(crate) struct ForwardAcceptor {
    forwarder: Arc<Forwarder>,
}

impl ForwardAcceptor {
    pub(crate) fn new(forwarder: Arc<Forwarder>) -> Self {
        Self { forwarder }
    }

    async fn read_loop(
        self,
        upstream: UnderlayId,
        connection: Connection,
        gate: Arc<Mutex<RelayGate>>,
        mut recv: iroh::endpoint::RecvStream,
    ) {
        while let Ok(cell) = read_cell(&mut recv).await {
            let admitted = gate
                .lock()
                .expect("relay gate poisoned")
                .admits(&connection);
            if admitted {
                self.forwarder.handle_cell(cell, upstream);
            } else {
                self.forwarder.note_inbound_refusal(upstream, &connection);
            }
        }
    }
}

impl ProtocolHandler for ForwardAcceptor {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // The peer's QUIC-TLS identity: the one thing about a cell's origin its
        // sender cannot choose, and constant across every stream on this
        // connection. Every cell that arrives here is checked against it.
        let upstream = UnderlayId::new(connection.remote_id());
        let gate = Arc::new(Mutex::new(RelayGate::new(
            self.forwarder.rule.allow_relay,
            self.forwarder.underlay.id(),
            GateRole::Inbound,
        )));
        // Loop ends when the upstream hop closes the connection: normal teardown.
        while let Ok(recv) = connection.accept_uni().await {
            n0_future::task::spawn(self.clone().read_loop(
                upstream,
                connection.clone(),
                Arc::clone(&gate),
                recv,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Arc, AtomicUsize, Delivered, Duration, Forwarder, MAX_WRITERS, Ordering, RwLock,
        TransportAddr, UNRESOLVED_SEEN_CAP,
    };
    use crate::addr::{Route, RouteHop};
    use crate::role::{AppId, UnderlayId};
    use crate::test_support::relay_server;
    use crate::topology::{LinkVector, Topology};
    use crate::wire::Cell;
    use habilis_network_test_tracing::{expect_warn, test};
    use iroh::endpoint::presets;
    use iroh::endpoint::transports::{PathSelection, PathSelectionContext, PathSelector};
    use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
    use std::net::SocketAddr;
    use tokio::sync::mpsc;

    fn stranger(seed: u8) -> RouteHop {
        let id: EndpointId = SecretKey::from_bytes(&[seed; 32]).public();
        RouteHop {
            app_id: AppId::new(id),
            underlay_id: UnderlayId::new(id),
        }
    }

    /// Closes the endpoint at the end of the test, so that it does not drop open.
    fn close_at_end(endpoint: &Endpoint) {
        let endpoint = endpoint.clone();
        habilis_network_test_tracing::at_end(async move { endpoint.close().await });
    }

    /// A forwarder over a real loopback underlay, plus the delivery receiver the
    /// local transport would hold. `app_id` is a distinct key from the underlay's,
    /// as it is in production.
    async fn forwarder() -> (Forwarder, AppId, mpsc::Receiver<Delivered>) {
        let loopback: SocketAddr = "127.0.0.1:0".parse().expect("loopback addr");
        let underlay = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind_addr(loopback)
            .expect("valid bind addr")
            .bind()
            .await
            .expect("bind underlay endpoint");
        close_at_end(&underlay);
        let app_id = AppId::new(SecretKey::from_bytes(&[99; 32]).public());
        let (inbound, received) = mpsc::channel(4);
        (
            Forwarder::new(
                underlay,
                app_id,
                inbound,
                false,
                Duration::from_secs(20),
                Arc::new(RwLock::new(Topology::default())),
            ),
            app_id,
            received,
        )
    }

    /// This forwarder's own hop, as a legitimate route would name it.
    fn self_hop(forwarder: &Forwarder) -> RouteHop {
        RouteHop {
            app_id: forwarder.self_app_id,
            underlay_id: UnderlayId::new(forwarder.underlay.id()),
        }
    }

    fn cell(hops: Vec<RouteHop>, pos: u16, source: RouteHop) -> Cell {
        Cell {
            path: Route::new(hops).expect("legal route"),
            pos,
            source,
            packet: vec![1, 2, 3],
        }
    }

    fn live_writers(forwarder: &Forwarder) -> usize {
        forwarder
            .pool
            .writers
            .lock()
            .expect("writers mutex poisoned")
            .len()
    }

    #[test]
    async fn a_cell_that_ends_at_us_is_delivered_locally() {
        // The happy path the refusals below are measured against.
        let (forwarder, _app, mut received) = forwarder().await;
        let source = stranger(1);
        let subject = cell(vec![self_hop(&forwarder)], 0, source.clone());
        forwarder.handle_cell(subject, source.underlay_id);
        assert!(received.try_recv().is_ok());
        assert_eq!(
            forwarder.forwarded_cells(),
            0,
            "a delivery is not a forward"
        );
    }

    #[test]
    async fn a_cell_that_ends_at_us_is_counted_as_delivered() {
        let (forwarder, _app, _received) = forwarder().await;
        let source = stranger(1);
        let subject = cell(vec![self_hop(&forwarder)], 0, source.clone());
        forwarder.handle_cell(subject, source.underlay_id);
        let counters = forwarder.counters();
        assert_eq!(
            (counters.delivered, counters.dropped, counters.forwarded),
            (1, 0, 0)
        );
    }

    #[test]
    async fn a_full_inbox_drops_the_cell_and_counts_it() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "reason=\"inbox of the local transport is full\"",
        );
        // The inbox of the fixture holds 4 cells and nothing drains it, as on a transport
        // that is never polled: the fifth and sixth cell are lost, and the counters say so.
        let (forwarder, _app, _received) = forwarder().await;
        let source = stranger(1);
        for _ in 0..6 {
            let subject = cell(vec![self_hop(&forwarder)], 0, source.clone());
            forwarder.handle_cell(subject, source.underlay_id);
        }
        let counters = forwarder.counters();
        assert_eq!((counters.delivered, counters.dropped), (4, 2));
    }

    #[test]
    async fn a_packet_that_does_not_fit_the_buffer_is_counted_as_dropped() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "multihop transport dropping packets",
        );
        let (forwarder, _app, _received) = forwarder().await;
        forwarder.note_oversized(2000, 1500);
        assert_eq!(forwarder.counters().dropped, 1);
    }

    #[test]
    async fn a_cell_naming_another_node_is_neither_delivered_nor_forwarded() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "reason=\"position does not name this node\"",
        );
        // The reflector proper: we are nowhere on this route, so relaying it
        // would spend our bandwidth on a stranger's behalf.
        let (forwarder, _app, mut received) = forwarder().await;
        let source = stranger(1);
        let subject = cell(vec![stranger(2), stranger(3)], 0, source.clone());
        forwarder.handle_cell(subject, source.underlay_id);
        assert!(received.try_recv().is_err());
        assert_eq!(live_writers(&forwarder), 0, "no writer, no dial, no bytes");
    }

    #[test]
    async fn a_cell_from_the_wrong_upstream_is_refused() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "reason=\"cell did not arrive from its preceding hop\"",
        );
        // A hostile downstream hop bouncing a structurally valid cell back at
        // us. Every hop on this route is real and we genuinely occupy `pos`, so
        // only the authenticated sender id catches it.
        let (forwarder, _app, mut received) = forwarder().await;
        let source = stranger(1);
        let downstream = stranger(4);
        let subject = cell(
            vec![stranger(2), self_hop(&forwarder), downstream.clone()],
            1,
            source,
        );
        forwarder.handle_cell(subject, downstream.underlay_id);
        assert!(received.try_recv().is_err());
        assert_eq!(live_writers(&forwarder), 0);
    }

    #[test]
    async fn a_cell_positioned_past_the_end_is_not_delivered() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "reason=\"position past the end of the route\"",
        );
        let (forwarder, _app, mut received) = forwarder().await;
        let source = stranger(1);
        let subject = cell(vec![self_hop(&forwarder)], 7, source.clone());
        forwarder.handle_cell(subject, source.underlay_id);
        assert!(received.try_recv().is_err());
    }

    #[test]
    async fn a_cell_passing_through_us_is_queued_for_the_next_hop() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "multihop forwarder: hop without a vector that no delivered cell named",
        );
        let (forwarder, _app, mut received) = forwarder().await;
        let source = stranger(1);
        let next = stranger(5);
        let subject = cell(vec![self_hop(&forwarder), next.clone()], 0, source.clone());
        forwarder.handle_cell(subject, source.underlay_id);
        assert!(received.try_recv().is_err(), "not ours to deliver");
        assert_eq!(live_writers(&forwarder), 1);
        assert_eq!(forwarder.forwarded_cells(), 1);
    }

    #[test]
    async fn a_refused_cell_is_not_counted_as_forwarded() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "reason=\"position does not name this node\"",
        );
        let (forwarder, _app, _received) = forwarder().await;
        let source = stranger(1);
        let subject = cell(vec![stranger(2), stranger(3)], 0, source.clone());
        forwarder.handle_cell(subject, source.underlay_id);
        assert_eq!(forwarder.forwarded_cells(), 0);
    }

    /// A node whose underlay can only use the relay, as a forwarder with its
    /// accept side running.
    struct RelayNode {
        forwarder: Arc<Forwarder>,
        hop: RouteHop,
        /// The key of the application endpoint, which signs the link vector of the node.
        app_secret: SecretKey,
        /// The address that the node would advertise for its underlay.
        underlay_addr: EndpointAddr,
        received: mpsc::Receiver<Delivered>,
        _router: iroh::protocol::Router,
    }

    impl RelayNode {
        /// Make `other` known to this node, as the link vector of `other` would: signed by
        /// its application key, with its underlay address. A route names a hop by ids, and
        /// the forwarder dials the address of the topology.
        fn learns(&self, other: &RelayNode) {
            let vector = LinkVector::signed(
                &other.app_secret,
                crate::topology::wall_clock_ms(),
                other.underlay_addr.clone(),
                Vec::new(),
            );
            self.forwarder
                .topology
                .write()
                .expect("topology lock poisoned")
                .ingest(vector);
        }
    }

    async fn relay_node(seed: u8, url: &iroh::RelayUrl, allow_relay: bool) -> RelayNode {
        let underlay = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .relay_mode(RelayMode::custom([url.clone()]))
            .clear_ip_transports()
            .bind()
            .await
            .expect("bind a relay-only underlay");
        close_at_end(&underlay);
        tokio::time::timeout(Duration::from_secs(10), underlay.online())
            .await
            .expect("the underlay reaches the relay");
        let app_secret = SecretKey::from_bytes(&[seed.wrapping_add(100); 32]);
        let app_id = AppId::new(app_secret.public());
        let (inbound, received) = mpsc::channel(8);
        let forwarder = Arc::new(Forwarder::new(
            underlay.clone(),
            app_id,
            inbound,
            allow_relay,
            Duration::from_millis(300),
            Arc::new(RwLock::new(Topology::default())),
        ));
        let router = iroh::protocol::Router::builder(underlay.clone())
            .accept(
                super::FORWARD_ALPN,
                super::ForwardAcceptor::new(Arc::clone(&forwarder)),
            )
            .spawn();
        let hop = RouteHop {
            app_id,
            underlay_id: UnderlayId::new(underlay.id()),
        };
        RelayNode {
            forwarder,
            hop,
            app_secret,
            underlay_addr: underlay.addr(),
            received,
            _router: router,
        }
    }

    /// Send one cell from `from` to `to` over their underlays and say whether it
    /// arrived within a few seconds.
    async fn cell_arrives(from: &RelayNode, to: &mut RelayNode) -> bool {
        from.learns(to);
        let subject = Cell {
            path: Route::new(vec![to.hop.clone()]).expect("legal route"),
            pos: 0,
            source: from.hop.clone(),
            packet: vec![7, 7, 7],
        };
        // Retried: the first attempts can find the connection still being set up.
        for _ in 0..6 {
            from.forwarder.enqueue(&to.hop, subject.clone());
            if tokio::time::timeout(Duration::from_millis(500), to.received.recv())
                .await
                .is_ok_and(|delivered| delivered.is_some())
            {
                return true;
            }
        }
        false
    }

    #[test]
    async fn the_relay_carries_cells_when_the_mesh_lets_it() {
        let (url, _server) = relay_server().await;
        let from = relay_node(1, &url, true).await;
        let mut to = relay_node(2, &url, true).await;
        assert!(
            cell_arrives(&from, &mut to).await,
            "relay payload is allowed"
        );
    }

    #[test]
    async fn a_cell_is_not_sent_on_a_relay_selected_path() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "multihop underlay stays on the relay: this hop is not advertised as a link",
        );
        let (url, _server) = relay_server().await;
        let from = relay_node(3, &url, false).await;
        let mut to = relay_node(4, &url, true).await;
        assert!(
            !cell_arrives(&from, &mut to).await,
            "the sender refuses the relay"
        );
        assert!(
            from.forwarder.pool.refused_on_relay.load(Ordering::Relaxed) > 0,
            "and counts what it refused"
        );
    }

    #[test]
    async fn a_cell_that_arrives_on_a_relay_selected_path_is_dropped() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "reason=\"cell arrived over the relay\"",
        );
        let (url, _server) = relay_server().await;
        let from = relay_node(5, &url, true).await;
        let mut to = relay_node(6, &url, false).await;
        assert!(
            !cell_arrives(&from, &mut to).await,
            "the receiver refuses the relay"
        );
        assert!(to.forwarder.dropped.load(Ordering::Relaxed) > 0);
    }

    #[test]
    async fn a_hop_that_stays_on_the_relay_becomes_stuck() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "multihop underlay stays on the relay: this hop is not advertised as a link",
        );
        let (url, _server) = relay_server().await;
        let from = relay_node(7, &url, false).await;
        let mut to = relay_node(8, &url, true).await;
        assert!(!cell_arrives(&from, &mut to).await);
        // Refused for longer than the deadline: no longer a link.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while from.forwarder.stuck_hops().is_empty() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(from.forwarder.stuck_hops(), vec![to.hop.app_id]);
    }

    #[test]
    fn the_path_list_marks_the_selected_path_with_a_star() {
        let ip = TransportAddr::Ip("127.0.0.1:9".parse().expect("an address"));
        let relay = TransportAddr::Relay("http://127.0.0.1:1".parse().expect("a relay url"));
        let list = super::path_list([(relay, true), (ip, false)]);
        assert!(list.starts_with("Relay("), "{list}");
        assert!(list.ends_with(")* Ip(127.0.0.1:9)"), "{list}");
    }

    /// Whether `wake` holds a wake-up now.
    async fn woke(wake: &tokio::sync::Notify) -> bool {
        tokio::time::timeout(Duration::from_millis(20), wake.notified())
            .await
            .is_ok()
    }

    /// A hop of `seed`, whose node signed a vector that names `advertised` as its underlay
    /// endpoint, held by `forwarder`. The hop itself names `named`.
    fn hop_with_vector(
        forwarder: &Forwarder,
        seed: u8,
        advertised: &EndpointAddr,
        named: EndpointId,
    ) -> RouteHop {
        let app = SecretKey::from_bytes(&[seed; 32]);
        forwarder
            .topology
            .write()
            .expect("topology lock poisoned")
            .ingest(LinkVector::signed(
                &app,
                crate::topology::wall_clock_ms(),
                advertised.clone(),
                Vec::new(),
            ));
        RouteHop {
            app_id: AppId::new(app.public()),
            underlay_id: UnderlayId::new(named),
        }
    }

    #[test]
    async fn a_hop_is_dialed_at_the_address_that_its_vector_signed() {
        let (forwarder, _app, _received) = forwarder().await;
        let underlay_id = SecretKey::from_bytes(&[121; 32]).public();
        let signed = EndpointAddr::new(underlay_id)
            .with_ip_addr("10.0.0.9:4000".parse().expect("an address"));
        let hop = hop_with_vector(&forwarder, 120, &signed, underlay_id);
        assert_eq!(forwarder.dial_addr(&hop), signed);
        assert_eq!(forwarder.unresolved_hops(), 0);
    }

    #[test]
    async fn a_hop_that_the_topology_does_not_know_is_dialed_by_id_and_counted() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "multihop forwarder: hop without a vector that no delivered cell named",
        );
        let (forwarder, _app, _received) = forwarder().await;
        let hop = stranger(122);
        assert_eq!(
            forwarder.dial_addr(&hop),
            EndpointAddr::new(hop.underlay_id.get()),
            "no address is made up"
        );
        assert_eq!(forwarder.unresolved_hops(), 1);
    }

    /// Counts the WARN and ERROR events of the thread that installs it. The tests of this module
    /// run in parallel, and many of them drop an endpoint without a close, so a subscriber that
    /// is global to the binary would see the events of the other tests.
    struct CountsWarnings(Arc<AtomicUsize>);

    impl tracing::Subscriber for CountsWarnings {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() <= tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// A reply goes back along the reversed route of a cell that this node delivered, so its first
    /// hop is the sender, whose link-vector may not have arrived yet: that case is normal.
    #[test]
    async fn a_hop_without_a_vector_is_not_a_warning() {
        let (forwarder, _app, _received) = forwarder().await;
        let sender = stranger(140);
        let delivered = cell(vec![self_hop(&forwarder)], 0, sender.clone());
        forwarder.handle_cell(delivered, sender.underlay_id);
        assert_eq!(forwarder.counters().delivered, 1, "the cell was delivered");
        let warnings = Arc::new(AtomicUsize::new(0));
        tracing::subscriber::with_default(CountsWarnings(Arc::clone(&warnings)), || {
            forwarder.dial_addr(&sender);
        });
        assert_eq!(warnings.load(Ordering::Relaxed), 0);
        assert_eq!(forwarder.unresolved_hops(), 1, "the hop was counted");
        forwarder.underlay.close().await;
    }

    /// A neighbor that this node links to is a hop whose own vector has not arrived yet: the
    /// origin of a route saw it first. This node reaches the neighbor by the link it holds.
    #[test]
    async fn a_hop_without_a_vector_that_is_a_link_of_ours_is_not_a_warning() {
        let (forwarder, _app, _received) = forwarder().await;
        let neighbor = stranger(142);
        let own_key = SecretKey::from_bytes(&[99; 32]);
        let own_vector = LinkVector::signed(
            &own_key,
            crate::topology::wall_clock_ms(),
            EndpointAddr::new(forwarder.underlay.id()),
            vec![(neighbor.app_id, 1)],
        );
        assert!(
            forwarder
                .topology
                .write()
                .expect("topology lock poisoned")
                .ingest(own_vector),
            "the vector of this node is accepted"
        );
        let warnings = Arc::new(AtomicUsize::new(0));
        tracing::subscriber::with_default(CountsWarnings(Arc::clone(&warnings)), || {
            forwarder.dial_addr(&neighbor);
            forwarder.dial_addr(&stranger(143));
        });
        assert_eq!(
            warnings.load(Ordering::Relaxed),
            1,
            "the hop that is no link of ours is the only warning"
        );
        forwarder.underlay.close().await;
    }

    /// A hop that no delivered cell named, and that has no vector, is not explained by a reply on
    /// a reversed route: it is a warning, once.
    #[test]
    async fn a_hop_without_a_vector_that_no_delivered_cell_named_is_a_warning() {
        let (forwarder, _app, _received) = forwarder().await;
        let warnings = Arc::new(AtomicUsize::new(0));
        tracing::subscriber::with_default(CountsWarnings(Arc::clone(&warnings)), || {
            forwarder.dial_addr(&stranger(141));
            forwarder.dial_addr(&stranger(141));
        });
        assert_eq!(warnings.load(Ordering::Relaxed), 1, "one line per hop");
        assert_eq!(forwarder.unresolved_hops(), 2, "both lookups were counted");
        forwarder.underlay.close().await;
    }

    #[test]
    async fn a_hop_without_a_vector_is_logged_once_each() {
        let (forwarder, _app, _received) = forwarder().await;
        let (one, other) = (stranger(130).underlay_id, stranger(131).underlay_id);
        assert!(forwarder.line_is_due(one, 1, false), "the first hop");
        assert!(!forwarder.line_is_due(one, 2, false), "the same hop again");
        assert!(forwarder.line_is_due(other, 3, false), "another hop");
        // Past the ceiling the rule is one line in 256.
        for seed in 0..u8::try_from(UNRESOLVED_SEEN_CAP).expect("fits") {
            let id = SecretKey::from_bytes(&[seed.wrapping_add(1); 32]).public();
            forwarder.line_is_due(UnderlayId::new(id), 4, false);
        }
        let beyond = stranger(200).underlay_id;
        assert!(!forwarder.line_is_due(beyond, 5, false), "past the ceiling");
        assert!(forwarder.line_is_due(beyond, 256, false), "one in 256");
    }

    /// A hop that was explained once, by a link of this node, is warned about when the link is
    /// gone and nothing else explains it: the line at debug does not spend the warning of the hop.
    #[test]
    async fn a_hop_explained_by_a_link_that_is_gone_is_warned_about() {
        let (forwarder, _app, _received) = forwarder().await;
        let neighbor = stranger(144);
        let own_key = SecretKey::from_bytes(&[99; 32]);
        let own_vector = LinkVector::signed(
            &own_key,
            crate::topology::wall_clock_ms(),
            EndpointAddr::new(forwarder.underlay.id()),
            vec![(neighbor.app_id, 1)],
        );
        assert!(
            forwarder
                .topology
                .write()
                .expect("topology lock poisoned")
                .ingest(own_vector),
            "the vector of this node is accepted"
        );
        let warnings = Arc::new(AtomicUsize::new(0));
        tracing::subscriber::with_default(CountsWarnings(Arc::clone(&warnings)), || {
            forwarder.dial_addr(&neighbor);
        });
        assert_eq!(warnings.load(Ordering::Relaxed), 0, "a link of ours");

        assert!(
            forwarder
                .topology
                .write()
                .expect("topology lock poisoned")
                .remove(forwarder.self_app_id),
            "the vector of this node is removed"
        );
        tracing::subscriber::with_default(CountsWarnings(Arc::clone(&warnings)), || {
            forwarder.dial_addr(&neighbor);
            forwarder.dial_addr(&neighbor);
        });
        assert_eq!(
            warnings.load(Ordering::Relaxed),
            1,
            "warned once, after the link is gone"
        );
        forwarder.underlay.close().await;
    }

    /// A hop whose vector this node held and removed, because the peer left or its vector
    /// expired, is still named by the cells in flight to it: the origin of the route is behind,
    /// and the hop is no warning. A hop that this node never knew stays one.
    #[test]
    async fn a_hop_whose_vector_is_gone_is_not_a_warning() {
        let (forwarder, _app, _received) = forwarder().await;
        let gone_key = SecretKey::from_bytes(&[145; 32]);
        let gone = RouteHop {
            app_id: AppId::new(gone_key.public()),
            underlay_id: UnderlayId::new(gone_key.public()),
        };
        let vector = LinkVector::signed(
            &gone_key,
            crate::topology::wall_clock_ms(),
            EndpointAddr::new(gone.underlay_id.get()),
            vec![],
        );
        {
            let mut topology = forwarder.topology.write().expect("topology lock poisoned");
            assert!(topology.ingest(vector), "the vector is accepted");
            assert!(topology.remove(gone.app_id), "the vector is removed");
        }
        let warnings = Arc::new(AtomicUsize::new(0));
        tracing::subscriber::with_default(CountsWarnings(Arc::clone(&warnings)), || {
            forwarder.dial_addr(&gone);
            forwarder.dial_addr(&stranger(146));
        });
        assert_eq!(
            warnings.load(Ordering::Relaxed),
            1,
            "the hop that was never known is the only warning"
        );
        assert_eq!(forwarder.unresolved_hops(), 2, "both hops were counted");
        forwarder.underlay.close().await;
    }

    /// The hops that delivered cells named are remembered past [`HEARD_HOPS_CAP`]: the oldest
    /// hop is forgotten, and a reply to the newest cell is explained.
    #[test]
    async fn a_hop_named_by_a_cell_past_the_heard_cap_is_not_a_warning() {
        let (forwarder, _app, mut received) = forwarder().await;
        let hop = |seed: u16| {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&seed.to_be_bytes());
            bytes[2] = 7;
            let id = SecretKey::from_bytes(&bytes).public();
            RouteHop {
                app_id: AppId::new(id),
                underlay_id: UnderlayId::new(id),
            }
        };
        let cap = u16::try_from(super::HEARD_HOPS_CAP).expect("fits");
        for seed in 0..=cap {
            let sender = hop(seed);
            let delivered = cell(vec![self_hop(&forwarder)], 0, sender.clone());
            forwarder.handle_cell(delivered, sender.underlay_id);
            received.try_recv().expect("delivered");
        }
        let newest = hop(cap);
        let warnings = Arc::new(AtomicUsize::new(0));
        tracing::subscriber::with_default(CountsWarnings(Arc::clone(&warnings)), || {
            forwarder.dial_addr(&newest);
        });
        assert_eq!(
            warnings.load(Ordering::Relaxed),
            0,
            "the newest delivered cell named the hop"
        );
        forwarder.underlay.close().await;
    }

    #[test]
    async fn a_vector_that_names_another_underlay_does_not_resolve_the_hop() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "multihop forwarder: hop without a vector that no delivered cell named",
        );
        // The route says the underlay of this node is `named`; the node signed another.
        // The address of the vector is not the address of the hop.
        let (forwarder, _app, _received) = forwarder().await;
        let signed = EndpointAddr::new(SecretKey::from_bytes(&[124; 32]).public())
            .with_ip_addr("10.0.0.9:4000".parse().expect("an address"));
        let named = SecretKey::from_bytes(&[125; 32]).public();
        let hop = hop_with_vector(&forwarder, 123, &signed, named);
        assert_eq!(forwarder.dial_addr(&hop), EndpointAddr::new(named));
        assert_eq!(forwarder.unresolved_hops(), 1);
    }

    #[test]
    async fn the_pool_wakes_at_the_first_refusal_of_a_hop_and_at_its_recovery() {
        let (hop, app) = (stranger(13).underlay_id, stranger(14).app_id);
        let pool = super::WriterPool::default();
        let wake = Arc::clone(&pool.route_wake);
        pool.track(hop, app);
        assert!(!woke(&wake).await, "a hop that was never refused");
        pool.note_admitted(hop);
        assert!(!woke(&wake).await, "an admitted hop that was not refused");

        pool.note_refused(hop, Duration::from_mins(1));
        assert!(woke(&wake).await, "the first refusal");
        pool.note_refused(hop, Duration::from_mins(1));
        pool.note_refused(hop, Duration::from_mins(1));
        assert!(!woke(&wake).await, "a refusal that goes on is not news");

        pool.note_admitted(hop);
        assert!(woke(&wake).await, "the recovery of a refused hop");
        pool.note_admitted(hop);
        assert!(!woke(&wake).await, "an admitted hop that stays admitted");
    }

    #[test]
    fn a_stuck_hop_is_a_link_again_once_it_is_admitted() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "multihop underlay stays on the relay: this hop is not advertised as a link",
        );
        let (hop, app) = (stranger(11).underlay_id, stranger(12).app_id);
        let pool = super::WriterPool::default();
        pool.track(hop, app);
        pool.note_refused(hop, Duration::ZERO);
        assert_eq!(pool.stuck_app_ids(), vec![app], "refused past the deadline");
        pool.note_admitted(hop);
        assert!(pool.stuck_app_ids().is_empty(), "admitted: a link again");
        pool.note_refused(hop, Duration::from_mins(1));
        assert!(
            pool.stuck_app_ids().is_empty(),
            "a fresh refusal is not yet stuck"
        );
    }

    /// A node whose underlay is on loopback, with its accept side running: the
    /// path between two of these is direct.
    async fn loopback_node(seed: u8, stuck_after: Duration) -> RelayNode {
        loopback_node_with(seed, stuck_after, None).await
    }

    /// A [`loopback_node`] whose underlay chooses its paths with `selector`.
    async fn loopback_node_with(
        seed: u8,
        stuck_after: Duration,
        selector: Option<Arc<dyn PathSelector>>,
    ) -> RelayNode {
        let loopback: SocketAddr = "127.0.0.1:0".parse().expect("loopback addr");
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .relay_mode(RelayMode::Disabled)
            .bind_addr(loopback)
            .expect("valid bind addr");
        if let Some(selector) = selector {
            builder = builder.path_selector(selector);
        }
        let underlay = builder.bind().await.expect("bind a loopback underlay");
        close_at_end(&underlay);
        let app_secret = SecretKey::from_bytes(&[seed.wrapping_add(100); 32]);
        let app_id = AppId::new(app_secret.public());
        let (inbound, received) = mpsc::channel(8);
        let forwarder = Arc::new(Forwarder::new(
            underlay.clone(),
            app_id,
            inbound,
            false,
            stuck_after,
            Arc::new(RwLock::new(Topology::default())),
        ));
        let router = iroh::protocol::Router::builder(underlay.clone())
            .accept(
                super::FORWARD_ALPN,
                super::ForwardAcceptor::new(Arc::clone(&forwarder)),
            )
            .spawn();
        let hop = RouteHop {
            app_id,
            underlay_id: UnderlayId::new(underlay.id()),
        };
        RelayNode {
            forwarder,
            hop,
            app_secret,
            underlay_addr: underlay.addr(),
            received,
            _router: router,
        }
    }

    /// A selector that never selects a path. iroh opens paths only from the dialling
    /// end, so on the accepting end the chosen path can be none of those open.
    #[derive(Debug)]
    struct NeverSelects;

    impl PathSelector for NeverSelects {
        fn select(&self, _ctx: &PathSelectionContext<'_>) -> PathSelection {
            PathSelection::none()
        }
    }

    fn ip(port: u16) -> TransportAddr {
        TransportAddr::Ip(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn relay() -> TransportAddr {
        TransportAddr::Relay("http://127.0.0.1:1".parse().expect("a relay url"))
    }

    #[test]
    fn an_accepted_connection_is_direct_when_any_open_path_is_not_the_relay() {
        use super::{direct_for_inbound, direct_for_writer};
        assert!(
            direct_for_inbound(&[(ip(9), false), (relay(), false)]),
            "an IP path in backup beside the relay in backup"
        );
        assert!(direct_for_inbound(&[(ip(9), true), (relay(), false)]));
        assert!(
            !direct_for_inbound(&[(relay(), false)]),
            "only the relay is open"
        );
        assert!(
            !direct_for_inbound(&[(relay(), true)]),
            "only the relay, selected"
        );
        assert!(!direct_for_inbound(&[]), "no path is open");
        // The writer keeps the stricter rule: it sends on the selected path.
        assert!(!direct_for_writer(&[(ip(9), false), (relay(), false)]));
        assert!(direct_for_writer(&[(ip(9), true), (relay(), false)]));
    }

    /// A test cut takes a path away from the selector, and iroh does not select again for a
    /// connection that already stands on it. The gate must read the cut itself: a path that the
    /// test blocked is not a direct path, so that a live writer gives the hop up.
    #[test]
    fn a_selected_direct_path_that_a_test_blocked_is_not_a_direct_path() {
        use super::{direct_for_writer, unblocked};
        let paths = vec![(ip(9), true), (relay(), false)];
        assert!(
            direct_for_writer(&paths),
            "before the cut the writer is admitted"
        );
        assert!(
            !direct_for_writer(unblocked(&paths, |path| *path == ip(9))),
            "the blocked path is gone, and nothing direct is selected"
        );
        assert!(
            unblocked(&paths, |path| *path == ip(9)).any(|(path, _)| *path == relay()),
            "the relay stays in the list"
        );
    }

    #[test]
    fn the_accepting_end_gives_up_a_path_that_a_test_blocked_too() {
        use super::{direct_for_inbound, unblocked};
        let paths = vec![(ip(9), false), (relay(), false)];
        assert!(direct_for_inbound(&paths));
        assert!(
            !direct_for_inbound(unblocked(&paths, |path| matches!(
                path,
                TransportAddr::Ip(_)
            ))),
            "only the relay is left, and it is not direct"
        );
    }

    #[test]
    fn a_path_that_no_test_blocked_is_kept() {
        use super::unblocked;
        let paths = vec![(ip(9), true), (relay(), false)];
        assert_eq!(
            unblocked(&paths, |_| false).cloned().collect::<Vec<_>>(),
            paths
        );
    }

    #[test]
    fn an_ip_path_that_a_test_blocked_for_this_node_is_blocked() {
        use super::blocked_by_test;
        use habilis_network_iroh_transport_util::block_ip_to;
        let local = SecretKey::from_bytes(&[141; 32]).public();
        let other = SecretKey::from_bytes(&[142; 32]).public();
        block_ip_to(local, [9]);
        assert!(blocked_by_test(local, &ip(9)), "the blocked port");
        assert!(!blocked_by_test(local, &ip(10)), "another port");
        assert!(!blocked_by_test(local, &relay()), "the relay");
        assert!(!blocked_by_test(other, &ip(9)), "another node");
        block_ip_to(local, []);
        assert!(!blocked_by_test(local, &ip(9)), "an empty set clears");
    }

    #[test]
    fn a_webrtc_path_that_a_test_blocked_toward_one_remote_is_blocked() {
        use super::blocked_by_test;
        use habilis_network_iroh_transport_util::{Rung, WEBRTC_TRANSPORT_ID, block_rung_to};
        use iroh_base::CustomAddr;
        let local = SecretKey::from_bytes(&[143; 32]).public();
        let cut = SecretKey::from_bytes(&[144; 32]).public();
        let kept = SecretKey::from_bytes(&[145; 32]).public();
        let webrtc = |remote: EndpointId| {
            TransportAddr::Custom(CustomAddr::from_parts(
                WEBRTC_TRANSPORT_ID,
                remote.as_bytes(),
            ))
        };
        block_rung_to(local, Rung::WebRtc, cut, true);
        assert!(blocked_by_test(local, &webrtc(cut)), "the cut remote");
        assert!(!blocked_by_test(local, &webrtc(kept)), "another remote");
        assert!(!blocked_by_test(local, &ip(9)), "another rung");
        block_rung_to(local, Rung::WebRtc, cut, false);
        assert!(!blocked_by_test(local, &webrtc(cut)), "cleared");
    }

    #[test]
    async fn a_cell_arrives_when_the_accepting_end_selected_no_path() {
        // The dialling end sends on a selected IP path. The accepting end opened no
        // path of its own and selects none, but its connection has the IP path open.
        let stuck_after = Duration::from_millis(300);
        let from = loopback_node(31, stuck_after).await;
        let mut to = loopback_node_with(32, stuck_after, Some(Arc::new(NeverSelects))).await;
        assert!(
            cell_arrives(&from, &mut to).await,
            "a cell that came over IP is not a cell over the relay"
        );
        assert_eq!(to.forwarder.dropped.load(Ordering::Relaxed), 0);
        assert_eq!(
            from.forwarder.pool.refused_on_relay.load(Ordering::Relaxed),
            0,
            "and the writer did not refuse the relay on the way"
        );
    }

    #[test]
    async fn a_writer_retires_when_its_connection_closes_under_it() {
        // A direct hop, then the far underlay goes away while no cell is in
        // flight. The writer must see the close: a dead connection read as one
        // with no direct path would mark the hop stuck and never end the writer.
        let stuck_after = Duration::from_millis(300);
        let from = loopback_node(21, stuck_after).await;
        let mut to = loopback_node(22, stuck_after).await;
        assert!(cell_arrives(&from, &mut to).await, "the hop is direct");
        assert_eq!(live_writers(&from.forwarder), 1, "a writer carries it");

        to.forwarder.underlay.close().await;

        // Longer than the deadline and the one-second tick, twice over.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while live_writers(&from.forwarder) > 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            live_writers(&from.forwarder),
            0,
            "the writer retires with its connection"
        );
        assert!(
            from.forwarder.stuck_hops().is_empty(),
            "a hop whose connection closed is not stuck on the relay"
        );
    }

    #[test]
    async fn a_writer_retires_itself_and_releases_its_bytes_when_it_gives_up() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "multihop forwarder: hop without a vector that no delivered cell named",
        );
        // The unpruned-map leak: every next-hop id a peer ever names used to
        // leave an entry behind, and its queued bytes charged, for the life of
        // the process. The hop here is unreachable, so the writer gives up after
        // its dial backoff and must clean up after itself.
        let (forwarder, _app, _received) = forwarder().await;
        let source = stranger(1);
        let next = stranger(7);
        forwarder.enqueue(&next, cell(vec![next.clone()], 0, source));
        assert_eq!(live_writers(&forwarder), 1, "writer spawned");

        // DIAL_ATTEMPTS with linear backoff is ~1s; allow margin.
        for _ in 0..40 {
            if live_writers(&forwarder) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(live_writers(&forwarder), 0, "writer retired its own entry");
        assert_eq!(
            forwarder.pool.queued_bytes.load(Ordering::Relaxed),
            0,
            "a dead hop must not hold the shared byte budget"
        );
    }

    #[test]
    async fn writer_spawns_stop_at_the_ceiling() {
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "multihop forwarder: hop without a vector that no delivered cell named",
        );
        expect_warn(
            "habilis_network_iroh_multihop_transport::underlay",
            "reason=\"next-hop writer ceiling reached\"",
        );
        // Each cell names a fresh next hop, which is how a remote peer turns an
        // unpruned writer map into unbounded tasks and dials.
        let (forwarder, _app, _received) = forwarder().await;
        let source = stranger(1);
        for seed in 0..u8::try_from(MAX_WRITERS + 8).expect("fits") {
            let next = stranger(seed.wrapping_add(100));
            if next.underlay_id == UnderlayId::new(forwarder.underlay.id()) {
                continue;
            }
            forwarder.enqueue(&next, cell(vec![next.clone()], 0, source.clone()));
        }
        assert!(live_writers(&forwarder) <= MAX_WRITERS);
    }

    /// A test cut reaches a gate at once. The reading of the paths stands for `PATH_RECHECK`,
    /// but a cut made inside that span must not: the cell would leave on the relay, and the
    /// forwarder at the other end would refuse it.
    #[test]
    fn a_writer_gate_refuses_at_once_when_a_test_cuts_the_selected_path() {
        use super::{GateRole, RelayGate};
        use habilis_network_iroh_transport_util::{Rung, block_rung};

        let local: EndpointId = SecretKey::from_bytes(&[41; 32]).public();
        let relay: iroh::RelayUrl = "http://127.0.0.1:1".parse().expect("relay url");
        let ip: SocketAddr = "127.0.0.1:2".parse().expect("ip addr");
        let paths = || {
            vec![
                (TransportAddr::Relay(relay.clone()), false),
                (TransportAddr::Ip(ip), true),
            ]
        };
        let mut gate = RelayGate::new(false, local, GateRole::Writer);
        assert!(gate.admits_paths(paths), "a selected IP path admits");

        block_rung(local, Rung::Ip, true);
        let admitted = gate.admits_paths(paths);
        block_rung(local, Rung::Ip, false);

        assert!(
            !admitted,
            "a cut IP path must not admit, even inside the recheck span"
        );
    }
}
