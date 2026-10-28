//! A `WebRTC` leg on the multihop underlay, so that a cell can be forwarded over a
//! session between two members that have no IP path to each other.
//!
//! The underlay is an endpoint of its own with its own key. It gets its own
//! `WebRtcHandle`, its own admission table (cap G) and the signal protocol on
//! its router. A session opens only to a member whose application path is
//! `WebRTC`: where IP works, the underlay reaches the member over IP already. A
//! node without `udp` has an underlay with no IP socket, and a session opens to
//! every member it holds a link vector from.
//!
//! The members are read from the roster, not from the live gossip links. The
//! relay watcher closes a gossip link on purpose, and a route that other
//! members use must not end with it. So there is one session per known member
//! that needs one, and the cap of the admission table bounds them.

use crate::transport::UdpTransport;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointId};

use super::webrtc::close_code::NOT_A_NEIGHBOR;
use super::{LOG_TARGET, SignalAdmission, WebRtcSignalAcceptor};

use crate::daemon::state;
use iroh::address_lookup::memory;
/// How long the task of an offer that was turned away as not a neighbor keeps its slot, the first
/// time in a row. Its end wakes the event loop, which offers again: the answerer reads our link
/// vector a few milliseconds after our offer reaches it, so the second offer finds us a neighbor,
/// and the alive tick (30 s) would be too late for the route that the session carries. A peer
/// that turns us away again goes through the backoff of the admission table.
const REFUSAL_RETRY: Duration = Duration::from_secs(1);

/// What one tick does with the sessions of the underlay.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Underlay ids to offer a session to.
    pub(crate) dial: Vec<EndpointId>,
    /// Underlay ids whose session is no longer wanted.
    pub(crate) detach: Vec<EndpointId>,
}

/// Decide the sessions of the underlay. `room` is how many new offers the table of sessions admits
/// now (see `SignalAdmission::room`): the lowest ids that are wanted go first, and the others wait for
/// a later tick. `wanted` are the underlay ids of the
/// neighbors that need a session (see [`wanted_underlays`]), and `kept` those whose session
/// stays, that is every neighbor that is not on IP; `held` are the ids with a live
/// session, and `local` is our own underlay id. The lower id dials, so exactly one
/// offer crosses per pair. A session goes only when its neighbor is no longer one
/// or when the pair climbed to IP: an application path that is not read for the
/// moment (an idle connection of the pool closed, say) does not end it, since the
/// session carries the edge of a route that other members use.
pub(crate) fn plan(
    local: EndpointId,
    wanted: &[EndpointId],
    kept: &[EndpointId],
    held: &[EndpointId],
    room: usize,
) -> Plan {
    let mut dial: Vec<EndpointId> = wanted
        .iter()
        .copied()
        .filter(|peer| local < *peer && !held.contains(peer))
        .collect();
    // Sorted, so that a cap that bites picks the same peers on each run.
    dial.sort_unstable();
    dial.truncate(room);
    let detach = held
        .iter()
        .copied()
        .filter(|peer| !kept.contains(peer))
        .collect();
    Plan { dial, detach }
}

/// The neighbors that need a session on the underlay: those whose application
/// path is `WebRTC`. `neighbors` pairs each gossip neighbor with its underlay
/// address, and `kind_of` gives the selected path of the application pair.
/// A neighbor that left the list, or whose path climbed to IP, is not wanted, so
/// `plan` detaches its session.
///
/// A node without `udp` has an underlay with no IP socket, so no neighbor reaches it over IP
/// and the session is the only path of the underlay to every neighbor, whatever the
/// application path is. The same holds from the other side: a neighbor whose underlay address
/// has no IP entry (a node without `udp`, read from its signed link vector) is wanted, since
/// it can only be reached by a session. [`plan`] dials only from the lower id, so each end
/// has to want the pair for the lower one to offer.
fn wanted_underlays(
    neighbors: &[(EndpointId, iroh::EndpointAddr)],
    local_has_udp: UdpTransport,
    kind_of: impl Fn(EndpointId) -> Option<super::probe::PathKind>,
) -> Vec<iroh::EndpointAddr> {
    if local_has_udp == UdpTransport::Absent {
        return neighbors.iter().map(|(_, addr)| addr.clone()).collect();
    }
    neighbors
        .iter()
        .filter(|(member, addr)| {
            kind_of(*member) == Some(super::probe::PathKind::WebRtc)
                || addr.ip_addrs().next().is_none()
        })
        .map(|(_, addr)| addr.clone())
        .collect()
}

/// The neighbors that a test did not deny. A denied member gets no underlay session: it is not
/// offered one, it is not allowed to open one, and one that exists is detached.
fn undenied(
    neighbors: Vec<(EndpointId, iroh::EndpointAddr)>,
    is_denied: impl Fn(EndpointId) -> bool,
) -> Vec<(EndpointId, iroh::EndpointAddr)> {
    neighbors
        .into_iter()
        .filter(|(member, _)| !is_denied(*member))
        .collect()
}

/// The neighbors whose session stays: all of them except those whose application
/// path is on IP, where the underlay reaches the neighbor over IP already.
fn kept_underlays(
    neighbors: &[(EndpointId, iroh::EndpointAddr)],
    kind_of: impl Fn(EndpointId) -> Option<super::probe::PathKind>,
) -> Vec<EndpointId> {
    neighbors
        .iter()
        .filter(|(member, _)| kind_of(*member) != Some(super::probe::PathKind::Ip))
        .map(|(_, addr)| addr.id)
        .collect()
}

/// The underlay ids that may open a session with us now: the underlay ids of the
/// members we hold a link vector from. The event loop refreshes it on each tick.
#[derive(Debug, Clone, Default)]
pub(crate) struct Allowed(Arc<Mutex<HashSet<EndpointId>>>);

impl Allowed {
    pub(crate) fn replace(&self, ids: HashSet<EndpointId>) {
        *self.0.lock().expect("allowed set poisoned") = ids;
    }

    pub(crate) fn contains(&self, id: &EndpointId) -> bool {
        self.0.lock().expect("allowed set poisoned").contains(id)
    }
}

/// The signal acceptor of the underlay. It answers only a neighbor: a signal
/// proves the underlay id and nothing more, and the signed link-vector of a
/// neighbor is what binds that id to a member.
#[derive(Debug, Clone)]
pub(crate) struct UnderlaySignalGate {
    inner: WebRtcSignalAcceptor,
    allowed: Allowed,
}

impl UnderlaySignalGate {
    pub(crate) fn new(inner: WebRtcSignalAcceptor, allowed: Allowed) -> Self {
        Self { inner, allowed }
    }
}

impl ProtocolHandler for UnderlaySignalGate {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        if !self.allowed.contains(&connection.remote_id()) {
            tracing::debug!(target: LOG_TARGET, peer = %connection.remote_id(), "underlay signal refused: not a neighbor");
            connection.close(NOT_A_NEIGHBOR.into(), b"not a neighbor");
            return Ok(());
        }
        self.inner.accept(connection).await
    }
}

/// [`tick`] now, when the engine learns something that changes the neighbors or
/// their paths (a neighbor came up, a path changed), without waiting for the alive
/// tick. A hop that stays on the relay is withdrawn from the vector after 20 s,
/// so a session offered 30 s late would come too late for the route it carries.
/// It does nothing for a node that has no underlay leg.
pub(crate) fn tick_now(state: &state::EventLoopState) {
    if let Some(underlay) = state.underlay_webrtc.as_ref() {
        tick(state, underlay);
    }
}

/// The members that the underlay can name, less the denied ones. The underlay address of a
/// member is in its signed link-vector, and a member we hold no vector from yet is skipped: it
/// gets one on a later tick.
fn neighbors_of(
    state: &state::EventLoopState,
    multihop: &habilis_network_iroh_multihop_transport::MultihopHandle,
) -> Vec<(EndpointId, iroh::EndpointAddr)> {
    let mut neighbors: Vec<(EndpointId, iroh::EndpointAddr)> = Vec::new();
    for member in state.peer_endpoints.values().map(|addr| addr.id) {
        if let Some(addr) =
            multihop.underlay_addr_of(habilis_network_iroh_multihop_transport::AppId::new(member))
        {
            neighbors.push((member, addr));
        }
    }
    undenied(neighbors, |member| state.webrtc_admission.is_denied(member))
}

/// One alive tick: offer a session to each neighbor that needs one, and drop the
/// sessions that no neighbor needs. A neighbor needs one when its application
/// path is `WebRTC`; see the module note.
pub(crate) fn tick(state: &state::EventLoopState, underlay: &UnderlayWebRtc) {
    let Some(multihop) = state.multihop() else {
        return;
    };
    let neighbors = neighbors_of(state, multihop);
    underlay
        .allowed
        .replace(neighbors.iter().map(|(_, addr)| addr.id).collect());

    let wanted_addrs = wanted_underlays(&neighbors, state.local_udp_transport, |member| {
        state.pair_path_kind(member)
    });
    let wanted: Vec<EndpointId> = wanted_addrs.iter().map(|addr| addr.id).collect();
    let kept = kept_underlays(&neighbors, |member| state.pair_path_kind(member));
    let held = underlay.handle.live_peer_ids().collect::<Vec<_>>();
    let Plan { dial, detach } = plan(
        underlay.endpoint.id(),
        &wanted,
        &kept,
        &held,
        underlay.admission.room(),
    );
    tracing::debug!(
        target: LOG_TARGET,
        local = %underlay.endpoint.id().fmt_short(),
        linked = state.linked_endpoints.len(),
        members = neighbors.len(),
        kinds = ?neighbors
            .iter()
            .map(|(member, _)| (member.fmt_short().to_string(), state.pair_path_kind(*member)))
            .collect::<Vec<_>>(),
        wanted = wanted.len(),
        kept = kept.len(),
        held = held.len(),
        dial = dial.len(),
        detach = detach.len(),
        "underlay tick"
    );

    for peer in &wanted {
        if !held.contains(peer) && !dial.contains(peer) {
            tracing::debug!(target: LOG_TARGET, %peer, "wanted, but the neighbor is the one that offers");
        }
    }
    for peer in detach {
        if underlay.handle.detach(&peer) {
            tracing::debug!(target: LOG_TARGET, %peer, "underlay session detached: its member left the roster, or the pair is on IP");
        }
    }
    for peer in dial {
        let Some(addr) = wanted_addrs.iter().find(|addr| addr.id == peer) else {
            continue;
        };
        let guard = match underlay.admission.try_admit(peer, &underlay.handle) {
            Ok(guard) => guard,
            Err(reason) => {
                tracing::debug!(target: LOG_TARGET, %peer, ?reason, "not offering an underlay session");
                continue;
            }
        };
        let (endpoint, book, handle, admission) = (
            underlay.endpoint.clone(),
            underlay.book.clone(),
            underlay.handle.clone(),
            underlay.admission.clone(),
        );
        let addr = addr.clone();
        let ice = state.webrtc_ice;
        let epoch = guard.epoch();
        let task = n0_future::task::spawn(async move {
            let _guard = guard;
            match Box::pin(super::webrtc::dial_signal(
                &endpoint, &book, addr, &handle, ice,
            ))
            .await
            {
                Ok(()) => {
                    admission.note_success(peer);
                    // The acceptor of the other side nudges when it takes the
                    // session; the dialer must too. An underlay connection that
                    // was dialed before the session learns the address of the
                    // session only from a dial that names it, and iroh does not
                    // ask the lookup again for a remote it already knows.
                    super::webrtc::nudge_session(&endpoint, peer).await;
                }
                Err(error) => {
                    if matches!(error, crate::lookup::EndpointError::CapRefused { .. }) {
                        admission.note_refused(peer);
                    }
                    tracing::debug!(target: LOG_TARGET, %peer, %error, "underlay webrtc offer failed");
                    // The guard of the round is held for the delay: its end rings the table, and
                    // the loop ticks and offers again (see `event_loop`). A second turn-away in
                    // a row is noted as a refusal: the peer waits, and the round ends at once.
                    if matches!(error, crate::lookup::EndpointError::NotANeighbor { .. })
                        && admission.note_not_a_neighbor(peer)
                    {
                        n0_future::time::sleep(REFUSAL_RETRY).await;
                    }
                }
            }
        });
        underlay.admission.track(peer, epoch, task.abort_handle());
    }
}

/// The members whose underlay holds a live session with us, by member id. `neighbors` pairs each
/// member with its underlay address, and `held` are the underlay ids with a live session.
pub(crate) fn members_with_session(
    neighbors: &[(EndpointId, iroh::EndpointAddr)],
    held: &[EndpointId],
) -> Vec<EndpointId> {
    neighbors
        .iter()
        .filter(|(_, addr)| held.contains(&addr.id))
        .map(|(member, _)| *member)
        .collect()
}

/// The members with a live session on our underlay, by member id: the edges of the routing graph
/// that a session carries, whether or not a gossip link to the member is up. Empty when the
/// node has no multihop handle.
pub(crate) fn held_members(
    state: &state::EventLoopState,
    underlay: &UnderlayWebRtc,
) -> Vec<EndpointId> {
    let Some(multihop) = state.multihop() else {
        return Vec::new();
    };
    members_with_session(
        &neighbors_of(state, multihop),
        &underlay.handle.live_peer_ids().collect::<Vec<_>>(),
    )
}

/// What the event loop keeps of the `WebRTC` leg of the underlay.
#[derive(Debug, Clone)]
pub(crate) struct UnderlayWebRtc {
    pub(crate) handle: habilis_network_iroh_webrtc_transport::WebRtcHandle,
    pub(crate) admission: SignalAdmission,
    pub(crate) endpoint: Endpoint,
    /// The address book of `endpoint`: the sessions of the underlay are named in it.
    pub(crate) book: memory::MemoryLookup,
    pub(crate) allowed: Allowed,
}

#[cfg(test)]
mod tests {
    use crate::transport::UdpTransport;
    use habilis_network_test_tracing::test;
    use iroh::{EndpointId, SecretKey};

    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::{Endpoint, EndpointAddr, RelayMode};

    use super::{
        Allowed, Plan, UnderlaySignalGate, kept_underlays, members_with_session, plan, undenied,
        wanted_underlays,
    };
    use crate::transport::probe::PathKind;
    use crate::transport::{
        IceProfile, MESH_WEBRTC_SIGNAL_ALPN, SignalAdmission, WebRtcSignalAcceptor,
    };

    use crate::transport::webrtc;
    fn id(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// Two ids, the lower first.
    fn ordered() -> (EndpointId, EndpointId) {
        let (first, second) = (id(1), id(2));
        if first < second {
            (first, second)
        } else {
            (second, first)
        }
    }

    #[test]
    fn the_lower_id_dials_a_wanted_neighbor_with_no_session() {
        let (low, high) = ordered();
        assert_eq!(
            plan(low, &[high], &[high], &[], usize::MAX),
            Plan {
                dial: vec![high],
                detach: vec![]
            }
        );
    }

    #[test]
    fn the_higher_id_waits_to_be_dialed() {
        let (low, high) = ordered();
        assert_eq!(plan(high, &[low], &[low], &[], usize::MAX), Plan::default());
    }

    #[test]
    fn a_neighbor_that_has_a_session_is_not_dialed_again() {
        let (low, high) = ordered();
        assert_eq!(
            plan(low, &[high], &[high], &[high], usize::MAX),
            Plan::default()
        );
    }

    #[test]
    fn a_session_with_a_peer_that_is_not_kept_is_detached() {
        let (low, high) = ordered();
        assert_eq!(
            plan(low, &[], &[], &[high], usize::MAX),
            Plan {
                dial: vec![],
                detach: vec![high]
            }
        );
    }

    #[test]
    fn a_session_with_a_kept_peer_stays_even_when_it_is_not_wanted() {
        let (low, high) = ordered();
        assert_eq!(
            plan(low, &[], &[high], &[high], usize::MAX),
            Plan::default()
        );
    }

    fn neighbor_kinds(
        walking: EndpointId,
        on_ip: EndpointId,
        on_relay: EndpointId,
    ) -> impl Fn(EndpointId) -> Option<PathKind> {
        move |member| {
            if member == walking {
                Some(PathKind::WebRtc)
            } else if member == on_ip {
                Some(PathKind::Ip)
            } else if member == on_relay {
                Some(PathKind::Relay)
            } else {
                None
            }
        }
    }

    #[test]
    fn only_a_neighbor_whose_application_path_is_webrtc_is_wanted() {
        let (webrtc, ip, relay, unknown) = (id(11), id(12), id(13), id(14));
        let neighbors: Vec<(EndpointId, EndpointAddr)> = [webrtc, ip, relay, unknown]
            .into_iter()
            .map(|member| (member, reachable_over_ip(id(member.as_bytes()[0] ^ 0x55))))
            .collect();
        let wanted = wanted_underlays(
            &neighbors,
            UdpTransport::Present,
            neighbor_kinds(webrtc, ip, relay),
        );
        assert_eq!(wanted, vec![neighbors[0].1.clone()]);
    }

    /// The underlay address of a neighbor that has an IP socket.
    fn reachable_over_ip(underlay: EndpointId) -> EndpointAddr {
        EndpointAddr::new(underlay).with_ip_addr("127.0.0.1:4433".parse().expect("an address"))
    }

    /// The underlay address of a neighbor without an IP socket, as its link vector gives it: the
    /// relay and nothing else.
    fn relay_only(underlay: EndpointId) -> EndpointAddr {
        EndpointAddr::new(underlay).with_relay_url("https://relay.test".parse().expect("a url"))
    }

    /// A neighbor whose underlay address has no IP entry (a node without `udp`) can only be
    /// reached by a session, so a node with `udp` wants it too, whatever the application path is.
    /// A neighbor with an IP entry on the relay path is not wanted.
    #[test]
    fn a_neighbor_whose_underlay_has_no_ip_is_wanted_by_a_node_with_udp() {
        let (no_ip, with_ip) = (id(41), id(42));
        let neighbors = vec![
            (no_ip, relay_only(id(51))),
            (with_ip, reachable_over_ip(id(52))),
        ];
        let on_relay = |_member: EndpointId| Some(PathKind::Relay);
        assert_eq!(
            wanted_underlays(&neighbors, UdpTransport::Present, on_relay),
            vec![neighbors[0].1.clone()]
        );
    }

    /// The rule above is for the lower id: `plan` dials only from there. A node with the higher
    /// underlay id wants the session and waits for the offer.
    #[test]
    fn the_higher_underlay_id_wants_a_session_and_does_not_dial() {
        let (low, high) = ordered();
        assert_eq!(plan(high, &[low], &[low], &[], usize::MAX), Plan::default());
        assert_eq!(
            plan(low, &[high], &[high], &[], usize::MAX).dial,
            vec![high]
        );
    }

    /// A node without `udp` has no IP on its underlay: the session is the only path to every
    /// neighbor, so each one is wanted, whatever the application path is (a lookup-only mesh
    /// can leave the pair on the relay or unread).
    #[test]
    fn a_node_without_udp_wants_a_session_to_every_neighbor() {
        let (webrtc, ip, relay, unknown) = (id(11), id(12), id(13), id(14));
        let neighbors: Vec<(EndpointId, EndpointAddr)> = [webrtc, ip, relay, unknown]
            .into_iter()
            .map(|member| (member, EndpointAddr::new(id(member.as_bytes()[0] ^ 0x55))))
            .collect();
        let wanted = wanted_underlays(
            &neighbors,
            UdpTransport::Absent,
            neighbor_kinds(webrtc, ip, relay),
        );
        let all: Vec<EndpointAddr> = neighbors.iter().map(|(_, addr)| addr.clone()).collect();
        assert_eq!(wanted, all);
    }

    #[test]
    fn a_denied_member_is_not_a_neighbor_of_the_underlay() {
        let (kept, denied) = (id(21), id(22));
        let neighbors: Vec<(EndpointId, EndpointAddr)> = [kept, denied]
            .into_iter()
            .map(|member| (member, EndpointAddr::new(id(member.as_bytes()[0] ^ 0x55))))
            .collect();
        let left = undenied(neighbors.clone(), |member| member == denied);
        assert_eq!(left, vec![neighbors[0].clone()]);
    }

    /// A neighbor whose path is not read for the moment (an idle connection of the
    /// pool closed), or is on another rung, keeps its session. It goes only when
    /// the neighbor leaves the view or the pair climbs to IP.
    #[test]
    fn a_session_is_detached_only_when_the_neighbor_climbs_to_ip_or_leaves() {
        let (low, high) = ordered();
        let (member, other) = (id(31), id(32));
        let neighbor = vec![(member, EndpointAddr::new(high))];
        let kept_with =
            |kind_of: &dyn Fn(EndpointId) -> Option<PathKind>| kept_underlays(&neighbor, kind_of);

        let on_webrtc = kept_with(&neighbor_kinds(member, other, other));
        assert_eq!(
            plan(low, &[], &on_webrtc, &[high], usize::MAX),
            Plan::default()
        );
        let unread = kept_with(&neighbor_kinds(other, other, other));
        assert_eq!(
            plan(low, &[], &unread, &[high], usize::MAX),
            Plan::default(),
            "unread"
        );
        let on_relay = kept_with(&neighbor_kinds(other, other, member));
        assert_eq!(
            plan(low, &[], &on_relay, &[high], usize::MAX),
            Plan::default(),
            "relay"
        );

        let on_ip = kept_with(&neighbor_kinds(other, member, other));
        assert_eq!(
            plan(low, &[], &on_ip, &[high], usize::MAX),
            Plan {
                dial: vec![],
                detach: vec![high]
            },
            "the pair climbed to IP"
        );

        let left = kept_underlays(&[], neighbor_kinds(member, other, other));
        assert_eq!(
            plan(low, &[], &left, &[high], usize::MAX),
            Plan {
                dial: vec![],
                detach: vec![high]
            },
            "the member left the roster"
        );
    }

    /// A session is named by the underlay id of its member, and the edge by the member id.
    #[test]
    fn a_member_whose_underlay_holds_a_session_is_listed_by_its_member_id() {
        let (with_session, without) = (id(61), id(62));
        let neighbors = vec![
            (with_session, relay_only(id(71))),
            (without, relay_only(id(72))),
        ];
        assert_eq!(
            members_with_session(&neighbors, &[id(71)]),
            vec![with_session]
        );
        assert!(members_with_session(&neighbors, &[]).is_empty());
    }

    #[test]
    fn plan_dials_the_lowest_ids_that_the_room_allows() {
        let mut ids: Vec<EndpointId> = (1..=4).map(id).collect();
        ids.sort_unstable();
        let (low, higher) = (ids[0], ids[1..].to_vec());
        let all = plan(low, &higher, &higher, &[], usize::MAX);
        assert_eq!(all.dial, higher, "no limit: every wanted id above ours");
        let one = plan(low, &higher, &higher, &[], 1);
        assert_eq!(one.dial, higher[..1].to_vec(), "room 1: the lowest id");
        let none = plan(low, &higher, &higher, &[], 0);
        assert!(none.dial.is_empty(), "no room: no offer");
    }

    async fn loopback_endpoint() -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .expect("loopback"),
            )
            .expect("valid bind addr")
            .bind()
            .await
            .expect("bind a loopback endpoint")
    }

    /// The code that the gate closes a connection with when the dialer is not a
    /// neighbor.
    fn closed_with(reason: &iroh::endpoint::ConnectionError) -> Option<u64> {
        match reason {
            iroh::endpoint::ConnectionError::ApplicationClosed(close) => {
                Some(close.error_code.into_inner())
            }
            iroh::endpoint::ConnectionError::VersionMismatch
            | iroh::endpoint::ConnectionError::TransportError(_)
            | iroh::endpoint::ConnectionError::ConnectionClosed(_)
            | iroh::endpoint::ConnectionError::Reset
            | iroh::endpoint::ConnectionError::TimedOut
            | iroh::endpoint::ConnectionError::LocallyClosed
            | iroh::endpoint::ConnectionError::CidsExhausted => None,
        }
    }

    #[test]
    async fn the_gate_refuses_a_signal_from_an_endpoint_that_is_not_a_neighbor() {
        let (logs, _log_guard) = crate::testing::LogCapture::start(tracing::Level::DEBUG);
        let server = loopback_endpoint().await;
        let allowed = Allowed::default();
        let acceptor = WebRtcSignalAcceptor::new(
            crate::lookup::new_webrtc_handle(server.id()),
            server.clone(),
            crate::lookup::address_book(&server.clone()),
            server.id(),
            SignalAdmission::new(4),
            IceProfile { host_only: true },
        );
        let router = Router::builder(server.clone())
            .accept(
                MESH_WEBRTC_SIGNAL_ALPN,
                UnderlaySignalGate::new(acceptor, allowed.clone()),
            )
            .spawn();
        let client = loopback_endpoint().await;

        let refused = client
            .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
            .await
            .expect("the connection opens");
        let reason = tokio::time::timeout(std::time::Duration::from_secs(5), refused.closed())
            .await
            .expect("the gate closes the connection of a stranger");
        assert_eq!(closed_with(&reason), Some(9), "{reason:?}");
        let logged = logs.text();
        assert!(
            logged.contains("underlay signal refused") && logged.contains(&client.id().to_string()),
            "the refusal names the peer and the reason: {logged}"
        );

        // Once the client is a neighbor, the gate hands the connection to the
        // acceptor, which waits for an offer and does not close it.
        allowed.replace([client.id()].into_iter().collect());
        let accepted = client
            .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
            .await
            .expect("the connection opens");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(700), accepted.closed())
                .await
                .is_err(),
            "a neighbor is not turned away"
        );
        router.shutdown().await.expect("the router stops");
    }

    /// The offerer must tell a stranger's turn-away from a refusal at the cap: the first is a
    /// race that the next offer wins, the second backs off.
    #[test]
    async fn an_offer_that_the_gate_turns_away_is_told_apart_from_a_cap_refusal() {
        let server = loopback_endpoint().await;
        let allowed = Allowed::default();
        let acceptor = WebRtcSignalAcceptor::new(
            crate::lookup::new_webrtc_handle(server.id()),
            server.clone(),
            crate::lookup::address_book(&server.clone()),
            server.id(),
            SignalAdmission::new(4),
            IceProfile { host_only: true },
        );
        let router = Router::builder(server.clone())
            .accept(
                MESH_WEBRTC_SIGNAL_ALPN,
                UnderlaySignalGate::new(acceptor, allowed.clone()),
            )
            .spawn();
        let client = loopback_endpoint().await;
        let handle = crate::lookup::new_webrtc_handle(client.id());
        let book = crate::lookup::address_book(&client);

        let error = webrtc::dial_signal(
            &client,
            &book,
            server.addr(),
            &handle,
            IceProfile { host_only: true },
        )
        .await
        .expect_err("the gate turns a stranger away");
        assert!(
            matches!(error, crate::lookup::EndpointError::NotANeighbor { .. }),
            "the refusal is read from the close code: {error:#}"
        );
        assert!(
            !matches!(error, crate::lookup::EndpointError::CapRefused { .. }),
            "a stranger is not a cap refusal: {error:#}"
        );

        // Once the client is a neighbor the same dial is not turned away as one.
        allowed.replace([client.id()].into_iter().collect());
        if let Ok(Err(late_error)) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            webrtc::dial_signal(
                &client,
                &book,
                server.addr(),
                &handle,
                IceProfile { host_only: true },
            ),
        )
        .await
        {
            assert!(
                !matches!(
                    late_error,
                    crate::lookup::EndpointError::NotANeighbor { .. }
                ),
                "a neighbor is not turned away: {late_error:#}"
            );
        }
        router.shutdown().await.expect("the router stops");
        client.close().await;
    }
}
