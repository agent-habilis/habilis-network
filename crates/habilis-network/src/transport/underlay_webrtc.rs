//! A `WebRTC` leg on the multihop underlay, so that a cell can be forwarded over a
//! session between two members that have no IP path to each other.
//!
//! The underlay is an endpoint of its own with its own key. It gets its own
//! `WebRtcHandle`, its own admission table (cap G) and the signal protocol on
//! its router. A session opens only to a gossip neighbor whose application
//! path is `WebRTC`: where IP works, the underlay reaches the neighbor over IP
//! already. So a session on the underlay rides a gossip edge, which is why it
//! counts in G and not in D.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointId};

use super::{LOG_TARGET, SignalAdmission, WebRtcSignalAcceptor};

/// The close code of a signal from an endpoint that is not a neighbor of ours.
/// The codes of `webrtc::close_code` stop at 8.
const NOT_A_NEIGHBOR: u32 = 9;

/// What one tick does with the sessions of the underlay.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Underlay ids to offer a session to.
    pub(crate) dial: Vec<EndpointId>,
    /// Underlay ids whose session is no longer wanted.
    pub(crate) detach: Vec<EndpointId>,
}

/// Decide the sessions of the underlay. `wanted` are the underlay ids of the
/// neighbors whose application path is `WebRTC`, and `kept` those whose session
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
) -> Plan {
    let mut dial: Vec<EndpointId> = wanted
        .iter()
        .copied()
        .filter(|peer| local < *peer && !held.contains(peer))
        .collect();
    // Sorted, so that a cap that bites picks the same peers on each run.
    dial.sort_unstable();
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
fn wanted_underlays(
    neighbors: &[(EndpointId, iroh::EndpointAddr)],
    kind_of: impl Fn(EndpointId) -> Option<super::probe::PathKind>,
) -> Vec<iroh::EndpointAddr> {
    neighbors
        .iter()
        .filter(|(member, _)| kind_of(*member) == Some(super::probe::PathKind::WebRtc))
        .map(|(_, addr)| addr.clone())
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

/// The underlay ids that may open a session with us now: the underlay ids of our
/// gossip neighbors. The event loop refreshes it on each tick.
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
            connection.close(NOT_A_NEIGHBOR.into(), b"not a neighbor");
            return Ok(());
        }
        self.inner.accept(connection).await
    }
}

/// One alive tick: offer a session to each neighbor that needs one, and drop the
/// sessions that no neighbor needs. A neighbor needs one when its application
/// path is `WebRTC`; see the module note.
pub(crate) fn tick(state: &crate::daemon::state::EventLoopState, underlay: &UnderlayWebRtc) {
    let Some(multihop) = state.multihop() else {
        return;
    };
    // The underlay address of a neighbor is in its signed link-vector. A
    // neighbor we hold no vector from yet is skipped: it gets one on a later tick.
    let mut neighbors: Vec<(EndpointId, iroh::EndpointAddr)> = Vec::new();
    for member in &state.linked_endpoints {
        if let Some(addr) = multihop.underlay_addr_of(*member) {
            neighbors.push((*member, addr));
        }
    }
    underlay
        .allowed
        .replace(neighbors.iter().map(|(_, addr)| addr.id).collect());

    let wanted_addrs = wanted_underlays(&neighbors, |member| state.pair_path_kind(member));
    let wanted: Vec<EndpointId> = wanted_addrs.iter().map(|addr| addr.id).collect();
    let kept = kept_underlays(&neighbors, |member| state.pair_path_kind(member));
    let held = underlay.handle.live_peer_ids();
    let Plan { dial, detach } = plan(underlay.endpoint.id(), &wanted, &kept, &held);

    for peer in detach {
        if underlay.handle.detach(&peer) {
            tracing::debug!(target: LOG_TARGET, %peer, "underlay session detached: its neighbor left, or the pair is on IP");
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
        let (endpoint, handle, admission) = (
            underlay.endpoint.clone(),
            underlay.handle.clone(),
            underlay.admission.clone(),
        );
        let addr = addr.clone();
        let ice = state.webrtc_ice;
        let task = n0_future::task::spawn(async move {
            let _guard = guard;
            match Box::pin(super::webrtc::dial_signal(&endpoint, addr, &handle, ice)).await {
                Ok(()) => admission.note_success(peer),
                Err(error) => {
                    if super::webrtc::is_cap_refusal(&error) {
                        admission.note_refused(peer);
                    }
                    tracing::debug!(target: LOG_TARGET, %peer, %error, "underlay webrtc offer failed");
                }
            }
        });
        underlay.admission.track(peer, task.abort_handle());
    }
}

/// What the event loop keeps of the `WebRTC` leg of the underlay.
#[derive(Debug, Clone)]
pub(crate) struct UnderlayWebRtc {
    pub(crate) handle: habilis_network_iroh_webrtc_transport::WebRtcHandle,
    pub(crate) admission: SignalAdmission,
    pub(crate) endpoint: Endpoint,
    pub(crate) allowed: Allowed,
}

#[cfg(test)]
mod tests {
    use iroh::{EndpointId, SecretKey};

    use iroh::EndpointAddr;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::{Endpoint, RelayMode};

    use super::{Allowed, Plan, UnderlaySignalGate, kept_underlays, plan, wanted_underlays};
    use crate::transport::probe::PathKind;
    use crate::transport::{
        IceProfile, MESH_WEBRTC_SIGNAL_ALPN, SignalAdmission, WebRtcSignalAcceptor,
    };

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
            plan(low, &[high], &[high], &[]),
            Plan {
                dial: vec![high],
                detach: vec![]
            }
        );
    }

    #[test]
    fn the_higher_id_waits_to_be_dialed() {
        let (low, high) = ordered();
        assert_eq!(plan(high, &[low], &[low], &[]), Plan::default());
    }

    #[test]
    fn a_neighbor_that_has_a_session_is_not_dialed_again() {
        let (low, high) = ordered();
        assert_eq!(plan(low, &[high], &[high], &[high]), Plan::default());
    }

    #[test]
    fn a_session_with_a_peer_that_is_not_kept_is_detached() {
        let (low, high) = ordered();
        assert_eq!(
            plan(low, &[], &[], &[high]),
            Plan {
                dial: vec![],
                detach: vec![high]
            }
        );
    }

    #[test]
    fn a_session_with_a_kept_peer_stays_even_when_it_is_not_wanted() {
        let (low, high) = ordered();
        assert_eq!(plan(low, &[], &[high], &[high]), Plan::default());
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
            .map(|member| (member, EndpointAddr::new(id(member.as_bytes()[0] ^ 0x55))))
            .collect();
        let wanted = wanted_underlays(&neighbors, neighbor_kinds(webrtc, ip, relay));
        assert_eq!(wanted, vec![neighbors[0].1.clone()]);
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
        assert_eq!(plan(low, &[], &on_webrtc, &[high]), Plan::default());
        let unread = kept_with(&neighbor_kinds(other, other, other));
        assert_eq!(plan(low, &[], &unread, &[high]), Plan::default(), "unread");
        let on_relay = kept_with(&neighbor_kinds(other, other, member));
        assert_eq!(plan(low, &[], &on_relay, &[high]), Plan::default(), "relay");

        let on_ip = kept_with(&neighbor_kinds(other, member, other));
        assert_eq!(
            plan(low, &[], &on_ip, &[high]),
            Plan {
                dial: vec![],
                detach: vec![high]
            },
            "the pair climbed to IP"
        );

        let left = kept_underlays(&[], neighbor_kinds(member, other, other));
        assert_eq!(
            plan(low, &[], &left, &[high]),
            Plan {
                dial: vec![],
                detach: vec![high]
            },
            "the neighbor left the view"
        );
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

    #[tokio::test]
    async fn the_gate_refuses_a_signal_from_an_endpoint_that_is_not_a_neighbor() {
        let server = loopback_endpoint().await;
        let allowed = Allowed::default();
        let acceptor = WebRtcSignalAcceptor::new(
            crate::lookup::new_webrtc_handle(server.id()),
            server.clone(),
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
}
