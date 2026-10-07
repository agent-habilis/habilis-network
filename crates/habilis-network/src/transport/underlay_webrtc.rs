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
/// neighbors whose application path is `WebRTC`, `held` are those with a live
/// session, and `local` is our own underlay id. The lower id dials, so exactly
/// one offer crosses per pair.
pub(crate) fn plan(local: EndpointId, wanted: &[EndpointId], held: &[EndpointId]) -> Plan {
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
        .filter(|peer| !wanted.contains(peer))
        .collect();
    Plan { dial, detach }
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

    let wanted_addrs: Vec<&iroh::EndpointAddr> = neighbors
        .iter()
        .filter(|(member, _)| state.pair_path_kind(*member) == Some(super::probe::PathKind::WebRtc))
        .map(|(_, addr)| addr)
        .collect();
    let wanted: Vec<EndpointId> = wanted_addrs.iter().map(|addr| addr.id).collect();
    let held = underlay.handle.live_peer_ids();
    let Plan { dial, detach } = plan(underlay.endpoint.id(), &wanted, &held);

    for peer in detach {
        if underlay.handle.detach(&peer) {
            tracing::debug!(target: LOG_TARGET, %peer, "underlay session detached: no neighbor needs it");
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
        let addr = (*addr).clone();
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

    use super::{Plan, plan};

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
            plan(low, &[high], &[]),
            Plan {
                dial: vec![high],
                detach: vec![]
            }
        );
    }

    #[test]
    fn the_higher_id_waits_to_be_dialed() {
        let (low, high) = ordered();
        assert_eq!(plan(high, &[low], &[]), Plan::default());
    }

    #[test]
    fn a_neighbor_that_has_a_session_is_not_dialed_again() {
        let (low, high) = ordered();
        assert_eq!(plan(low, &[high], &[high]), Plan::default());
    }

    #[test]
    fn a_session_with_a_peer_that_is_no_longer_wanted_is_detached() {
        let (low, high) = ordered();
        assert_eq!(
            plan(low, &[], &[high]),
            Plan {
                dial: vec![],
                detach: vec![high]
            }
        );
    }
}
