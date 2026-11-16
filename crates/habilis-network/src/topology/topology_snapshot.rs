use std::collections::BTreeSet;

use iroh::EndpointId;
use serde::Serialize;

#[cfg(feature = "multihop")]
use habilis_network_iroh_multihop_transport::{AppId, TopologyView};

#[cfg(feature = "multihop")]
use super::TopologyLink;
use super::{PathLabel, PeerLink, TopologyGraph};
use crate::daemon::state::EventLoopState;
use crate::transport::LedgerView;
use crate::transport::probe::PathKind;

/// The connections of a node, the cap on them, and the multihop link-state graph, read at one
/// instant.
///
/// ```no_run
/// use habilis_network::embed::EventLoopState;
///
/// # fn demo(state: &EventLoopState) -> usize {
/// state.topology_snapshot().direct_units
/// # }
/// ```
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct TopologySnapshot {
    /// The endpoint id of this node, in hex, or `None` while the admission table does not know it.
    pub self_id: Option<String>,
    /// The cap on the direct connections of the node.
    pub max_connections: usize,
    /// The units of the ceiling now: a gossip neighbor, a session and a connection to one peer
    /// are one unit.
    pub direct_units: usize,
    /// How many units the count is over the ceiling by.
    pub over_ceiling: usize,
    /// The peers that the node holds a connection, a session or a gossip link to, units and extras
    /// together.
    pub connected_peers: usize,
    /// The cap on the connected peers in all.
    pub connected_cap: usize,
    /// Every peer that the node holds a connection, a session or a gossip link to.
    pub peers: Vec<PeerLink>,
    /// The multihop link-state graph, or `None` when multihop is off.
    pub graph: Option<TopologyGraph>,
}

impl EventLoopState {
    /// The connections of this node, read at one instant.
    #[must_use]
    pub fn topology_snapshot(&self) -> TopologySnapshot {
        let ledger: LedgerView = self.webrtc_admission.ledger();
        let mut ids: BTreeSet<EndpointId> = BTreeSet::new();
        ids.extend(&ledger.quic_peers);
        ids.extend(&ledger.session_peers);
        ids.extend(&self.linked_endpoints);
        let peers: Vec<PeerLink> = ids
            .into_iter()
            .map(|id| self.peer_link(id, &ledger))
            .collect();
        let self_id: Option<String> = ledger.local.map(|id| id.to_string());
        TopologySnapshot {
            self_id,
            max_connections: ledger.cap,
            direct_units: ledger.units,
            over_ceiling: ledger.over_ceiling,
            connected_peers: ledger.connections,
            connected_cap: ledger.total_cap,
            peers,
            graph: self.graph(),
        }
    }

    fn peer_link(&self, peer: EndpointId, ledger: &LedgerView) -> PeerLink {
        // A pinned peer takes multihop paths only, and a pair may have no path watcher to report one.
        let reported: PathKind = self
            .path_kinds
            .get(&peer)
            .copied()
            .unwrap_or(PathKind::None);
        let kind: PathKind = if ledger.pinned.contains(&peer) {
            PathKind::Multihop
        } else {
            reported
        };
        let via: Option<String> = if kind == PathKind::Multihop {
            self.first_hop(peer)
        } else {
            None
        };
        PeerLink {
            endpoint: peer.to_string(),
            nickname: self.nickname_of_endpoint(peer),
            path: PathLabel::from(kind),
            via,
            neighbor: self.linked_endpoints.contains(&peer),
            pinned: ledger.pinned.contains(&peer),
            extra: ledger.extras.contains(&peer),
        }
    }

    /// The nickname that the roster gave the endpoint `peer`, when it did.
    fn nickname_of_endpoint(&self, peer: EndpointId) -> Option<String> {
        for (nickname, address) in &self.peer_endpoints {
            if address.id == peer {
                return Some(nickname.to_string());
            }
        }
        None
    }

    /// The first hop of the multihop route that the topology gives for `peer` now, in hex. It is
    /// the route a send would take, not a reading of the path in use. Without multihop there is
    /// none.
    fn first_hop(&self, peer: EndpointId) -> Option<String> {
        #[cfg(feature = "multihop")]
        {
            let mut hops = self.multihop()?.route_hops(AppId::new(peer))?;
            hops.next().map(|hop| hop.get().to_string())
        }
        #[cfg(not(feature = "multihop"))]
        {
            let _ = (self, peer);
            None
        }
    }

    /// The multihop link-state graph of this node. Without multihop there is none.
    fn graph(&self) -> Option<TopologyGraph> {
        #[cfg(feature = "multihop")]
        {
            let view: TopologyView = self.multihop()?.topology_view();
            let edges: Vec<TopologyLink> = view
                .edges
                .iter()
                .map(|edge| TopologyLink {
                    from: edge.from.clone(),
                    to: edge.to.clone(),
                    metric: edge.metric,
                })
                .collect();
            Some(TopologyGraph {
                self_id: view.self_id,
                edges,
            })
        }
        #[cfg(not(feature = "multihop"))]
        {
            let _ = self;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh::EndpointAddr;

    use crate::testing::{endpoint_id, fresh_state, nick};
    use crate::topology::{PathLabel, PeerLink};
    use crate::transport::probe::PathKind;
    use crate::util::tuning::MAX_CONNECTIONS;

    /// A peer with a session and a peer with a gossip link are two peers and two units, each with
    /// the path, the nickname and the neighbor flag that the engine holds for it.
    #[test]
    fn a_session_and_a_gossip_link_are_two_peers_and_two_units() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let (bob, carol) = (endpoint_id(1), endpoint_id(2));
        state.webrtc_admission.note_success(bob);
        state.link(carol);
        state.path_kinds.insert(bob, PathKind::WebRtc);
        state.path_kinds.insert(carol, PathKind::Ip);
        state.note_peer_endpoint(nick("bob"), EndpointAddr::new(bob));

        let snapshot = state.topology_snapshot();

        assert_eq!(snapshot.peers.len(), 2, "two peers: {snapshot:?}");
        assert_eq!(snapshot.direct_units, 2, "two units: {snapshot:?}");
        assert_eq!(
            snapshot.max_connections, MAX_CONNECTIONS,
            "the cap is the default"
        );
        assert_eq!(
            snapshot.connected_cap,
            2 * MAX_CONNECTIONS,
            "the total cap is twice the cap"
        );
        assert!(snapshot.graph.is_none(), "multihop is off in this state");
        let bob_link: &PeerLink = snapshot
            .peers
            .iter()
            .find(|peer| peer.endpoint == bob.to_string())
            .expect("bob is a peer");
        assert_eq!(bob_link.path, PathLabel::Webrtc, "bob is on a session");
        assert_eq!(bob_link.nickname.as_deref(), Some("bob"), "bob is named");
        assert!(!bob_link.neighbor, "bob has no gossip link");
        let carol_link: &PeerLink = snapshot
            .peers
            .iter()
            .find(|peer| peer.endpoint == carol.to_string())
            .expect("carol is a peer");
        assert_eq!(carol_link.path, PathLabel::Ip, "carol is on an ip path");
        assert!(carol_link.neighbor, "carol is a gossip neighbor");
        assert!(carol_link.nickname.is_none(), "carol has no nickname yet");
        assert!(carol_link.via.is_none(), "an ip path has no first hop");
        assert!(!carol_link.pinned, "carol is not pinned");
        assert!(!carol_link.extra, "carol holds a unit");
    }

    /// A session that no unit could take is an extra: it counts toward the total cap and not
    /// toward the units, and the snapshot flags that peer alone.
    #[test]
    fn a_session_above_a_full_ceiling_is_flagged_as_an_extra() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        for seed in 1..=u8::try_from(MAX_CONNECTIONS).expect("a small cap") {
            state.link(endpoint_id(seed));
        }
        let extra = endpoint_id(200);
        state.webrtc_admission.note_success(extra);

        let snapshot = state.topology_snapshot();

        assert_eq!(
            snapshot.direct_units, MAX_CONNECTIONS,
            "the neighbors fill the ceiling: {snapshot:?}"
        );
        assert_eq!(
            snapshot.connected_peers,
            MAX_CONNECTIONS + 1,
            "the extra counts toward the total cap: {snapshot:?}"
        );
        let flagged: Vec<&str> = snapshot
            .peers
            .iter()
            .filter(|peer| peer.extra)
            .map(|peer| peer.endpoint.as_str())
            .collect();
        assert_eq!(
            flagged,
            [extra.to_string().as_str()],
            "only the session that took no unit is an extra"
        );
    }

    #[test]
    fn a_peer_with_no_reading_has_an_unknown_path() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let dave = endpoint_id(3);
        state.link(dave);

        let snapshot = state.topology_snapshot();

        assert_eq!(snapshot.peers.len(), 1, "one peer: {snapshot:?}");
        assert_eq!(
            snapshot.peers[0].path,
            PathLabel::Unknown,
            "no reading is unknown"
        );
        assert_eq!(
            serde_json::to_value(snapshot.peers[0].path).expect("a label serializes"),
            "unknown",
            "the label serializes in lowercase"
        );
    }
}
