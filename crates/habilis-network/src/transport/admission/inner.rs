//! The state behind the admission gate.
use crate::transport::{ceiling, probe};

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use iroh::EndpointId;
use iroh::endpoint::WeakConnectionHandle;

use crate::util::clock::Instant;

use super::{RefusalBackoff, Sessions, Slot, Victims, sampler};
use tokio::sync::mpsc;

/// How long a pair keeps reading as the gossip rung after the recursion rule closed its gossip
/// connection and no other connection is left to read. The loss of the link, the race for a
/// session and its attach all fit in it.
pub(crate) const RUNG_CLOSE_MEMORY: Duration = Duration::from_secs(15);

pub(crate) struct Inner {
    pub(crate) slots: HashMap<EndpointId, Slot>,
    /// Peers that refused us at their cap, each with its wait.
    pub(crate) refused: RefusalBackoff,
    /// The hub whose sessions the cap counts, learned at the first admission.
    pub(crate) hub: Option<Arc<dyn Sessions>>,
    pub(crate) sampler_running: bool,
    pub(crate) closed: bool,
    /// The direct connections of the node against the ceiling, see [`crate::transport::ceiling`].
    pub(crate) ceiling: ceiling::Ceiling,
    /// The peers that closed a connection of ours with the `EVICTED` code.
    pub(crate) evicted_by: ceiling::EvictionBackoff,
    /// Where an answered session is reported to the event loop, set once the loop has its channel.
    pub(crate) proven_sink: Option<mpsc::UnboundedSender<probe::DirectOutcome>>,
    /// Where the relay watch of a dialed gossip link reports to the event loop, set with the sink above.
    pub(crate) path_sink: Option<mpsc::UnboundedSender<probe::PathChange>>,
    /// The gossip transport of the endpoint, when the mesh has `gossip`. The table sees every
    /// connection, so it tells the handle which peers are established and which pairs a higher
    /// rung carries (see [`Inner::sync_gossip`]).
    pub(crate) gossip: Option<habilis_network_iroh_gossip_transport::GossipHandle>,
    /// The peers that we evicted. A peer whose session we detach has no connection to read the code
    /// on, so we refuse its offer for the same minute instead.
    pub(crate) we_evicted: ceiling::EvictionBackoff,
    /// The peers that a test denied (see [`SignalAdmission::deny`]). Empty in a product build:
    /// only `deny` fills it.
    pub(crate) denied: HashSet<EndpointId>,
    /// When the recursion rule last closed a gossip connection of a peer. The closed connection
    /// leaves the table at once, so this is what keeps the pair reading as the gossip rung while
    /// the event loop handles the loss of the link (see [`SignalAdmission::selected_kind`]).
    pub(crate) closed_on_rung: HashMap<EndpointId, Instant>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("Inner");
        debug.field("peers", &self.slots.len());
        debug.field("closed", &self.closed);
        debug.finish_non_exhaustive()
    }
}

impl Inner {
    pub(crate) fn slot(&mut self, peer: EndpointId) -> &mut Slot {
        self.slots.entry(peer).or_insert_with(Slot::new)
    }

    pub(crate) fn rounds_in_flight(&self) -> usize {
        self.slots
            .values()
            .filter(|slot| slot.round.is_some())
            .count()
    }

    /// The peers whose session was last used `window` ago or more, each handed back once. The
    /// last use is the one of the ledger, so a session goes a window after its last use, and no
    /// later. A round in flight holds the peer, and so does a live gossip connection: a gossip
    /// neighbor never idles out. A peer that is handed back starts a new window, in case the caller
    /// keeps its session.
    pub(crate) fn take_idle(&mut self, now: Instant, window: Duration) -> Vec<EndpointId> {
        self.sample();
        let Some(hub) = self.hub.clone() else {
            return Vec::new();
        };
        let mut idle = Vec::new();
        for peer in self.ceiling.session_peers() {
            let held: bool = self.slots.get(&peer).is_some_and(|slot| {
                let on_gossip = slot
                    .conns
                    .iter()
                    .filter_map(WeakConnectionHandle::upgrade)
                    .any(|connection| connection.alpn() == iroh_gossip::net::GOSSIP_ALPN);
                slot.round.is_some() || on_gossip
            });
            if held || !hub.has_session(&peer) {
                continue;
            }
            if self
                .ceiling
                .unused_for(peer, now)
                .is_some_and(|unused| unused >= window)
            {
                self.ceiling.touch(peer, now);
                idle.push(peer);
            }
        }
        idle.sort_unstable();
        idle
    }

    /// The connections and the sessions of the peers that `evictions` names, and the end of
    /// their units in the ledger: the caller ends them once it has dropped the lock.
    pub(crate) fn take_victims(&mut self, evictions: &ceiling::Admission) -> Victims {
        let mut victims = Victims::default();
        for peer in &evictions.evict {
            self.ceiling.unregister_quic(*peer);
            self.ceiling.unregister_session(*peer);
            let spread = rand::Rng::random_range(&mut rand::rng(), -1.0..=1.0);
            self.we_evicted.note(*peer, Instant::now(), spread);
            if let Some(hub) = self.hub.as_ref().filter(|hub| hub.has_session(peer)) {
                victims.sessions.push((*peer, Arc::clone(hub)));
            }
            let Some(slot) = self.slots.get(peer) else {
                continue;
            };
            victims.conns.extend(
                slot.conns
                    .iter()
                    .filter_map(WeakConnectionHandle::upgrade)
                    .filter(|connection| {
                        connection.close_reason().is_none()
                            && connection.alpn() == crate::transport::UNICAST_ALPN
                    }),
            );
        }
        victims
    }

    /// End the unit of the unicast connections of `peer` in the ledger if it holds none that is
    /// alive.
    pub(crate) fn drop_quic_without_connection(&mut self, peer: EndpointId) {
        let alive: bool = self.slots.get(&peer).is_some_and(|slot| {
            slot.conns
                .iter()
                .filter_map(WeakConnectionHandle::upgrade)
                .any(|connection| {
                    connection.close_reason().is_none()
                        && connection.alpn() == crate::transport::UNICAST_ALPN
                })
        });
        if !alive {
            self.ceiling.unregister_quic(peer);
        }
    }

    /// Tell the gossip transport what the table sees, for every peer with a slot: a peer with a
    /// live connection is established, and frames go to a peer only when no higher rung carries
    /// the pair (see [`gossip_view`]). Called when a connection is noted and on every sweep, so
    /// both ids of a pair get it, not only the lower one that has a path watcher. A peer without
    /// a live connection is established no more, and allowed again: a destination that was never
    /// named is allowed, so that a handshake to a new peer is not dropped.
    pub(crate) fn sync_gossip(&self) {
        let Some(gossip) = &self.gossip else {
            return;
        };
        for (peer, slot) in &self.slots {
            let open = slot.conns.iter().filter_map(WeakConnectionHandle::upgrade);
            let live = open.filter(|connection| connection.close_reason().is_none());
            let kinds: Vec<probe::PathKind> = live
                .map(|connection| probe::selected_kind(&connection))
                .collect();
            let (established, allowed) = sampler::gossip_view(&kinds);
            gossip.set_established(*peer, established);
            // A session carries the pair though no connection is left to read: a gossip
            // connection dialed now would be born on the gossip rung and closed by the
            // recursion rule before iroh moves it onto the session. With a live connection its
            // own path decides: a session whose rung is cut carries nothing, and a block would
            // starve the connection that does.
            let carried =
                kinds.is_empty() && self.hub.as_ref().is_some_and(|hub| hub.has_session(peer));
            gossip.allow(*peer, allowed && !carried);
        }
    }

    /// Drop the connections that are gone, and the slots nothing holds.
    pub(crate) fn sample(&mut self) {
        for slot in self.slots.values_mut() {
            slot.conns.retain(|handle| {
                handle
                    .upgrade()
                    .is_some_and(|connection| connection.close_reason().is_none())
            });
        }
        self.sync_gossip();
        let now = Instant::now();
        self.closed_on_rung
            .retain(|_, at| now.saturating_duration_since(*at) < RUNG_CLOSE_MEMORY);
        for peer in self.ceiling.quic_peers() {
            self.drop_quic_without_connection(peer);
        }
        let hub = self.hub.clone();
        if let Some(hub) = &hub {
            let live = hub.live_peers();
            for peer in self.ceiling.session_peers() {
                if !live.contains(&peer) {
                    self.ceiling.unregister_session(peer);
                }
            }
        }
        self.slots.retain(|peer, slot| {
            let session = hub.as_ref().is_some_and(|hub| hub.has_session(peer));
            slot.round.is_some() || !slot.conns.is_empty() || session
        });
    }
}
