//! The admission gate of the signalling plane.
use crate::transport::{ceiling, probe, webrtc};

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::EndpointId;
use iroh::endpoint::{Connection, WeakConnectionHandle};
use n0_future::task::AbortHandle;

use crate::util::clock::Instant;
use crate::util::tuning;

use super::inner::RUNG_CLOSE_MEMORY;
use super::{
    AdmissionGuard, BusyGuard, ConnectionHook, Inner, Refusal, RefusalBackoff, Round, Sessions,
    sampler,
};
use tokio::sync::mpsc;

/// The one place a direct-peer slot is granted, for both roles.
#[derive(Debug, Clone)]
pub struct SignalAdmission {
    // the table and the sampler share the inner state
    pub(crate) inner: Arc<Mutex<Inner>>,
    pub(crate) cap: usize,
    /// The mesh lets no payload ride the relay, so the hook keeps watch over the
    /// gossip connections that this node dialed (see [`ConnectionHook`]). Set once
    /// the router, which knows the mesh policy, is built.
    pub(crate) watch_dialed_gossip: Arc<AtomicBool>,
    /// Woken when a round ends, offered or answered, so that the event loop can offer the
    /// sessions that the budget kept back (see [`Self::slot_freed`]).
    pub(crate) freed: Arc<tokio::sync::Notify>,
}

impl SignalAdmission {
    /// The table of the sessions of the underlay. A session there is a route edge, not a cache
    /// entry: at the cap it refuses a newcomer and evicts nobody, so a route that other members use
    /// does not end because a node learned of one more. Above the cap a pair has no session and
    /// routes through others.
    #[must_use]
    pub fn new_route_table(cap: usize) -> Self {
        let table = Self::new(cap);
        table.lock().ceiling = ceiling::Ceiling::refusing(cap);
        table
    }

    /// How many new rounds the table admits now: the cap less the units and the rounds in flight.
    #[cfg(any(feature = "multihop", test))]
    #[must_use]
    pub(crate) fn room(&self) -> usize {
        let inner = self.lock();
        self.cap
            .saturating_sub(inner.ceiling.units() + inner.rounds_in_flight())
    }

    /// An admission table with a ceiling of `cap` direct connections and none in use.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            // the table and the sampler share the inner state
            inner: Arc::new(Mutex::new(Inner {
                slots: HashMap::new(),
                refused: RefusalBackoff::default(),
                hub: None,
                sampler_running: false,
                closed: false,
                ceiling: ceiling::Ceiling::new(cap),
                evicted_by: ceiling::EvictionBackoff::default(),
                we_evicted: ceiling::EvictionBackoff::default(),
                denied: HashSet::new(),
                proven_sink: None,
                path_sink: None,
                gossip: None,
                closed_on_rung: HashMap::new(),
            })),
            cap,
            // the flag is shared by the table and the gossip watch
            watch_dialed_gossip: Arc::new(AtomicBool::new(false)),
            // the slot-freed signal is shared with the pool that waits on it
            freed: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// The cap this table enforces: D, the most `WebRTC` sessions the node holds.
    #[must_use]
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Whether the hook keeps the relay policy on the gossip connections that
    /// this node dials: on when the mesh lets no payload ride the relay.
    pub(crate) fn watch_dialed_gossip(&self, on: bool) {
        self.watch_dialed_gossip.store(on, Ordering::Relaxed);
    }

    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    /// Tests only: whether the hook recorded a live connection to `peer`.
    pub(crate) fn has_live_connection(&self, peer: EndpointId) -> bool {
        self.lock().slots.get(&peer).is_some_and(|slot| {
            let mut live = slot.conns.iter().filter_map(WeakConnectionHandle::upgrade);
            live.any(|connection| connection.close_reason().is_none())
        })
    }

    /// The peers whose session nothing has held for `window` (see
    /// [`Inner::take_idle`]). Each is handed back once, and the caller detaches
    /// it.
    pub(crate) fn idle_sessions(&self, now: Instant, window: Duration) -> Vec<EndpointId> {
        self.lock().take_idle(now, window)
    }

    /// The selected path of `peer`, read from the live connections that the hook
    /// recorded for it: the gossip link, the pooled unicast connection, and the inbound
    /// ones. iroh selects a path per connection, so the best of them stands for the pair
    /// (see [`best_kind`](probe::best_kind)): a link that is still on the relay
    /// can sit beside one that is already direct. A pair that only gossips has no pooled
    /// connection, and this is how the engine sees it. `None` if the peer has no live
    /// connection with a selected path. On the underlay a peer that has a relay link beside a
    /// session now reads as the session (`[Relay, WebRtc]` reads `WebRtc`), where the first
    /// connection used to decide.
    pub(crate) fn selected_kind(&self, peer: EndpointId) -> Option<probe::PathKind> {
        let handles: Vec<WeakConnectionHandle> = {
            let inner = self.lock();
            inner
                .slots
                .get(&peer)
                .map(|slot| slot.conns.clone())
                .unwrap_or_default()
        };
        let connections = handles.iter().filter_map(WeakConnectionHandle::upgrade);
        let live = connections.filter(|connection| connection.close_reason().is_none());
        let kinds = live.map(|connection| probe::selected_kind(&connection));
        probe::best_kind(kinds).or_else(|| self.recently_closed_on_rung(peer))
    }

    /// The recursion rule closed a gossip connection of `peer`: for a while, the pair reads as
    /// the gossip rung though no connection is left to read it from.
    pub(crate) fn note_closed_on_rung(&self, peer: EndpointId) {
        self.lock().closed_on_rung.insert(peer, Instant::now());
    }

    /// The gossip rung, if the recursion rule closed a connection of `peer` lately.
    pub(crate) fn recently_closed_on_rung(&self, peer: EndpointId) -> Option<probe::PathKind> {
        let inner = self.lock();
        let at = inner.closed_on_rung.get(&peer)?;
        (Instant::now().saturating_duration_since(*at) < RUNG_CLOSE_MEMORY)
            .then_some(probe::PathKind::Gossip)
    }

    /// Whether any live connection of `peer` with a selected path reads below IP: the relay, a
    /// session or a route (see [`any_not_ip`](probe::any_not_ip)).
    pub(crate) fn any_connection_not_ip(&self, peer: EndpointId) -> bool {
        let handles: Vec<WeakConnectionHandle> = {
            let inner = self.lock();
            inner
                .slots
                .get(&peer)
                .map(|slot| slot.conns.clone())
                .unwrap_or_default()
        };
        let connections = handles.iter().filter_map(WeakConnectionHandle::upgrade);
        let live = connections.filter(|connection| connection.close_reason().is_none());
        let kinds = live.map(|connection| probe::selected_kind(&connection));
        probe::any_not_ip(kinds)
    }

    /// The endpoint hook that reports every connection to this table. Install
    /// it on the endpoint builder, before bind.
    #[must_use]
    pub fn connection_hook(&self) -> ConnectionHook {
        ConnectionHook {
            admission: self.clone(),
        }
    }

    /// Claim a negotiation slot for `peer`.
    ///
    /// Synchronous by design: the whole decision happens under one lock with
    /// nothing awaited inside, which is what lets in-flight rounds be counted
    /// against the cap without a lock ever crossing a suspension point.
    ///
    /// # Errors
    /// A [`Refusal`] saying which gate closed. All of them are "not now" — none
    /// is a fault, and all but `ShuttingDown` clear on their own.
    pub(crate) fn try_admit<Handle>(
        &self,
        peer: EndpointId,
        handle: &Handle,
    ) -> Result<AdmissionGuard, Refusal>
    where
        Handle: Sessions + Clone,
    {
        self.try_admit_at(peer, handle, Instant::now())
    }

    pub(crate) fn try_admit_at<Handle>(
        &self,
        peer: EndpointId,
        handle: &Handle,
        now: Instant,
    ) -> Result<AdmissionGuard, Refusal>
    where
        Handle: Sessions + Clone,
    {
        self.admit(peer, handle, now, false)
    }

    pub(crate) fn admit<Handle>(
        &self,
        peer: EndpointId,
        handle: &Handle,
        now: Instant,
        outgoing: bool,
    ) -> Result<AdmissionGuard, Refusal>
    where
        Handle: Sessions + Clone,
    {
        let mut inner = self.lock();
        if inner.closed {
            return Err(Refusal::ShuttingDown);
        }
        if inner.denied.contains(&peer) {
            return Err(Refusal::Denied);
        }
        if inner
            .slots
            .get(&peer)
            .is_some_and(|slot| slot.round.is_some())
        {
            return Err(Refusal::InFlight);
        }
        // Nesting the transport's own lock is safe: it is a leaf, with no path
        // back into us.
        if handle.has_session(&peer) {
            return Err(Refusal::HaveSession);
        }
        if inner.refused.on_cooldown(&peer, now) {
            return Err(Refusal::Cooling);
        }
        // Only the offer of the peer: our own offer, from a frame that is held for it, is a send.
        if !outgoing && inner.we_evicted.holds(&peer, now) {
            return Err(Refusal::Evicted);
        }
        if inner.ceiling.refuses()
            && !inner.ceiling.holds(peer)
            && inner.ceiling.units() + inner.rounds_in_flight() >= self.cap
        {
            return Err(Refusal::AtCapacity);
        }
        if inner.hub.is_none() {
            // the table keeps the hub as a shared trait object
            inner.hub = Some(Arc::new(handle.clone()));
        }
        let slot = inner.slot(peer);
        slot.round = Some(Round::Admitted);
        slot.epoch += 1;
        slot.outgoing = outgoing;
        let epoch = slot.epoch;
        drop(inner);
        Ok(AdmissionGuard {
            admission: self.clone(),
            peer,
            epoch,
        })
    }

    /// [`Self::try_admit`] for a round that this node offers, not one that it answers. Only such
    /// a round can be given up for an offer of the peer, see [`Self::preempt_offer`].
    pub(crate) fn try_admit_offer<Handle>(
        &self,
        peer: EndpointId,
        handle: &Handle,
    ) -> Result<AdmissionGuard, Refusal>
    where
        Handle: Sessions + Clone,
    {
        self.try_admit_offer_at(peer, handle, Instant::now())
    }

    pub(crate) fn try_admit_offer_at<Handle>(
        &self,
        peer: EndpointId,
        handle: &Handle,
        now: Instant,
    ) -> Result<AdmissionGuard, Refusal>
    where
        Handle: Sessions + Clone,
    {
        self.admit(peer, handle, now, true)
    }

    /// The peer offers a session while this node's own offer to it runs: give ours up, so that the
    /// peer's offer is answered. Returns whether an offer was given up. A round that answers is
    /// never given up.
    ///
    /// Each round has an epoch, and a guard releases the slot only if its round still holds it.
    /// Without it, the guard of the round that was given up would drop later, and release the slot of
    /// the answer that took its place, so that a third round could start beside the answer.
    pub(crate) fn preempt_offer(&self, peer: EndpointId) -> bool {
        let mut inner = self.lock();
        let Some(slot) = inner
            .slots
            .get_mut(&peer)
            .filter(|slot| slot.outgoing && slot.round.is_some())
        else {
            return false;
        };
        if let Some(Round::Running(abort)) = slot.round.take() {
            abort.abort();
        }
        slot.epoch += 1;
        slot.outgoing = false;
        true
    }

    /// The identity of `peer` has a new holder, or none: a round of this node that was started
    /// against the previous holder cannot find the new one, and holds the slot for the whole round
    /// deadline. End it, so that the next offer is made at once, and forget the wait that the
    /// refusals of the previous holder earned. An aborted round never reaches its error branch, so
    /// this records no wait of its own. Returns whether a round was ended.
    pub(crate) fn cancel_round(&self, peer: EndpointId) -> bool {
        let mut inner = self.lock();
        inner.refused.forget(&peer);
        let Some(slot) = inner
            .slots
            .get_mut(&peer)
            .filter(|slot| slot.round.is_some())
        else {
            return false;
        };
        if let Some(Round::Running(abort)) = slot.round.take() {
            abort.abort();
        }
        slot.epoch += 1;
        slot.outgoing = false;
        drop(inner);
        tracing::debug!(target: crate::transport::LOG_TARGET, peer = %peer.fmt_short(), "cancelled the signalling round of a peer whose holder changed");
        self.freed.notify_one();
        true
    }

    /// Record the task holding `peer`'s slot, so shutdown can cancel it.
    ///
    /// Separate from `try_admit` because the slot must be claimed *before* the
    /// task is spawned — that ordering is what bounds the task count — and the
    /// abort handle does not exist until after.
    ///
    /// `epoch` names the round, from [`AdmissionGuard::epoch`]. A round that was given up before
    /// its task was recorded has its task aborted here.
    pub(crate) fn track(&self, peer: EndpointId, epoch: u64, abort: AbortHandle) {
        let mut inner = self.lock();
        let found = inner
            .slots
            .get_mut(&peer)
            .filter(|slot| slot.epoch == epoch);
        let round = found.and_then(|slot| slot.round.as_mut());
        match round {
            Some(round) => *round = Round::Running(abort),
            None => abort.abort(),
        }
    }

    /// Note that `peer` refused us at its cap; stop offering for a while, longer
    /// each time in a row.
    pub(crate) fn note_refused(&self, peer: EndpointId) {
        self.lock().refused.note(peer, Instant::now());
    }

    /// Note that the underlay of `peer` turned our offer away as not a neighbor. Whether to offer
    /// again soon: only the first time in a row. A second one waits like a refusal at the cap,
    /// and a success starts the row over.
    #[cfg(any(feature = "multihop", test))]
    pub(crate) fn note_not_a_neighbor(&self, peer: EndpointId) -> bool {
        self.lock().refused.note_stranger(peer, Instant::now())
    }

    /// Forget that peers turned our offers away as not a neighbor, and the wait that a second
    /// turn-away earned: this node just sent its link vector, and the vector is what they lacked.
    #[cfg(any(feature = "multihop", test))]
    pub(crate) fn forget_not_a_neighbor(&self) {
        self.lock().refused.forget_strangers();
    }

    /// A round with `peer` ended in a session: it is no longer refusing us, so
    /// its wait starts over.
    pub(crate) fn note_success(&self, peer: EndpointId) {
        let mut inner = self.lock();
        inner.refused.forget(&peer);
        let evictions = inner.ceiling.register_session(peer, Instant::now());
        let victims = inner.take_victims(&evictions);
        drop(inner);
        victims.end();
    }

    /// Drop the wait that `peer`'s refusals earned, because the peer at that
    /// address is not the one that refused: a new holder of the rendezvous id.
    pub(crate) fn forget_refusal(&self, peer: EndpointId) {
        self.lock().refused.forget(&peer);
    }

    /// Cancel every round in flight and refuse all later admissions.
    ///
    /// Called from `ProtocolHandler::shutdown`, which the Router awaits before
    /// closing the endpoint — so aborting rather than draining is the right
    /// semantic: an in-flight negotiation has nothing left to attach to.
    ///
    /// Each aborted task drops its `AdmissionGuard`, which is what empties the
    /// table; nothing here removes entries itself.
    pub(crate) fn close(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        for slot in inner.slots.values() {
            if let Some(Round::Running(abort)) = &slot.round {
                abort.abort();
            }
        }
    }

    /// Whether a round with `peer` holds a slot right now, in either role.
    pub(crate) fn negotiating(&self, peer: EndpointId) -> bool {
        self.lock()
            .slots
            .get(&peer)
            .is_some_and(|slot| slot.round.is_some())
    }

    /// Woken once, with a stored permit, after any round ended: several ends in a row wake it
    /// once, and the pass that follows spends the whole budget that they freed, so one wake is
    /// enough. The end of a round that failed counts as much as one that attached, and no
    /// `DirectOutcome` is sent for it, because a verdict of `direct: false` would mark a lane peer
    /// relay-only.
    pub(crate) fn slot_freed(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.freed)
    }

    pub(crate) fn release(&self, peer: EndpointId, epoch: u64) {
        let ended: bool = {
            let mut inner = self.lock();
            inner
                .slots
                .get_mut(&peer)
                .filter(|slot| slot.epoch == epoch)
                .map(|slot| slot.round = None)
                .is_some()
        };
        if ended {
            self.freed.notify_one();
        }
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.lock().rounds_in_flight()
    }

    /// Put a connection under its peer, and start the sampler if it is not
    /// running.
    pub(crate) fn note_connection(&self, connection: &Connection) {
        let peer = connection.remote_id();
        let handle = connection.weak_handle();
        let mut inner = self.lock();
        if inner.closed {
            return;
        }
        inner.slot(peer).conns.push(handle);
        inner.sync_gossip();
        let evictions = if connection.alpn() == crate::transport::UNICAST_ALPN {
            inner.ceiling.register_quic(peer, Instant::now())
        } else {
            ceiling::Admission::default()
        };
        let victims = inner.take_victims(&evictions);
        if !inner.sampler_running {
            inner.sampler_running = true;
            sampler::spawn_sampler(Arc::downgrade(&self.inner), tuning::SLOT_SWEEP);
        }
        drop(inner);
        if connection.alpn() == crate::transport::UNICAST_ALPN {
            self.watch_for_eviction(connection.clone());
        }
        victims.end();
    }

    /// When `conn` closes, whatever the reason, the peer leaves the ledger unless it holds another
    /// unicast connection: a unit ends with its last connection. When the peer closes it with the
    /// `EVICTED` code, note that too, so that no proactive dial goes back to that peer for a while.
    pub(crate) fn watch_for_eviction(&self, connection: Connection) {
        let admission = self.clone();
        n0_future::task::spawn(async move {
            let reason = connection.closed().await;
            let peer = connection.remote_id();
            let mut inner = admission.lock();
            inner.drop_quic_without_connection(peer);
            if let iroh::endpoint::ConnectionError::ApplicationClosed(close) = reason
                && close.error_code.into_inner() == u64::from(webrtc::close_code::EVICTED)
            {
                let spread = rand::Rng::random_range(&mut rand::rng(), -1.0..=1.0);
                inner.evicted_by.note(peer, Instant::now(), spread);
            }
        });
    }

    /// A send or a stream is in flight on the connection of `peer`: the ledger does not
    /// evict it until the guard is dropped.
    pub(crate) fn busy(&self, peer: EndpointId) -> BusyGuard {
        self.lock().ceiling.busy_begin(peer);
        BusyGuard {
            admission: self.clone(),
            peer,
        }
    }

    /// When the ledger last saw `peer` used, for a test.
    #[cfg(test)]
    pub(crate) fn last_use(&self, peer: EndpointId) -> Option<Instant> {
        self.lock().ceiling.last_use(peer)
    }

    /// Whether a send or a stream is in flight on `peer`, for a test.
    #[cfg(test)]
    pub(crate) fn is_busy(&self, peer: EndpointId) -> bool {
        self.lock()
            .ceiling
            .unused_for(peer, Instant::now())
            .is_none()
    }

    /// Note an eviction by `peer`, for a test that does not run the eviction.
    #[cfg(test)]
    pub(crate) fn note_evicted(&self, peer: EndpointId) {
        self.lock().evicted_by.note(peer, Instant::now(), 0.0);
    }

    /// Tests only: refuse every round with `peer`, the ones this node offers and the ones it
    /// answers, or lift the refusal. A test uses it to keep two members from forming a direct
    /// session, so that their traffic has to take the multihop route. A test that keeps a pair
    /// apart denies each member on the other's node: the refusal is one-sided.
    #[cfg(any(test, feature = "iroh-test-utils"))]
    pub(crate) fn deny(&self, peer: EndpointId, denied: bool) {
        let mut inner = self.lock();
        if denied {
            inner.denied.insert(peer);
        } else {
            inner.denied.remove(&peer);
        }
    }

    /// Whether a test denied `peer`. The underlay tick reads it, so it exists where the
    /// underlay does.
    #[cfg(any(feature = "multihop", test))]
    pub(crate) fn is_denied(&self, peer: EndpointId) -> bool {
        self.lock().denied.contains(&peer)
    }

    /// Whether `peer` evicted our connection lately, so that no proactive dial goes to it.
    pub(crate) fn evicted_recently(&self, peer: EndpointId) -> bool {
        self.lock().evicted_by.holds(&peer, Instant::now())
    }

    /// The gossip neighbors changed. A session counts only while its peer is not one, so a
    /// peer that stops being a neighbor can take the ceiling over.
    pub(crate) fn set_neighbors(&self, neighbors: &HashSet<EndpointId>) {
        let mut inner = self.lock();
        let evictions = inner.ceiling.set_neighbors(neighbors, Instant::now());
        let victims = inner.take_victims(&evictions);
        drop(inner);
        victims.end();
    }

    /// The gossip transport of this endpoint, kept by the table so that it can tell the transport
    /// which peers are established and which pairs a higher rung carries.
    pub(crate) fn set_gossip(&self, handle: habilis_network_iroh_gossip_transport::GossipHandle) {
        self.lock().gossip = Some(handle);
    }

    /// The gossip transport that [`set_gossip`](Self::set_gossip) set, if the mesh has gossip.
    pub(crate) fn gossip_handle(
        &self,
    ) -> Option<habilis_network_iroh_gossip_transport::GossipHandle> {
        self.lock().gossip.clone()
    }

    /// [`Inner::sync_gossip`], now. The sweep and every new connection do it too.
    pub(crate) fn sync_gossip(&self) {
        self.lock().sync_gossip();
    }

    /// The event loop's channel for the sessions that this node answered.
    pub(crate) fn set_proven_sink(&self, sink: mpsc::UnboundedSender<probe::DirectOutcome>) {
        self.lock().proven_sink = Some(sink);
    }

    /// The event loop's channel for the dialed gossip links that left a direct path.
    pub(crate) fn set_path_sink(&self, sink: mpsc::UnboundedSender<probe::PathChange>) {
        self.lock().path_sink = Some(sink);
    }

    pub(crate) fn path_sink(&self) -> Option<mpsc::UnboundedSender<probe::PathChange>> {
        self.lock().path_sink.clone()
    }

    /// A session to `peer` attached on the answering side. The loop flushes the frames held for the
    /// peer, if there are any: the offering side does the same on its own attach.
    pub(crate) fn report_answered(&self, peer: EndpointId) {
        if let Some(sink) = &self.lock().proven_sink {
            let _ = sink.send(probe::DirectOutcome {
                peer,
                direct: true,
                answered: true,
            });
        }
    }

    /// How many peers the node holds a direct connection to, against the ceiling.
    pub(crate) fn direct_units(&self) -> usize {
        self.lock().ceiling.units()
    }

    /// How many direct connections the node is over its ceiling by, because every other
    /// candidate was busy when a newcomer came.
    pub(crate) fn over_ceiling(&self) -> usize {
        self.lock().ceiling.over_ceiling()
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("signal admission poisoned")
    }
}
