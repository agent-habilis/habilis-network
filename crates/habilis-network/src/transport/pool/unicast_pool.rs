//! The dial side of the unicast plane: the per-peer connection pool.

use super::in_flight_dial::InFlightDial;
use super::outgoing_frame::OutgoingFrame;
use super::plan_release::PlanRelease;
use super::registration::Registration;
use super::send_fault::SendFault;
use super::timeouts::{
    AT_CEILING, COOLDOWN_REFUSED, DIAL_FAILURE_COOLDOWN, DIAL_TIMEOUT, PATH_SELECT_TIMEOUT,
    PINNED_IDLE, PINNED_REDIAL, SEND_ANSWER_TIMEOUT, SEND_TIMEOUT,
};
use super::warm_send::WarmSend;
use crate::transport::admission::{BusyGuard, SignalAdmission};
use crate::transport::ceiling::DialPlan;
use crate::transport::payload_path;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use bytes::Bytes;
use iroh::endpoint::{Connection, ReadError, ReadExactError};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use n0_future::time::Instant as PoolInstant;
use tokio::sync::{Mutex, watch};

#[cfg(test)]
use crate::transport::PendingSend;
use crate::transport::unicast_acceptor::NOT_TAKEN;
use crate::transport::webrtc::close_code::IDLE;
use crate::transport::{LOG_TARGET, RELAY_REFUSED, SendVerdict, UNICAST_ALPN, payload_allowed_on};

use crate::util::clock::Instant;
use crate::util::cooldown::Cooldown;
use crate::util::tuning::{DIRECT_IDLE_BACKSTOP, PROBE_HOLD};

use crate::daemon::state::WireOutTally;

use n0_future::{task, time};
use std::fmt;
use std::sync::{Mutex as std_Mutex, OnceLock, OnceLock as std_OnceLock};
#[cfg(test)]
use tokio::sync::Notify;
use tokio::sync::oneshot;
#[derive(Clone)]
pub(crate) struct UnicastPool {
    // the pool and its clones share the inner state
    pub(in crate::transport::pool) inner: Arc<PoolInner>,
}

impl fmt::Debug for UnicastPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnicastPool").finish_non_exhaustive()
    }
}

/// A held outcome of a dial: the peer, the sender that says the dialer holds, and the receiver
/// that lets it go on.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
type OutcomeHold = (EndpointId, oneshot::Sender<()>, oneshot::Receiver<()>);

/// Why a pooled connection is held, which decides when it closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::transport::pool) enum Hold {
    /// A send opened or used it: it closes after the idle timeout.
    Used,
    /// A direct-path probe opened it and is still running.
    Probing,
    /// The probe ended at this time and no send has taken the connection since:
    /// it closes after the probe hold.
    Probed(PoolInstant),
}

/// A pooled connection and when a send last used it.
#[derive(Debug, Clone)]
pub(in crate::transport::pool) struct Pooled {
    pub(in crate::transport::pool) connection: Connection,
    /// On the clock the tokio runtime keeps, so a test can pause it.
    pub(in crate::transport::pool) last_used: PoolInstant,
    pub(in crate::transport::pool) hold: Hold,
    /// The connection rides multihop for a peer that the node could not dial directly, and the
    /// sweeper closes it after [`PoolInner::pinned_idle`].
    pub(in crate::transport::pool) pinned: bool,
}

#[derive(Debug)]
pub(in crate::transport::pool) struct PoolInner {
    /// `None` for a detached pool (unit-test states / pre-wiring default): every
    /// operation is inert, so a directed send simply errors instead of dialing.
    pub(in crate::transport::pool) endpoint: Option<Endpoint>,
    pub(in crate::transport::pool) conns: Mutex<HashMap<EndpointId, Pooled>>,
    /// The bytes of every frame written to a pooled connection, so a test can count what a node
    /// puts on the wire beside gossip.
    #[cfg(test)]
    pub(in crate::transport::pool) tap: std_Mutex<Vec<Vec<u8>>>,
    /// How long a pooled connection may go unused before it is closed. The
    /// peer's acceptor closes an unused connection on its own side too, so a
    /// link that nobody sends on does not hold its two ends open for ever.
    pub(in crate::transport::pool) idle: Duration,
    /// How long the connection of a direct-path probe stays after the probe ends
    /// when no send takes it.
    pub(in crate::transport::pool) probe_hold: Duration,
    /// Set once the sweeper is running, so that it starts at the first dial.
    pub(in crate::transport::pool) sweeping: AtomicBool,
    /// When each endpoint's last dial failed, for the
    /// [`DIAL_FAILURE_COOLDOWN`] gate. An entry clears on a successful dial or
    /// a graceful `Left`; expired ones are pruned on the next `note`.
    pub(in crate::transport::pool) dial_failures: Mutex<Cooldown<EndpointId>>,
    /// The answer batches in flight: a peer cannot draw more of them than its share, however many
    /// Times the inline-dial path was entered. Counted on entry rather than at
    /// the dial itself, because the question a caller on the event loop needs
    /// answered is whether it *could* have waited here — a detached pool bails
    /// before dialing, and a warm hit inside never dials, but both mean the
    /// caller was willing to.
    pub(in crate::transport::pool) dial_attempts: AtomicU64,
    /// Tests only: the dials that reached the endpoint, where `dial_attempts` counts the calls.
    #[cfg(test)]
    pub(in crate::transport::pool) dials_started: AtomicU64,
    /// Tests only: how many dials this pool made to each peer, direct or through a route. A test
    /// that says a node dialed nobody for a peer reads it with [`UnicastPool::dials_to`].
    #[cfg(any(test, all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
    pub(in crate::transport::pool) dials_made: std_Mutex<HashMap<EndpointId, u64>>,
    /// Endpoints with a dial in flight, each with the receiver of the outcome that its dialer
    /// publishes. Every way into a dial of a peer takes a place here, sends, the direct-path probe and
    /// an inline dial alike: the first caller is the dialer and dials once, the others are waiters, and
    /// read the pooled connection when the dialer says that the dial ended. This is the only exclusion
    /// between two dials of one peer.
    pub(in crate::transport::pool) dialing:
        parking_lot::Mutex<HashMap<EndpointId, watch::Receiver<DialOutcome>>>,
    /// Tests only: how many callers wait now for the dial of another, so that a test knows that a
    /// caller is in place without a sleep.
    #[cfg(test)]
    pub(in crate::transport::pool) waiting: AtomicU64,
    /// Tests only: the next dial waits on this before it connects, so a test can queue a send
    /// behind it.
    #[cfg(test)]
    // the gate is shared by the dial and the test that holds it
    pub(in crate::transport::pool) dial_gate: std_Mutex<Option<Arc<Notify>>>,
    /// Tests only: the dialer of this peer holds its outcome here, after its dial and its path
    /// wait and before it publishes, so a test can line up a second send with a dial in flight.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(in crate::transport::pool) outcome_hold: std_Mutex<Option<OutcomeHold>>,
    /// Each peer's full address, from its `PeerInfo`. Dialed instead of the
    /// bare id so the relay is in the address book before the handshake:
    /// iroh opens a connection's relay path only then, and with it a UDP loss
    /// has a backup path to fall to rather than none.
    pub(in crate::transport::pool) addrs: std_Mutex<HashMap<EndpointId, EndpointAddr>>,
    /// The multihop route that the next dial of a peer takes, with no other address: the node is at
    /// its ceiling of direct connections, and the peer is pinned (see [`UnicastPool::plan_dial`]).
    /// The dial takes the entry.
    pub(in crate::transport::pool) routes: parking_lot::Mutex<HashMap<EndpointId, PlannedRoute>>,
    /// How long a pinned connection stays open with no send.
    pub(in crate::transport::pool) pinned_idle: Duration,
    /// `TransportPolicy::relay`. Off, a send on a connection whose selected
    /// path is the relay is refused; the connection stays pooled, since iroh
    /// may still punch a direct path on it.
    pub(in crate::transport::pool) relay_transport: bool,
    /// The table whose ceiling the connections of this pool count against. Set once the
    /// table exists, which is after the pool.
    pub(in crate::transport::pool) admission: std_OnceLock<SignalAdmission>,
    /// Where the frames of this pool are counted: the tally of the loop that owns it. Set once, like
    /// the table. A pool that no loop owns counts nothing.
    pub(in crate::transport::pool) tally: std_OnceLock<WireOutTally>,
}

/// What the dialer of a peer publishes to the callers that wait on its dial: nothing while the dial
/// runs, then `Ok` or the text of its error.
pub(crate) type DialOutcome = Option<DialEnd>;

/// How a dial that callers wait for ended.
#[derive(Debug, Clone)]
pub(crate) enum DialEnd {
    /// The dialer pooled a connection.
    Ready,
    /// The dial failed, with the text of its error.
    Failed(String),
    /// The dialer was dropped before the dial ended, as a task that is aborted. Nobody failed to
    /// dial, so a waiter takes the place of the dialer and dials in its turn.
    DialerLeft,
}

impl UnicastPool {
    /// A pool wired to `endpoint`, able to dial and carry unicast traffic.
    pub(crate) fn new(endpoint: Endpoint, relay_transport: bool) -> Self {
        Self::with_timeouts(endpoint, relay_transport, DIRECT_IDLE_BACKSTOP, PROBE_HOLD)
    }

    /// [`Self::new`] with the idle timeout spelled out, for tests that must not
    /// wait the real one.
    #[cfg(test)]
    pub(crate) fn with_idle(endpoint: Endpoint, relay_transport: bool, idle: Duration) -> Self {
        Self::with_timeouts(endpoint, relay_transport, idle, PROBE_HOLD)
    }

    /// [`Self::new`] with the idle timeout and the probe hold spelled out.
    pub(crate) fn with_timeouts(
        endpoint: Endpoint,
        relay_transport: bool,
        idle: Duration,
        probe_hold: Duration,
    ) -> Self {
        Self {
            // the pool and its clones share the inner state
            inner: Arc::new(PoolInner {
                endpoint: Some(endpoint),
                conns: Mutex::new(HashMap::new()),
                #[cfg(test)]
                tap: std_Mutex::default(),
                idle,
                probe_hold,
                sweeping: AtomicBool::new(false),
                dial_failures: Mutex::new(Cooldown::new(DIAL_FAILURE_COOLDOWN)),
                dial_attempts: AtomicU64::new(0),
                #[cfg(test)]
                waiting: AtomicU64::new(0),
                #[cfg(test)]
                dials_started: AtomicU64::new(0),
                #[cfg(any(test, all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
                dials_made: std_Mutex::new(HashMap::new()),
                dialing: parking_lot::Mutex::new(HashMap::new()),
                addrs: std_Mutex::new(HashMap::new()),
                routes: parking_lot::Mutex::new(HashMap::new()),
                pinned_idle: PINNED_IDLE,
                #[cfg(test)]
                dial_gate: std_Mutex::new(None),
                #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
                outcome_hold: std_Mutex::new(None),
                relay_transport,
                admission: std_OnceLock::new(),
                tally: std_OnceLock::new(),
            }),
        }
    }

    /// Report the sends of this pool to `admission`, so that a connection with a send in
    /// flight is never evicted at the ceiling and a used one is not the least recently used.
    pub(crate) fn set_admission(&self, admission: SignalAdmission) {
        if let Some(endpoint) = &self.inner.endpoint {
            admission.set_local(endpoint.id());
        }
        let _ = self.inner.admission.set(admission);
    }

    /// Decide how the next dial of `eid` goes, before it starts, and once for the caller that is
    /// the dialer of the peer. At the ceiling of direct connections, with a multihop `route` to the
    /// peer, the dial takes that route and nothing else, and the peer is pinned: its connection
    /// takes no direct unit, and its path selector refuses any other path. Below the ceiling, or
    /// with no route, the dial is direct and evicts when its connection registers, as it always did.
    /// The decision and the reservation of a free unit are one step under the lock of the table, so
    /// that parallel dials at one unit below the ceiling do not all dial direct.
    fn plan_dial(&self, eid: EndpointId, route: Option<iroh::TransportAddr>) {
        let Some(admission) = self.inner.admission.get() else {
            return;
        };
        let plan = admission.plan_dial(eid, route.is_some());
        let mut routes = self.inner.routes.lock();
        match (plan, route) {
            (DialPlan::Multihop, Some(route)) => {
                tracing::debug!(target: LOG_TARGET, %eid, "at the ceiling: dialing through multihop and pinning the peer");
                routes.insert(eid, PlannedRoute { route, alone: true });
            }
            // A direct dial that has a route takes it as one more address: a peer that no direct
            // path reaches is reached through multihop, and iroh keeps the best path of the set.
            (DialPlan::Direct, Some(route)) => {
                routes.insert(
                    eid,
                    PlannedRoute {
                        route,
                        alone: false,
                    },
                );
            }
            (DialPlan::Direct | DialPlan::Multihop, None) => {
                routes.remove(&eid);
            }
        }
    }

    /// [`Self::dial_and_send`] after a failed write, planned again. A pinned peer is not dialed
    /// again here: only the loop holds a fresh route to it, so the next send plans the dial, and the
    /// frame of this one is dropped as the frame of any write that fails after QUIC buffered it. A
    /// waiter has the dial of another caller to wait for, and the dial turn serializes the two.
    ///
    /// This joins the two results of one send. `first` is the error of the first send. If that send
    /// had committed the frame, the peer can have taken it, so whatever the second send says, the
    /// result is [`SendVerdict::Unconfirmed`] unless the second send delivered. Only a first fault
    /// before the commit lets the result of the second send stand as it is.
    async fn redial_and_send(
        &self,
        eid: EndpointId,
        bytes: Bytes,
        first: &anyhow::Error,
    ) -> Result<()> {
        let outcome = match self.redial_registration(eid) {
            None => Err(anyhow::anyhow!("{PINNED_REDIAL}")),
            Some(registration) => match self.connection_for_send(registration, eid).await {
                Ok(connection) => self.send_on(eid, &connection, &bytes).await,
                Err(error) => Err(error),
            },
        };
        match outcome {
            Err(error) if committed(first) => {
                SendVerdict::Unconfirmed(format!("{error:#}")).into_result()
            }
            other => other,
        }
    }

    /// The place of a dial that comes again, planned with no route, or `None` for a pinned peer:
    /// a route that pinned it may be gone, and a direct redial would take a unit or evict a peer.
    pub(in crate::transport::pool) fn redial_registration(
        &self,
        eid: EndpointId,
    ) -> Option<Registration> {
        let pinned = self
            .inner
            .admission
            .get()
            .is_some_and(|admission| admission.is_pinned(eid));
        if pinned {
            return None;
        }
        Some(self.register_planned_dial(eid, || None))
    }

    /// Count the frames of this pool into `tally`, the tally of the loop that owns it.
    pub(crate) fn set_tally(&self, tally: WireOutTally) {
        let _ = self.inner.tally.set(tally);
    }

    /// [`send_one`], marked busy in the ledger for as long as it runs.
    pub(in crate::transport::pool) async fn send_marked(
        &self,
        eid: EndpointId,
        connection: &Connection,
        bytes: &[u8],
    ) -> Result<()> {
        let busy = self.inner.admission.get().map(|table| table.busy(eid));
        send_one(connection, bytes, busy, self.inner.tally.get()).await?;
        // The tap holds only the frames that were written, or a redial counts a frame twice.
        #[cfg(test)]
        if let Ok(mut tap) = self.inner.tap.lock() {
            tap.push(bytes.to_vec());
        }
        Ok(())
    }

    /// Tests only: one send on the warm connection to `eid`, with no second send after a lost
    /// connection, so that a test reads the fault of the first.
    #[cfg(test)]
    pub(crate) async fn send_without_redial(&self, eid: EndpointId, bytes: Bytes) -> Result<()> {
        let Some(connection) = self.warm(eid).await else {
            bail!("no warm connection");
        };
        self.send_marked(eid, &connection, &bytes).await
    }

    /// The frames written to pooled connections so far, as they went on the wire.
    #[cfg(test)]
    pub(crate) fn sent_frames(&self) -> Vec<Vec<u8>> {
        self.inner
            .tap
            .lock()
            .map(|tap| tap.clone())
            .unwrap_or_default()
    }

    /// A detached pool with no endpoint — every operation is a no-op. The
    /// default an [`EventLoopState`](crate::daemon::state::EventLoopState) holds
    /// until the real loop installs an endpoint-backed pool; also what the
    /// lower-level unit tests (which never run the transport) get.
    pub(crate) fn disconnected() -> Self {
        Self {
            // the pool and its clones share the inner state
            inner: Arc::new(PoolInner {
                endpoint: None,
                conns: Mutex::new(HashMap::new()),
                #[cfg(test)]
                tap: std_Mutex::default(),
                idle: DIRECT_IDLE_BACKSTOP,
                probe_hold: PROBE_HOLD,
                sweeping: AtomicBool::new(false),
                dial_failures: Mutex::new(Cooldown::new(DIAL_FAILURE_COOLDOWN)),
                dial_attempts: AtomicU64::new(0),
                #[cfg(test)]
                waiting: AtomicU64::new(0),
                #[cfg(test)]
                dials_started: AtomicU64::new(0),
                #[cfg(any(test, all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
                dials_made: std_Mutex::new(HashMap::new()),
                dialing: parking_lot::Mutex::new(HashMap::new()),
                addrs: std_Mutex::new(HashMap::new()),
                routes: parking_lot::Mutex::new(HashMap::new()),
                pinned_idle: PINNED_IDLE,
                #[cfg(test)]
                dial_gate: std_Mutex::new(None),
                #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
                outcome_hold: std_Mutex::new(None),
                relay_transport: false,
                admission: OnceLock::new(),
                tally: std_OnceLock::new(),
            }),
        }
    }

    /// Send `bytes` over a warm connection to `eid` if one exists. `Cold` means no warm
    /// connection: the caller then dials via [`Self::dial_and_send`]. The send runs on a task so
    /// the event loop never blocks on QUIC I/O, and the handle of `Sent` gives its verdict: the
    /// peer took the frame (see [`send_one`]), or it did not. A send that ends with no
    /// acknowledgement because the connection ended evicts the connection and redials-and-resends
    /// once. A peer that said no ([`SendFault::NotTaken`]) and a send that timed out ([`SEND_TIMEOUT`],
    /// [`SEND_ANSWER_TIMEOUT`]) are not sent again: the peer is there.
    pub(crate) async fn send_if_warm(&self, eid: EndpointId, bytes: Bytes) -> WarmSend {
        let Some(connection) = self.warm(eid).await else {
            return WarmSend::Cold;
        };
        if !payload_allowed_on(&connection, self.inner.relay_transport) {
            return WarmSend::Refused;
        }
        let pool = self.clone();
        let (verdict, outcome) = oneshot::channel();
        task::spawn(async move {
            let sent = pool.send_acknowledged(eid, &connection, bytes).await;
            if let Err(error) = &sent {
                tracing::debug!(target: LOG_TARGET, %error, "unicast frame not delivered");
            }
            let _ = verdict.send(SendVerdict::of(sent));
        });
        WarmSend::Sent(outcome)
    }

    /// [`Self::send_marked`] on `connection`, and one more send after a redial when the first ended
    /// because the connection was lost. A peer that said no, and a deadline, are the verdict at once.
    async fn send_acknowledged(
        &self,
        eid: EndpointId,
        connection: &Connection,
        bytes: Bytes,
    ) -> Result<()> {
        let Err(error) = self.send_marked(eid, connection, &bytes).await else {
            return Ok(());
        };
        if !connection_lost(&error) {
            return Err(error);
        }
        tracing::debug!(target: LOG_TARGET, %error, "unicast send not acknowledged; dropping connection and redialing");
        self.evict_if_same(eid, connection).await;
        self.redial_and_send(eid, bytes, &error).await
    }

    /// Whether UDP to `eid` is selected within [`PATH_SELECT_TIMEOUT`], on the
    /// pooled connection, dialed if there is none. A gossip link can form with
    /// no pooled connection at all, so the synchronous read below cannot
    /// answer for a pair that linked through the rendezvous.
    pub(crate) async fn udp_won(&self, eid: EndpointId) -> bool {
        let won = match self.probe_connection(eid).await {
            Ok(connection) => payload_path::wait_ip(&connection, PATH_SELECT_TIMEOUT).await,
            Err(_) => false,
        };
        self.probe_done(eid).await;
        won
    }

    /// Remember `addr` as the address to dial its peer at.
    pub(crate) fn note_addr(&self, address: &EndpointAddr) {
        if let Ok(mut addrs) = self.inner.addrs.lock() {
            addrs.insert(address.id, address.clone());
        }
    }

    /// Whether `address` is the dial address remembered for its endpoint. Only `note_addr` writes
    /// it, next to the address book, so a dial hint that names the address does not count.
    pub(crate) fn remembers_address(&self, address: &EndpointAddr) -> bool {
        self.inner
            .addrs
            .lock()
            .is_ok_and(|addrs| addrs.get(&address.id) == Some(address))
    }

    /// Tests only: whether any dial is in flight.
    #[cfg(test)]
    pub(crate) fn is_dialing_any(&self) -> bool {
        !self.inner.dialing.lock().is_empty()
    }

    /// Tests only: how many callers wait now for the dial of another caller.
    #[cfg(test)]
    pub(crate) fn waiting_callers(&self) -> u64 {
        self.inner.waiting.load(Ordering::Relaxed)
    }

    /// Tests only: whether a dial to `eid` is in flight.
    #[cfg(test)]
    pub(crate) fn is_dialing(&self, eid: EndpointId) -> bool {
        self.inner.dialing.lock().contains_key(&eid)
    }

    /// The dial address remembered for `eid`, if any.
    #[cfg(test)]
    pub(crate) fn remembered_address(&self, eid: EndpointId) -> Option<EndpointAddr> {
        let addrs = self.inner.addrs.lock().ok()?;
        addrs.get(&eid).cloned()
    }

    /// Drop the remembered dial address of `eid`. The pooled connection stays open: the caller
    /// uses this when only the address has no owner left.
    pub(crate) fn forget_addr(&self, eid: EndpointId) {
        if let Ok(mut addrs) = self.inner.addrs.lock() {
            addrs.remove(&eid);
        }
    }

    /// Whether a dial address of `eid` is remembered.
    #[cfg(test)]
    pub(crate) fn has_addr(&self, eid: EndpointId) -> bool {
        self.inner
            .addrs
            .lock()
            .is_ok_and(|addrs| addrs.contains_key(&eid))
    }

    /// The open pooled connection to `eid`, whoever opened it. A contended lock
    /// reads as none.
    #[cfg(test)]
    pub(crate) fn connection(&self, eid: EndpointId) -> Option<Connection> {
        self.inner.conns.try_lock().ok().and_then(|conns| {
            let pooled = conns.get(&eid).map(|pooled| &pooled.connection);
            pooled
                .filter(|connection| connection.close_reason().is_none())
                .cloned()
        })
    }

    /// The open pooled connection to `eid` that a send opened or used. A
    /// connection that only a direct-path probe opened is not one: the pair was
    /// never sent to. A contended lock reads as none.
    pub(crate) fn used_connection(&self, eid: EndpointId) -> Option<Connection> {
        self.inner.conns.try_lock().ok().and_then(|conns| {
            let used = conns.get(&eid).filter(|pooled| pooled.hold == Hold::Used);
            let pooled_connection = used.map(|pooled| &pooled.connection);
            let open = pooled_connection.filter(|connection| connection.close_reason().is_none());
            open.cloned()
        })
    }

    /// Whether the pooled connection to `eid` is on a selected UDP path. The
    /// offer decisions read the admission table instead, which sees every
    /// connection of the peer and not only the pooled one.
    #[cfg(test)]
    pub(crate) fn selected_is_ip(&self, eid: EndpointId) -> bool {
        self.inner.conns.try_lock().is_ok_and(|conns| {
            conns.get(&eid).is_some_and(|pooled| {
                pooled.connection.close_reason().is_none()
                    && payload_path::selected_is_ip(&pooled.connection)
            })
        })
    }

    /// Whether a connection to `eid` is open and can carry a payload. It does not count as a use of
    /// it. The payload check is the one of [`Self::send_if_warm`]: an open connection that the
    /// relay selected, on a mesh whose relay is lookup only, refuses every payload
    /// ([`RELAY_REFUSED`]), so a caller that reads it as a path pays for the frame it builds and
    /// loses it at the send.
    pub(crate) async fn has_warm(&self, eid: EndpointId) -> bool {
        let conns = self.inner.conns.lock().await;
        conns.get(&eid).is_some_and(|pooled| {
            pooled.connection.close_reason().is_none()
                && payload_allowed_on(&pooled.connection, self.inner.relay_transport)
        })
    }

    /// The pooled connection to `eid`, if one is open. Taking it counts as
    /// using it: every caller is about to send or probe on it.
    pub(in crate::transport::pool) async fn warm(&self, eid: EndpointId) -> Option<Connection> {
        let mut conns = self.inner.conns.lock().await;
        let slot = conns.get_mut(&eid);
        let pooled = slot.filter(|pooled| pooled.connection.close_reason().is_none())?;
        pooled.last_used = PoolInstant::now();
        pooled.hold = Hold::Used;
        Some(pooled.connection.clone())
    }

    /// Drop the pooled connection of `eid`, but only if it is still `connection`. A write that
    /// fails takes up to [`SEND_ANSWER_TIMEOUT`], and another send can dial a replacement in that time: an
    /// eviction by endpoint id alone throws the replacement away, and every send that follows pays
    /// for a cold dial.
    pub(in crate::transport::pool) async fn evict_if_same(
        &self,
        eid: EndpointId,
        connection: &Connection,
    ) {
        let mut conns = self.inner.conns.lock().await;
        let pooled_id: Option<usize> = conns.get(&eid).map(|pooled| pooled.connection.stable_id());
        let same = pooled_id == Some(connection.stable_id());
        if same {
            conns.remove(&eid);
        }
    }

    /// Close the connections nothing has used for [`PoolInner::idle`], and the
    /// connections of a probe that ended [`PoolInner::probe_hold`] ago with no
    /// send taking them. One task for the whole pool, started with the first
    /// connection and gone with the pool.
    fn ensure_sweeper(&self) {
        if self.inner.sweeping.swap(true, Ordering::AcqRel) {
            return;
        }
        let pool = Arc::downgrade(&self.inner);
        let period = (self
            .inner
            .idle
            .min(self.inner.probe_hold)
            .min(self.inner.pinned_idle)
            / 4)
        .max(Duration::from_millis(1));
        task::spawn(async move {
            loop {
                time::sleep(period).await;
                let Some(inner) = pool.upgrade() else {
                    return;
                };
                let now = PoolInstant::now();
                inner.conns.lock().await.retain(|eid, pooled| {
                    let idle = match pooled.hold {
                        Hold::Probed(ended) => {
                            now.saturating_duration_since(ended) >= inner.probe_hold
                        }
                        Hold::Used | Hold::Probing => {
                            let table = inner.admission.get();
                            let extra: bool = table.map_or(pooled.pinned, |admission| {
                                admission.is_pinned(*eid) || admission.is_extra(*eid)
                            });
                            let idle = if extra {
                                inner.idle.min(inner.pinned_idle)
                            } else {
                                inner.idle
                            };
                            now.saturating_duration_since(pooled.last_used) >= idle
                        }
                    };
                    if idle {
                        let local: String = inner.endpoint.as_ref().map_or_else(String::new, |endpoint| {
                            endpoint.id().fmt_short().to_string()
                        });
                        tracing::debug!(target: LOG_TARGET, %local, %eid, "closing an idle pooled unicast connection");
                        pooled.connection.close(IDLE.into(), b"idle");
                    }
                    !idle
                });
            }
        });
    }

    /// How many times the inline-dial path was entered, for tests asserting a
    /// caller stayed off it.
    #[cfg(test)]
    pub(crate) fn dial_attempts(&self) -> u64 {
        self.inner.dial_attempts.load(Ordering::Relaxed)
    }

    /// Start a send to `eid` on a spawned task, and return whether one was started. `false` when
    /// `eid` is on the dial-failure cooldown: nothing is sent, and the caller can try again later. A
    /// frame for a peer whose dial is in flight waits for that dial and is sent after it. The guard
    /// of the dial is taken here, before the spawn: a task that took it would leave a gap in which a
    /// dial that ends at once removes its entry before the next caller looks for it.
    pub(crate) async fn dial_and_send_in_background(
        &self,
        eid: EndpointId,
        bytes: Bytes,
        route: impl FnOnce() -> Option<iroh::TransportAddr>,
    ) -> bool {
        if self.is_cooling(eid).await {
            return false;
        }
        let registration = self.register_dial(eid);
        // A waiter has a dial to wait for. A dialer takes the route to the peer at the ceiling and
        // pins it, or takes a free unit. A courtesy dial that finds neither evicts nobody: a backfill
        // is not the answer to a request, and the peer is reached through multihop when a send needs it.
        if matches!(registration, Registration::Dialer(_)) {
            match route() {
                Some(route) => self.plan_dial(eid, Some(route)),
                None if self.reserve_unprompted_dial(eid) => {}
                None => {
                    tracing::debug!(target: LOG_TARGET, %eid, "no courtesy dial: the node is at its ceiling and has no route");
                    return false;
                }
            }
        }
        let pool = self.clone();
        task::spawn(async move {
            if let Err(error) = pool.send_registered(registration, eid, bytes).await {
                tracing::debug!(target: LOG_TARGET, %eid, %error, "background send not delivered");
            }
        });
        true
    }

    /// Tests only: how many dials this pool made to `eid`: each reaches the endpoint, whether it
    /// takes a route or an address, and a send over a warm connection is not one.
    #[cfg(any(test, all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
    pub(crate) fn dials_to(&self, eid: EndpointId) -> u64 {
        let made = self.inner.dials_made.lock().ok();
        made.and_then(|made| made.get(&eid).copied()).unwrap_or(0)
    }

    /// Tests only: hold the next dial until the returned [`Notify`](tokio::sync::Notify) is notified.
    #[cfg(test)]
    // the gate is shared by the dial and the test that holds it
    pub(crate) fn hold_next_dial(&self) -> Arc<Notify> {
        // the gate is shared by the dial and the test that holds it
        let gate = Arc::new(Notify::new());
        if let Ok(mut slot) = self.inner.dial_gate.lock() {
            *slot = Some(Arc::clone(&gate));
        }
        gate
    }

    /// Forget the pooled connection of `eid` and its dial-failure cooldown, and keep its address,
    /// so that the next send to it is cold. For a test that needs a cold send. The connection is
    /// closed. Returns whether one was pooled.
    #[cfg(any(test, all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
    pub(crate) async fn drop_connection(&self, eid: EndpointId) -> bool {
        let pooled = self.inner.conns.lock().await.remove(&eid);
        self.inner.dial_failures.lock().await.forget(&eid);
        let was_pooled = pooled.is_some();
        if let Some(pooled) = pooled {
            pooled.connection.close(IDLE.into(), b"dropped by a test");
        }
        was_pooled
    }

    /// Whether a send to `eid` has a dial or a path wait in flight. A cold send now would wait
    /// for it and take its outcome. For a test whose send must be its own dialer.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) fn dial_in_flight(&self, eid: EndpointId) -> bool {
        self.inner.dialing.lock().contains_key(&eid)
    }

    /// Close the pooled connection of `eid` if it is pinned: the route that it rides is gone, and a
    /// pinned connection has no other reason to stay. A direct connection of the peer is left
    /// alone. Returns whether a connection was closed.
    pub(crate) async fn close_pinned(&self, eid: EndpointId) -> bool {
        let pinned_now = self.is_pinned_now(eid);
        let mut conns = self.inner.conns.lock().await;
        if !pinned_now || !conns.get(&eid).is_some_and(|pooled| pooled.pinned) {
            return false;
        }
        if let Some(pooled) = conns.remove(&eid) {
            tracing::debug!(target: LOG_TARGET, %eid, "closing a pinned connection: its route is gone");
            pooled.connection.close(IDLE.into(), b"route lost");
        }
        true
    }

    /// Whether `eid` is on the dial-failure cooldown.
    pub(crate) async fn is_cooling(&self, eid: EndpointId) -> bool {
        self.inner
            .dial_failures
            .lock()
            .await
            .on_cooldown(&eid, Instant::now())
    }

    /// Tests only: forget the pooled connection of `eid` and put it on the dial-failure cooldown, as
    /// a failed dial does. It waits for the dial that runs for the peer, because a dial that ends
    /// after it would clear the cooldown and pool a connection, and the next send would not meet
    /// the cooldown that the test asked for. A caller that waits behind it gets the text "the dial
    /// was failed for a test", which a test reads as its own doing and not as a product error.
    #[cfg(any(test, all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
    pub(crate) async fn fail_dial_for_test(&self, eid: EndpointId) {
        let in_flight = loop {
            match self.register_dial(eid) {
                Registration::Dialer(in_flight) => break in_flight,
                Registration::Waiter(outcome) => {
                    let _ended = wait_for_dial(outcome).await;
                }
            }
        };
        self.drop_connection(eid).await;
        self.note_dial_failure(eid).await;
        in_flight.publish(Err("the dial was failed for a test".to_owned()));
    }

    /// Put `eid` on the dial-failure cooldown, as a failed dial does.
    #[cfg(any(test, all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
    pub(crate) async fn note_dial_failure(&self, eid: EndpointId) {
        self.inner
            .dial_failures
            .lock()
            .await
            .note(eid, Instant::now());
    }

    /// Ensure a connection to `eid` (reusing a warm one or dialing inline) and
    /// send `bytes` over it, awaiting the handoff. The cold path for every
    /// directed send — there is no other transport to carry the first message.
    ///
    /// # Errors
    /// A detached pool, an endpoint on failed-dial cooldown, a dial that
    /// fails/times out, or a stream write error.
    pub(crate) async fn dial_and_send(&self, eid: EndpointId, bytes: Bytes) -> Result<()> {
        self.send_registered(self.register_dial(eid), eid, bytes)
            .await
    }

    /// The connection that a send to `eid` writes on, through the registration of its dial: a warm
    /// one, or one that the dialer of the peer dials, and with a direct path when the relay is lookup
    /// only. A waiter wants a connection and sends its own frame, so it never waits for the frame of
    /// the dialer or takes its verdict.
    async fn connection_for_send(
        &self,
        registration: Registration,
        eid: EndpointId,
    ) -> Result<Connection> {
        if matches!(registration, Registration::Dialer(_)) {
            self.inner.dial_attempts.fetch_add(1, Ordering::Relaxed);
        }
        let connection = self
            .connection_through(registration, eid, Hold::Used)
            .await?;
        // A connection this call just dialed is milliseconds old: its
        // non-relay path (the punch, or a WebRTC path opened right after
        // `AddConnection`) is still forming, and the synchronous check read
        // "no path selected yet" as relay — refusing the *first* directed
        // frame to every peer without a warm connection. Wait like the
        // accept side does, on a dial-sized budget. Each caller waits for itself: a
        // connection that a probe dialed has no path wait behind it.
        if !self.inner.relay_transport
            && !payload_path::wait_direct(&connection, PATH_SELECT_TIMEOUT).await
        {
            bail!("{RELAY_REFUSED}");
        }
        Ok(connection)
    }

    /// The pooled connection to `eid` for a caller that reads it with `hold`, through its place in
    /// the registry of dials. The dialer dials, publishes how the dial ended, and returns the
    /// connection. A waiter waits for that, and reads the connection with its own `hold`: a send
    /// turns a connection that a probe dialed into a used one, and a probe leaves a connection that
    /// a send dialed as it is. If the connection is gone by then, the waiter takes a new place, and
    /// the next caller waits for it.
    ///
    /// A waiter that reads [`DialEnd::DialerLeft`] takes the place of the dialer, and that is safe for
    /// the callers that exist: the only dialers that are dropped while the node runs are the probes of
    /// the offer round (`udp_won`), a probe registers only when a unit is free, and only a dialer plans
    /// a dial, which is what pins a peer. So a pinned peer never has a dropped dialer; if one had, the
    /// waiter would get [`PINNED_REDIAL`], a refusal that the next send mends. A new caller that can be
    /// dropped must keep that true.
    ///
    /// A caller that waits can wait again behind a new dial each time its connection is lost, and no
    /// code bounds the turns (see `LONGEST_SEND_CALL`). A caller that holds a place from the event
    /// loop (`register_planned_dial` in `deliver`) takes it there, before it spawns, because the plan
    /// of the dial reads the state of the loop, and a place taken inside the task would plan from a
    /// later state.
    async fn connection_through(
        &self,
        mut registration: Registration,
        eid: EndpointId,
        hold: Hold,
    ) -> Result<Connection> {
        loop {
            match registration {
                Registration::Dialer(in_flight) => {
                    let dialed = self.dial_now(eid, hold).await;
                    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
                    self.wait_outcome_hold(eid).await;
                    in_flight.publish(match &dialed {
                        Ok(_) => Ok(()),
                        Err(error) => Err(error.to_string()),
                    });
                    return dialed;
                }
                Registration::Waiter(outcome) => {
                    #[cfg(test)]
                    self.inner.waiting.fetch_add(1, Ordering::Relaxed);
                    let ended = wait_for_dial(outcome).await;
                    #[cfg(test)]
                    self.inner.waiting.fetch_sub(1, Ordering::Relaxed);
                    if let DialEnd::Failed(error) = ended {
                        bail!(error);
                    }
                    if let Some(connection) = self.open_pooled(eid, hold).await {
                        return Ok(connection);
                    }
                    let Some(next) = self.redial_registration(eid) else {
                        bail!("{PINNED_REDIAL}");
                    };
                    registration = next;
                }
            }
        }
    }

    /// One send of `bytes` on `connection`. A connection that was lost leaves the pool.
    async fn send_on(&self, eid: EndpointId, connection: &Connection, bytes: &Bytes) -> Result<()> {
        if let Err(error) = self.send_marked(eid, connection, bytes).await {
            if connection_lost(&error) {
                self.evict_if_same(eid, connection).await;
            }
            return Err(error);
        }
        Ok(())
    }

    /// Send `bytes` to `eid`, and dial a peer once, not once for each frame. A warm connection takes
    /// the frame at once. A cold peer with no dial in flight is dialed by this caller, which
    /// publishes the outcome of its dial. A cold peer whose dial is in flight is waited for, and
    /// the frame is written on the connection that dial made. A waiter whose dialer failed gets the
    /// error of that dial and does not dial again: the peer is on the dial-failure cooldown by then.
    ///
    /// # Errors
    /// A refused path, a dial or a path wait or a write that fails, a peer on the dial-failure
    /// cooldown, or the error of the dial that this call waited for.
    #[cfg(test)]
    pub(crate) async fn dial_or_warm_send(&self, eid: EndpointId, bytes: Bytes) -> Result<()> {
        match self.send_if_warm(eid, bytes.clone()).await {
            WarmSend::Sent(pending) => return verdict_of(pending).await,
            WarmSend::Refused => bail!("{RELAY_REFUSED}"),
            WarmSend::Cold => {}
        }
        self.send_registered(self.register_dial(eid), eid, bytes)
            .await
    }

    /// The send of a caller that has taken its place already, with [`Self::register_dial`]. The
    /// dialer dials and publishes how the dial ended, and sends its own frame. A waiter waits for the
    /// outcome, then sends its own frame on the connection that the dial made; if the connection is
    /// gone by then, it takes a new place, and the next caller waits for it.
    ///
    /// # Errors
    /// A refused path, a dial or a path wait or a write that fails, a peer on the dial-failure
    /// cooldown, or the error of the dial that this call waited for.
    pub(crate) async fn send_registered(
        &self,
        registration: Registration,
        eid: EndpointId,
        bytes: Bytes,
    ) -> Result<()> {
        let connection = self.connection_for_send(registration, eid).await?;
        match self.send_on(eid, &connection, &bytes).await {
            Err(error) if connection_lost(&error) => self.redial_and_send(eid, bytes, &error).await,
            other => other,
        }
    }

    /// Tests only: hold the outcome of the next dial of `eid`, after its dial and before it is
    /// published. The first receiver resolves once the dialer holds; the dialer goes
    /// on once the second sender sends or is dropped.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    pub(crate) fn hold_next_outcome(
        &self,
        eid: EndpointId,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached_tx, reached) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        if let Ok(mut slot) = self.inner.outcome_hold.lock() {
            *slot = Some((eid, reached_tx, release_rx));
        }
        (reached, release)
    }

    /// Wait on the hold of [`Self::hold_next_outcome`], if one is set for `eid`.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    async fn wait_outcome_hold(&self, eid: EndpointId) {
        let held: Option<OutcomeHold> = self.inner.outcome_hold.lock().ok().and_then(|mut slot| {
            if slot.as_ref().is_some_and(|(peer, _, _)| *peer == eid) {
                slot.take()
            } else {
                None
            }
        });
        if let Some((_, reached, release)) = held {
            let _ = reached.send(());
            let _ = release.await;
        }
    }

    /// Make this caller the dialer of `eid`, or the waiter of the dial or the path wait that is in
    /// flight. Taken by the caller itself, synchronously, before the task that sends is spawned.
    pub(crate) fn register_dial(&self, eid: EndpointId) -> Registration {
        let mut dialing = self.inner.dialing.lock();
        if let Some(outcome) = dialing.get(&eid) {
            return Registration::Waiter(outcome.clone());
        }
        let (outcome_tx, outcome) = watch::channel(None);
        dialing.insert(eid, outcome);
        Registration::Dialer(InFlightDial {
            pool: self.clone(),
            eid,
            outcome_tx,
        })
    }

    /// [`Self::register_dial`] for a send. The caller that becomes the dialer of the peer also
    /// plans the dial: `route` is read only then (see [`Self::plan_dial`]). A waiter plans nothing,
    /// because the dial that it waits for is planned already.
    pub(crate) fn register_planned_dial(
        &self,
        eid: EndpointId,
        route: impl FnOnce() -> Option<iroh::TransportAddr>,
    ) -> Registration {
        let registration = self.register_dial(eid);
        if matches!(registration, Registration::Dialer(_)) {
            self.plan_dial(eid, route());
        }
        registration
    }

    /// The pooled connection to `eid`, dialing one if none is warm, through the registry of dials like
    /// every other caller. Tests and test hooks only: the sends of the engine and its direct-path probe
    /// ask for their connection with their own hold.
    ///
    /// # Errors
    /// See [`Self::dial_and_send`].
    #[cfg(any(test, all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
    pub(crate) async fn warm_or_dial(&self, eid: EndpointId) -> Result<Connection> {
        if self.inner.endpoint.is_none() {
            bail!("unicast pool has no endpoint");
        }
        if let Some(connection) = self.warm(eid).await {
            return Ok(connection);
        }
        let registration = self.register_dial(eid);
        self.connection_through(registration, eid, Hold::Used).await
    }

    /// The pooled connection that a direct-path probe uses: the one a send
    /// already opened, left as it is, or else one dialed for the probe, which
    /// does not count as a send. See [`Self::probe_done`].
    ///
    /// # Errors
    /// See [`Self::dial_and_send`].
    pub(crate) async fn probe_connection(&self, eid: EndpointId) -> Result<Connection> {
        if self.inner.endpoint.is_none() {
            bail!("unicast pool has no endpoint");
        }
        let existing: Option<Connection> = {
            let conns = self.inner.conns.lock().await;
            let pooled = conns.get(&eid).map(|pooled| &pooled.connection);
            pooled
                .filter(|connection| connection.close_reason().is_none())
                .cloned()
        };
        if let Some(connection) = existing {
            return Ok(connection);
        }
        if self
            .inner
            .admission
            .get()
            .is_some_and(|table| table.evicted_recently(eid))
        {
            bail!("unicast probe waits: the peer evicted our connection lately");
        }
        if !self.reserve_unprompted_dial(eid) {
            bail!("{AT_CEILING}");
        }
        // A probe that dials owns the unit that it reserved, and gives it back when it fails. A probe
        // that waits for the dial of another caller owns nothing: the dialer holds the reservation of
        // the peer, and a send that waits behind a probe uses the unit that the probe reserved.
        let registration = self.register_dial(eid);
        let release =
            matches!(registration, Registration::Dialer(_)).then(|| PlanRelease::new(self, eid));
        let result = self
            .connection_through(registration, eid, Hold::Probing)
            .await;
        if result.is_ok()
            && let Some(release) = release
        {
            release.disarm();
        }
        result
    }

    /// The probe on `eid` has ended, whatever its verdict. A connection that only
    /// the probe opened now closes after the probe hold, unless a send takes it
    /// first. A connection that a send opened is left alone.
    pub(crate) async fn probe_done(&self, eid: EndpointId) {
        if let Some(pooled) = self.inner.conns.lock().await.get_mut(&eid)
            && pooled.hold == Hold::Probing
        {
            pooled.hold = Hold::Probed(PoolInstant::now());
        }
    }

    /// The open pooled connection of `eid`, if there is one. A caller that sends with it (`hold` is `Used`) takes it as
    /// [`warm`](Self::warm) does: the hold of the connection becomes `Used`. A probe leaves the hold the connection has, so a probe
    /// dial that finds a connection of a send does not turn it into a probe hold.
    ///
    /// The `Probing` hold matters here: the sweeper closes a connection that is `Probed` for longer than the probe
    /// hold, and a connection is `Probed` only if its hold was `Probing` when the probe ended. A send that takes a
    /// `Probing` connection without marking it `Used` would let the sweeper close a connection in use.
    async fn open_pooled(&self, eid: EndpointId, hold: Hold) -> Option<Connection> {
        let mut conns = self.inner.conns.lock().await;
        let pooled: &mut Pooled = conns
            .get_mut(&eid)
            .filter(|pooled| pooled.connection.close_reason().is_none())?;
        if matches!(hold, Hold::Used) {
            pooled.last_used = PoolInstant::now();
            pooled.hold = Hold::Used;
        }
        Some(pooled.connection.clone())
    }

    /// Dial `eid` and pool the connection under `hold`. Only the dialer of the peer calls this, from
    /// [`Self::connection_through`], so one dial runs for each peer at a time and a dial starts only when no
    /// connection of the peer is open: an insert never replaces a live connection. A replaced
    /// connection must be closed with `close()`, not dropped: an unacknowledged frame on a dropped
    /// connection is lost.
    async fn dial_now(&self, eid: EndpointId, hold: Hold) -> Result<Connection> {
        let planned = self.inner.routes.lock().remove(&eid);
        if let Some(connection) = self.open_pooled(eid, hold).await {
            self.release_plan(eid);
            return Ok(connection);
        }
        let Some(endpoint) = self.inner.endpoint.clone() else {
            bail!("unicast pool has no endpoint");
        };
        if self
            .inner
            .dial_failures
            .lock()
            .await
            .on_cooldown(&eid, Instant::now())
        {
            bail!("{COOLDOWN_REFUSED}");
        }
        let pinned = planned.as_ref().is_some_and(|planned| planned.alone);
        let address: EndpointAddr = self.dial_address(eid, planned);
        #[cfg(test)]
        {
            let gate = {
                let gate_slot = self.inner.dial_gate.lock().ok();
                gate_slot.and_then(|mut slot| slot.take())
            };
            if let Some(gate) = gate {
                gate.notified().await;
            }
        }
        #[cfg(test)]
        self.inner.dials_started.fetch_add(1, Ordering::Relaxed);
        #[cfg(any(test, all(feature = "iroh-test-utils", not(target_arch = "wasm32"))))]
        if let Ok(mut made) = self.inner.dials_made.lock() {
            *made.entry(eid).or_insert(0) += 1;
        }
        match dial(&endpoint, address).await {
            Ok(connection) => {
                self.inner.dial_failures.lock().await.forget(&eid);
                let mut conns = self.inner.conns.lock().await;
                debug_assert!(
                    conns
                        .get(&eid)
                        .is_none_or(|pooled| pooled.connection.close_reason().is_some()),
                    "a dial must not replace an open pooled connection"
                );
                conns.insert(
                    eid,
                    Pooled {
                        connection: connection.clone(),
                        last_used: PoolInstant::now(),
                        hold,
                        pinned,
                    },
                );
                drop(conns);
                self.ensure_sweeper();
                Ok(connection)
            }
            Err(error) => {
                self.release_plan(eid);
                self.inner
                    .dial_failures
                    .lock()
                    .await
                    .note(eid, Instant::now());
                Err(error)
            }
        }
    }

    /// Whether a dial that no send asked for (a probe, a courtesy reply) may take a unit for `eid`
    /// now. Without a table it always may. It reserves nothing: a caller that dials takes the
    /// unit with [`Self::reserve_unprompted_dial`].
    pub(crate) fn has_room_for_unprompted_dial(&self, eid: EndpointId) -> bool {
        self.inner
            .admission
            .get()
            .is_none_or(|admission| admission.has_room(eid))
    }

    /// The peers that hold a unit now, for a debug line.
    pub(crate) fn unit_holders(&self) -> String {
        self.inner
            .admission
            .get()
            .map_or_else(String::new, SignalAdmission::holders)
    }

    /// Take a unit for a dial that no send asked for, or refuse it when the node is at its
    /// ceiling: such a dial evicts nobody. The dial gives the unit back when it ends with no
    /// connection (see [`Self::release_plan`]).
    fn reserve_unprompted_dial(&self, eid: EndpointId) -> bool {
        self.inner
            .admission
            .get()
            .is_none_or(|admission| admission.reserve_proactive(eid))
    }

    /// The dial that [`Self::plan_dial`] planned ends without a new connection: the unit that it
    /// reserved and the pin that it set go back.
    /// The address of the next dial of `eid`. A pinned dial takes its route and no other address. Any
    /// other dial takes the address that the peer gave, and the route to the peer, if the plan had
    /// one, as one more address.
    pub(in crate::transport::pool) fn dial_address(
        &self,
        eid: EndpointId,
        planned: Option<PlannedRoute>,
    ) -> EndpointAddr {
        if let Some(PlannedRoute { route, alone: true }) = planned {
            return EndpointAddr::from_parts(eid, [route]);
        }
        let addrs = self.inner.addrs.lock().ok();
        let stored = addrs.and_then(|addrs| addrs.get(&eid).cloned());
        let mut address = stored.unwrap_or_else(|| EndpointAddr::new(eid));
        if let Some(planned) = planned {
            address.addrs.insert(planned.route);
        }
        address
    }

    /// Whether the ledger still pins `eid`: a peer that became a gossip neighbor is not pinned any
    /// more, though its pooled connection was dialed on a route. With no table, the flag of the
    /// pooled connection decides alone.
    fn is_pinned_now(&self, eid: EndpointId) -> bool {
        self.inner
            .admission
            .get()
            .is_none_or(|admission| admission.is_pinned(eid))
    }

    pub(in crate::transport::pool) fn release_plan(&self, eid: EndpointId) {
        if let Some(admission) = self.inner.admission.get() {
            admission.release_dial(eid);
        }
    }

    /// Drop `eid`'s pooled connection and dial-failure cooldown: the peer left
    /// gracefully, so neither may serve or block a future dial (a rejoin
    /// re-dials cold). The connection is closed explicitly — `Connection` is a
    /// cheap clone handle, and in-flight spawned writers hold clones, so just
    /// dropping the map entry would leave the QUIC connection open until every
    /// clone drops.
    pub(crate) async fn forget(&self, eid: EndpointId) {
        if let Some(pooled) = self.inner.conns.lock().await.remove(&eid) {
            pooled.connection.close(0u32.into(), b"peer left");
        }
        self.inner.dial_failures.lock().await.forget(&eid);
        self.inner.routes.lock().remove(&eid);
        self.release_plan(eid);
        // A rejoin may come back at another address; its `PeerInfo` notes it.
        if let Ok(mut addrs) = self.inner.addrs.lock() {
            addrs.remove(&eid);
        }
    }
}

/// The multihop route that the plan of a dial found for a peer. `alone` says whether the dial takes
/// it with no other address (a pinned dial), or as one more address beside the others.
#[derive(Debug, Clone)]
pub(in crate::transport::pool) struct PlannedRoute {
    route: iroh::TransportAddr,
    alone: bool,
}

/// Wait for the dialer of a peer to publish how its dial ended. The current value is read first, so
/// that a receiver made after the publish still sees it. A dialer that is dropped with no outcome
/// ends as [`DialEnd::DialerLeft`].
async fn wait_for_dial(mut outcome: watch::Receiver<DialOutcome>) -> DialEnd {
    loop {
        if let Some(done) = outcome.borrow_and_update().clone() {
            return done;
        }
        if outcome.changed().await.is_err() {
            return DialEnd::DialerLeft;
        }
    }
}

/// Dial `eid` on the unicast ALPN within [`DIAL_TIMEOUT`]. The endpoint already
/// knows the peer's address (registered via `add_peer_addr`), so a bare-id
/// `EndpointAddr` resolves through the endpoint's address book + lookups.
async fn dial(endpoint: &Endpoint, address: EndpointAddr) -> Result<Connection> {
    match time::timeout(DIAL_TIMEOUT, endpoint.connect(address, UNICAST_ALPN)).await {
        Ok(Ok(connection)) => Ok(connection),
        Ok(Err(error)) => Err(anyhow::anyhow!("{error}")),
        Err(_) => bail!("unicast dial timed out after {DIAL_TIMEOUT:?}"),
    }
}

/// One frame per bidirectional stream, in two steps. The sender writes the length and the frame and
/// does not finish. The peer takes a place in its inbox for the frame, and says `HELD`. The sender
/// then commits by finishing its side, and the peer hands the frame to its loop only after it.
/// Last, the peer ends its side, and the end is the acknowledgement. An `Ok` says that the peer took
/// the frame.
///
/// The phase is the phase of the sender. A fault before the commit is certain: the peer never takes
/// the frame, because the stream goes away uncommitted (see [`OutgoingFrame`]), and a second send
/// is safe. A fault after the commit is not: the peer can have taken the frame, and the sender did
/// not hear it. An error then means "not confirmed". The connection is busy in the ledger until the
/// end or the error.
pub(super) async fn send_one(
    connection: &Connection,
    bytes: &[u8],
    _busy: Option<BusyGuard>,
    tally: Option<&WireOutTally>,
) -> Result<(), SendFault> {
    // The open and the write share one deadline of SEND_TIMEOUT: both are local, and a peer that reads
    // nothing fills its limit of streams, so the open of the next stream waits for room that never
    // comes. The wait for HELD and the wait for the end are each SEND_ANSWER_TIMEOUT, because the path
    // of the connection can die with no signal and the transport needs its path idle timeout to move
    // to another one. The send sits in a task of its own, so a wait without a bound grows the tasks of
    // this node.
    let deadline = PoolInstant::now() + SEND_TIMEOUT;
    let (stream, held) = match time::timeout(SEND_TIMEOUT, connection.open_bi()).await {
        Ok(opened) => opened.map_err(|error| SendFault::LostBeforeCommit(error.to_string()))?,
        Err(_) => {
            return Err(SendFault::TimedOutBeforeCommit {
                step: "no stream was opened",
                after: SEND_TIMEOUT,
            });
        }
    };
    let mut frame = OutgoingFrame::new(stream, held);
    let left_to_write: Duration = deadline.saturating_duration_since(PoolInstant::now());
    match time::timeout(left_to_write, frame.write(bytes)).await {
        Ok(written) => written?,
        Err(_) => {
            return Err(SendFault::TimedOutBeforeCommit {
                step: "the peer read nothing",
                after: SEND_TIMEOUT,
            });
        }
    }
    if let Some(tally) = tally {
        tally.note(bytes);
    }
    match time::timeout(SEND_ANSWER_TIMEOUT, frame.held()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(fault_of_held(&error)),
        Err(_) => {
            return Err(SendFault::TimedOutBeforeCommit {
                step: "the peer did not hold the frame",
                after: SEND_ANSWER_TIMEOUT,
            });
        }
    }
    let mut committed = frame.commit()?;
    match time::timeout(SEND_ANSWER_TIMEOUT, committed.delivered()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(SendFault::LostAfterCommit(error.to_string())),
        Err(_) => {
            committed.stop();
            Err(SendFault::TimedOutAfterCommit(SEND_ANSWER_TIMEOUT))
        }
    }
}

/// What the end of the side of the peer says before it held the frame: a reset with [`NOT_TAKEN`] is
/// a peer that said no. Any other end is a lost connection.
fn fault_of_held(error: &ReadExactError) -> SendFault {
    let said_no = matches!(
        error,
        ReadExactError::ReadError(ReadError::Reset(code)) if code.into_inner() == u64::from(NOT_TAKEN)
    );
    if said_no {
        SendFault::NotTaken
    } else {
        SendFault::LostBeforeCommit(error.to_string())
    }
}

/// Whether the connection is the cause of a failed send, the only cause that a second send on a
/// new connection can mend.
fn connection_lost(error: &anyhow::Error) -> bool {
    let fault: Option<&SendFault> = error.downcast_ref();
    fault.is_some_and(SendFault::connection_lost)
}

/// Whether the sender had committed the frame when the send failed with `error`.
fn committed(error: &anyhow::Error) -> bool {
    let fault: Option<&SendFault> = error.downcast_ref();
    fault.is_some_and(SendFault::committed)
}

/// The verdict of a send that runs on a task. A task that ended without a verdict is a send that
/// was not delivered. Tests only.
#[cfg(test)]
pub(crate) async fn verdict_of(pending: PendingSend) -> Result<()> {
    pending
        .await
        .unwrap_or_else(|_| {
            SendVerdict::Unconfirmed("the send ended without an outcome".to_owned())
        })
        .into_result()
}

#[cfg(test)]
mod tests {
    use super::{Registration, UnicastPool};
    use crate::testing;
    use std::sync::Barrier;
    use std::thread;

    /// The entry of a dial leaves the map with its dialer, and not with a later one. After the outcome
    /// is published, the next caller is a dialer of its own, and the end of the first dialer, which
    /// drops after the publish, does not take the entry of the second.
    #[test]
    fn the_entry_of_a_dial_leaves_with_its_dialer_and_not_with_a_later_one() {
        let _guard = ::habilis_network_test_tracing::init();
        let pool = UnicastPool::disconnected();
        let peer = testing::endpoint_id(7);
        let Registration::Dialer(first) = pool.register_dial(peer) else {
            panic!("the first caller is the dialer");
        };
        assert!(
            matches!(pool.register_dial(peer), Registration::Waiter(_)),
            "a caller that comes while the dial is in flight waits for it"
        );
        first.publish(Err("the dial ended".to_owned()));
        assert!(
            !pool.is_dialing(peer),
            "the outcome takes the entry out of the map"
        );
        let Registration::Dialer(second) = pool.register_dial(peer) else {
            panic!("a caller after the outcome is a dialer of its own");
        };
        drop(first);
        assert!(
            pool.is_dialing(peer),
            "the end of the first dialer left the dial of the second in flight"
        );
        drop(second);
        assert!(
            !pool.is_dialing(peer),
            "the last dial of the peer leaves no entry"
        );
    }

    /// The end of a dialer and a new caller meet on two threads at once. Whichever comes first, the
    /// map holds no entry after both end. The window is a few nanoseconds, so a run of many pairs
    /// is a guard and not a proof.
    #[test]
    fn a_dialer_that_ends_as_a_caller_registers_leaves_no_entry_in_the_map() {
        let _guard = ::habilis_network_test_tracing::init();
        let pool = UnicastPool::disconnected();
        let peer = testing::endpoint_id(8);
        for round in 0..100_000 {
            let Registration::Dialer(first) = pool.register_dial(peer) else {
                panic!("round {round}: the map was not empty before the pair");
            };
            let start = Barrier::new(2);
            thread::scope(|scope| {
                scope.spawn(|| {
                    start.wait();
                    first.publish(Err("the dial ended".to_owned()));
                    drop(first);
                });
                scope.spawn(|| {
                    start.wait();
                    drop(pool.register_dial(peer));
                });
            });
            assert!(
                !pool.is_dialing(peer),
                "round {round}: an entry stayed in the map after the dialer and the caller ended"
            );
        }
    }
}
