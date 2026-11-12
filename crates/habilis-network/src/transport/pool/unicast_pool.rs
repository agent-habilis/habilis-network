//! The dial side of the unicast plane: the per-peer connection pool.

use super::in_flight_dial::InFlightDial;
use super::registration::Registration;
use super::timeouts::{
    BUSY_AFTER_FINISH, COOLDOWN_REFUSED, DIAL_FAILURE_COOLDOWN, DIAL_TIMEOUT, PATH_SELECT_TIMEOUT,
    SEND_TIMED_OUT, SEND_TIMEOUT,
};
use super::warm_send::WarmSend;
use crate::transport::admission::{BusyGuard, SignalAdmission};
use crate::transport::payload_path;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use n0_future::time::Instant as PoolInstant;
use tokio::sync::{Mutex, watch};

use crate::transport::webrtc::close_code::IDLE;
use crate::transport::{LOG_TARGET, RELAY_REFUSED, UNICAST_ALPN, payload_allowed_on};

use crate::util::clock::Instant;
use crate::util::cooldown::Cooldown;
use crate::util::tuning::{DIRECT_IDLE_BACKSTOP, PROBE_HOLD};

use crate::daemon::state::WireOutTally;

use n0_future::{task, time};
use std::sync::{Mutex as std_Mutex, OnceLock, OnceLock as std_OnceLock};
use std::{fmt, result};
#[cfg(test)]
use tokio::sync::Notify;
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
    /// Endpoints with a dial in flight, each with the receiver of the outcome that its dialer
    /// publishes, so that concurrent cold sends to one peer share one dial instead of racing their
    /// own: the first is the dialer, the others wait on the receiver. Read by
    /// [`UnicastPool::send_registered`] and [`UnicastPool::dial_and_send_in_background`]. An inline dial
    /// through [`UnicastPool::warm_or_dial`] waits on the peer lock of `dial_locks` instead.
    pub(in crate::transport::pool) dialing:
        parking_lot::Mutex<HashMap<EndpointId, watch::Receiver<DialOutcome>>>,
    /// One lock for each peer that is being dialed by [`UnicastPool::dial_pooled`]: a second dial waits for the first
    /// one, then finds its connection pooled. An entry is removed when its last waiter has gone.
    // shared: the dialer and every waiter for one peer hold the same lock
    dial_locks: parking_lot::Mutex<HashMap<EndpointId, Arc<Mutex<()>>>>,
    /// Tests only: the next dial waits on this before it connects, so a test can queue a send
    /// behind it.
    #[cfg(test)]
    // the gate is shared by the dial and the test that holds it
    pub(in crate::transport::pool) dial_gate: std_Mutex<Option<Arc<Notify>>>,
    /// Each peer's full address, from its `PeerInfo`. Dialed instead of the
    /// bare id so the relay is in the address book before the handshake:
    /// iroh opens a connection's relay path only then, and with it a UDP loss
    /// has a backup path to fall to rather than none.
    pub(in crate::transport::pool) addrs: std_Mutex<HashMap<EndpointId, EndpointAddr>>,
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
pub(super) type DialOutcome = Option<result::Result<(), String>>;

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
                dials_started: AtomicU64::new(0),
                dialing: parking_lot::Mutex::new(HashMap::new()),
                dial_locks: parking_lot::Mutex::new(HashMap::new()),
                addrs: std_Mutex::new(HashMap::new()),
                #[cfg(test)]
                dial_gate: std_Mutex::new(None),
                relay_transport,
                admission: std_OnceLock::new(),
                tally: std_OnceLock::new(),
            }),
        }
    }

    /// Report the sends of this pool to `admission`, so that a connection with a send in
    /// flight is never evicted at the ceiling and a used one is not the least recently used.
    pub(crate) fn set_admission(&self, admission: SignalAdmission) {
        let _ = self.inner.admission.set(admission);
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
                dials_started: AtomicU64::new(0),
                dialing: parking_lot::Mutex::new(HashMap::new()),
                dial_locks: parking_lot::Mutex::new(HashMap::new()),
                addrs: std_Mutex::new(HashMap::new()),
                #[cfg(test)]
                dial_gate: std_Mutex::new(None),
                relay_transport: false,
                admission: OnceLock::new(),
                tally: std_OnceLock::new(),
            }),
        }
    }

    /// Send `bytes` over a warm connection to `eid` if one exists, returning
    /// `true` on a fire-and-forget handoff. `false` means no warm connection —
    /// the caller then dials inline via [`Self::dial_and_send`]. The actual
    /// stream write is spawned so the event loop never blocks on QUIC I/O
    /// (awaiting it wouldn't buy delivery truth anyway — QUIC buffers locally,
    /// so a write "succeeds" before the path is proven). A write that fails on
    /// a half-dead pooled connection evicts it and redials-and-resends once in
    /// the background, so the detectable failure mode recovers instead of
    /// silently losing the frame; a path that dies *after* buffering remains
    /// at-most-once (an app-level concern: waiter timeouts, and the app's own retry).
    pub(crate) async fn send_if_warm(&self, eid: EndpointId, bytes: Bytes) -> WarmSend {
        let Some(connection) = self.warm(eid).await else {
            return WarmSend::Cold;
        };
        if !payload_allowed_on(&connection, self.inner.relay_transport) {
            return WarmSend::Refused;
        }
        let pool = self.clone();
        task::spawn(async move {
            let Err(error) = pool.send_marked(eid, &connection, &bytes).await else {
                return;
            };
            tracing::debug!(target: LOG_TARGET, %error, "unicast send failed; dropping connection and redialing");
            pool.evict_if_same(eid, &connection).await;
            if let Err(redial_error) = pool.dial_and_send(eid, bytes).await {
                tracing::debug!(target: LOG_TARGET, %redial_error, "redial after a failed warm send also failed; frame dropped");
            }
        });
        WarmSend::Sent
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
    /// fails takes up to [`SEND_TIMEOUT`], and another send can dial a replacement in that time: an
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
        let period = (self.inner.idle.min(self.inner.probe_hold) / 4).max(Duration::from_millis(1));
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
                            now.saturating_duration_since(pooled.last_used) >= inner.idle
                        }
                    };
                    if idle {
                        tracing::debug!(target: LOG_TARGET, %eid, "closing an idle pooled unicast connection");
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
    pub(crate) async fn dial_and_send_in_background(&self, eid: EndpointId, bytes: Bytes) -> bool {
        if self.is_cooling(eid).await {
            return false;
        }
        let registration = self.register_dial(eid);
        let pool = self.clone();
        task::spawn(async move {
            if let Err(error) = pool.send_registered(registration, eid, bytes).await {
                tracing::debug!(target: LOG_TARGET, %eid, %error, "background send not delivered");
            }
        });
        true
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

    /// Whether `eid` is on the dial-failure cooldown.
    pub(crate) async fn is_cooling(&self, eid: EndpointId) -> bool {
        self.inner
            .dial_failures
            .lock()
            .await
            .on_cooldown(&eid, Instant::now())
    }

    /// Put `eid` on the dial-failure cooldown, as a failed dial does.
    #[cfg(test)]
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
        self.inner.dial_attempts.fetch_add(1, Ordering::Relaxed);
        let connection = self.warm_or_dial(eid).await?;
        // A connection this call just dialed is milliseconds old: its
        // non-relay path (the punch, or a WebRTC path opened right after
        // `AddConnection`) is still forming, and the synchronous check read
        // "no path selected yet" as relay — refusing the *first* directed
        // frame to every peer without a warm connection. Wait like the
        // accept side does, on a dial-sized budget.
        if !self.inner.relay_transport
            && !payload_path::wait_direct(&connection, PATH_SELECT_TIMEOUT).await
        {
            bail!("{RELAY_REFUSED}");
        }
        if let Err(error) = self.send_marked(eid, &connection, &bytes).await {
            self.evict_if_same(eid, &connection).await;
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
            WarmSend::Sent => return Ok(()),
            WarmSend::Refused => bail!("{RELAY_REFUSED}"),
            WarmSend::Cold => {}
        }
        self.send_registered(self.register_dial(eid), eid, bytes)
            .await
    }

    /// The send of a caller that has taken its place already, with [`Self::register_dial`]. The
    /// dialer dials and publishes how the dial ended. A waiter waits for that, then writes on the
    /// connection that the dial made; if the connection is gone by then, it takes the place of the
    /// dialer, and the next waiter waits for it.
    ///
    /// # Errors
    /// A refused path, a dial or a path wait or a write that fails, a peer on the dial-failure
    /// cooldown, or the error of the dial that this call waited for.
    pub(crate) async fn send_registered(
        &self,
        mut registration: Registration,
        eid: EndpointId,
        bytes: Bytes,
    ) -> Result<()> {
        loop {
            match registration {
                Registration::Dialer(in_flight) => {
                    let outcome = self.dial_and_send(eid, bytes).await;
                    in_flight.publish(match &outcome {
                        Ok(()) => Ok(()),
                        Err(error) => Err(error.to_string()),
                    });
                    return outcome;
                }
                Registration::Waiter(outcome) => {
                    wait_for_dial(outcome).await.map_err(anyhow::Error::msg)?;
                    match self.send_if_warm(eid, bytes.clone()).await {
                        WarmSend::Sent => return Ok(()),
                        WarmSend::Refused => bail!("{RELAY_REFUSED}"),
                        WarmSend::Cold => registration = self.register_dial(eid),
                    }
                }
            }
        }
    }

    /// Make this caller the dialer of `eid`, or the waiter of the dial that is in flight. Taken by
    /// the caller itself, synchronously, before the task that sends is spawned.
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

    /// The pooled connection to `eid`, dialing one if none is warm. The
    /// direct-path probe uses this so its connection *is* the one later
    /// unicast rides — one handshake, and a punch landed here serves both.
    ///
    /// # Errors
    /// See [`Self::dial_and_send`].
    pub(crate) async fn warm_or_dial(&self, eid: EndpointId) -> Result<Connection> {
        if self.inner.endpoint.is_none() {
            bail!("unicast pool has no endpoint");
        }
        if let Some(connection) = self.warm(eid).await {
            return Ok(connection);
        }
        self.dial_pooled(eid, Hold::Used).await
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
        self.dial_pooled(eid, Hold::Probing).await
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

    /// Dial `eid` and pool the connection under `hold`. One dial runs for each peer at a time, and a dial starts only
    /// when no connection of the peer is open, so an insert never replaces a live connection. A replaced connection
    /// must be closed with `close()`, not dropped: an unacknowledged frame on a dropped connection is lost.
    async fn dial_pooled(&self, eid: EndpointId, hold: Hold) -> Result<Connection> {
        let lock = self.dial_lock(eid);
        let turn = lock.lock().await;
        let result = self.dial_pooled_turn(eid, hold).await;
        drop(turn);
        drop(lock);
        self.release_dial_lock(eid);
        result
    }

    /// The lock of `eid` for one dial. It is created on first use.
    fn dial_lock(&self, eid: EndpointId) -> Arc<Mutex<()>> {
        let mut locks = self.inner.dial_locks.lock();
        // shared: the dialer and every waiter for the peer hold the same lock
        let lock = locks.entry(eid).or_insert_with(|| Arc::new(Mutex::new(())));
        Arc::clone(lock)
    }

    /// Removes the lock of `eid` when no caller holds it any more.
    fn release_dial_lock(&self, eid: EndpointId) {
        let mut locks = self.inner.dial_locks.lock();
        if locks
            .get(&eid)
            .is_some_and(|lock| Arc::strong_count(lock) == 1)
        {
            locks.remove(&eid);
        }
    }

    /// The open pooled connection of `eid`, if there is one. A caller that sends with it (`mark_used`) takes it as
    /// [`warm`](Self::warm) does: the hold becomes `Used`. A probe leaves the hold the connection has, so a probe
    /// dial that finds a connection of a send does not turn it into a probe hold.
    async fn open_pooled(&self, eid: EndpointId, mark_used: bool) -> Option<Connection> {
        let mut conns = self.inner.conns.lock().await;
        let pooled: &mut Pooled = conns
            .get_mut(&eid)
            .filter(|pooled| pooled.connection.close_reason().is_none())?;
        if mark_used {
            pooled.last_used = PoolInstant::now();
            pooled.hold = Hold::Used;
        }
        Some(pooled.connection.clone())
    }

    /// The body of [`Self::dial_pooled`], run under the lock of the peer.
    async fn dial_pooled_turn(&self, eid: EndpointId, hold: Hold) -> Result<Connection> {
        if let Some(connection) = self.open_pooled(eid, matches!(hold, Hold::Used)).await {
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
        let address: EndpointAddr = {
            let addrs = self.inner.addrs.lock().ok();
            addrs
                .and_then(|addrs| addrs.get(&eid).cloned())
                .unwrap_or_else(|| EndpointAddr::new(eid))
        };
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
                    },
                );
                drop(conns);
                self.ensure_sweeper();
                Ok(connection)
            }
            Err(error) => {
                self.inner
                    .dial_failures
                    .lock()
                    .await
                    .note(eid, Instant::now());
                Err(error)
            }
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
        // A rejoin may come back at another address; its `PeerInfo` notes it.
        if let Ok(mut addrs) = self.inner.addrs.lock() {
            addrs.remove(&eid);
        }
    }
}

/// Wait for the dialer of a peer to publish how its dial ended. The current value is read first, so
/// that a receiver made after the publish still sees it.
async fn wait_for_dial(mut outcome: watch::Receiver<DialOutcome>) -> result::Result<(), String> {
    loop {
        if let Some(done) = outcome.borrow_and_update().clone() {
            return done;
        }
        if outcome.changed().await.is_err() {
            return Err("the dial ended without an outcome".to_owned());
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

/// One message per unidirectional stream: open, write the whole frame, finish.
/// No length framing is needed — the accept side reads the stream to EOF and
/// gets exactly one serialized `Message`. The finished stream keeps flushing
/// after it is dropped because the connection stays pooled, so the sender does not
/// await `stopped()` (which would block the event loop on the inline
/// unicast-only path). Only the busy mark waits for it, in a task of its own.
pub(super) async fn send_one(
    connection: &Connection,
    bytes: &[u8],
    busy: Option<BusyGuard>,
    tally: Option<&WireOutTally>,
) -> Result<()> {
    // The open and the write share one deadline: a peer that reads nothing fills its limit of streams, and the
    // open of the next stream then waits for room that never comes. The send sits in a task of its own, so a
    // wait without a bound grows the tasks of this node.
    let deadline = PoolInstant::now() + SEND_TIMEOUT;
    let mut stream = match time::timeout(SEND_TIMEOUT, connection.open_uni()).await {
        Ok(opened) => opened?,
        Err(_) => bail!("{SEND_TIMED_OUT} after {SEND_TIMEOUT:?}: no stream was opened"),
    };
    let left: Duration = deadline.saturating_duration_since(PoolInstant::now());
    if let Ok(written) = time::timeout(left, stream.write_all(bytes)).await {
        written?;
    } else {
        // The frame is cut short, so the stream is reset and not finished: dropping it finishes it, and the peer
        // would read the prefix as a whole frame. A reset also drops what is still buffered here.
        let _ = stream.reset(0u32.into());
        bail!("{SEND_TIMED_OUT} after {SEND_TIMEOUT:?}: the peer read nothing");
    }
    stream.finish()?;
    if let Some(tally) = tally {
        tally.note(bytes);
    }
    // `finish()` returns while the frame is still in flight. The busy mark moves to a task that waits
    // until the peer has read the stream (at most `BUSY_AFTER_FINISH`), so that the ledger does not
    // evict the connection under a slow reader. The sender does not wait: it would block the event
    // loop on the inline path.
    if let Some(busy) = busy {
        task::spawn(async move {
            let _ = time::timeout(BUSY_AFTER_FINISH, stream.stopped()).await;
            drop(busy);
        });
    }
    Ok(())
}
