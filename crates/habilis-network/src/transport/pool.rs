//! The dial side of the unicast plane: a per-peer connection pool that dials
//! lazily, reuses a warm QUIC connection across messages, and re-dials after a
//! close. Modeled on the application bridge's shared connection, but keyed per endpoint
//! and with a short dial budget so a send to an unreachable peer fails fast
//! rather than stalling the event loop.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use n0_future::time::Instant as PoolInstant;
use tokio::sync::Mutex;

use super::path::wait_direct;
use super::webrtc::close_code::IDLE;
use super::{LOG_TARGET, RELAY_REFUSED, UNICAST_ALPN, payload_allowed_on};

use crate::util::clock::Instant;
use crate::util::cooldown::Cooldown;
use crate::util::tuning::{DIRECT_IDLE_BACKSTOP_SECS, PROBE_HOLD_SECS};

/// How long an inline dial keeps trying before giving up. Deliberately short —
/// far under the application's 90s discovery deadline — because the dial blocks the send,
/// and an unreachable peer should surface as an error now, not stall the
/// caller. The addressee's `EndpointAddr` is already registered with the
/// endpoint (`add_peer_addr`), so a reachable peer resolves well inside this.
pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// After a failed dial the endpoint goes on cooldown: further cold sends to it
/// error immediately instead of re-dialing. The dial blocks the event loop, so
/// without this a burst of directed frames to one dead peer (a 16-shard repair
/// reply, a flushed backlog) serializes a [`DIAL_TIMEOUT`] stall per frame —
/// the cooldown bounds that to one stall per window per peer.
const DIAL_FAILURE_COOLDOWN: Duration = Duration::from_secs(10);

/// How long a *fresh* inline dial may wait for iroh to select a non-relay
/// path before the send is refused. Shorter than the accept side's
/// `PROBE_DEADLINE`: this wait blocks the event loop exactly like the dial
/// itself, so it gets a dial-sized budget, not an accept-sized one — and a
/// punch or a WebRTC path-open lands in single-digit seconds when it lands
/// at all.
const PATH_SELECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct UnicastPool {
    inner: Arc<PoolInner>,
}

impl std::fmt::Debug for UnicastPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnicastPool").finish_non_exhaustive()
    }
}

/// Why a pooled connection is held, which decides when it closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hold {
    /// A send opened or used it: it closes after the idle timeout.
    Used,
    /// A direct-path probe opened it and is still running.
    Probing,
    /// The probe ended at this time and no send has taken the connection since:
    /// it closes after the probe hold.
    Probed(PoolInstant),
}

/// A pooled connection and when a send last used it.
struct Pooled {
    conn: Connection,
    /// On the clock the tokio runtime keeps, so a test can pause it.
    last_used: PoolInstant,
    hold: Hold,
}

struct PoolInner {
    /// `None` for a detached pool (unit-test states / pre-wiring default): every
    /// operation is inert, so a directed send simply errors instead of dialing.
    endpoint: Option<Endpoint>,
    conns: Mutex<HashMap<EndpointId, Pooled>>,
    /// How long a pooled connection may go unused before it is closed. The
    /// peer's acceptor closes an unused connection on its own side too, so a
    /// link that nobody sends on does not hold its two ends open for ever.
    idle: Duration,
    /// How long the connection of a direct-path probe stays after the probe ends
    /// when no send takes it.
    probe_hold: Duration,
    /// Set once the sweeper is running, so that it starts at the first dial.
    sweeping: AtomicBool,
    /// When each endpoint's last dial failed, for the
    /// [`DIAL_FAILURE_COOLDOWN`] gate. An entry clears on a successful dial or
    /// a graceful `Left`; expired ones are pruned on the next `note`.
    dial_failures: Mutex<Cooldown<EndpointId>>,
    /// Times the inline-dial path was entered. Counted on entry rather than at
    /// the dial itself, because the question a caller on the event loop needs
    /// answered is whether it *could* have waited here — a detached pool bails
    /// before dialing, and a warm hit inside never dials, but both mean the
    /// caller was willing to.
    dial_attempts: AtomicU64,
    /// Endpoints with a background dial in flight, so that concurrent cold
    /// sends to one peer share one dial instead of racing their own. Only
    /// [`UnicastPool::dial_and_send_in_background`] reads it: an inline dial
    /// through [`UnicastPool::warm_or_dial`] does not.
    dialing: std::sync::Mutex<HashSet<EndpointId>>,
    /// Each peer's full address, from its `PeerInfo`. Dialed instead of the
    /// bare id so the relay is in the address book before the handshake:
    /// iroh opens a connection's relay path only then, and with it a UDP loss
    /// has a backup path to fall to rather than none.
    addrs: std::sync::Mutex<HashMap<EndpointId, EndpointAddr>>,
    /// `TransportPolicy::relay`. Off, a send on a connection whose selected
    /// path is the relay is refused; the connection stays pooled, since iroh
    /// may still punch a direct path on it.
    relay_transport: bool,
    /// The table whose ceiling the connections of this pool count against. Set once the
    /// table exists, which is after the pool.
    admission: std::sync::OnceLock<super::admission::SignalAdmission>,
}

/// What [`UnicastPool::send_if_warm`] did with the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WarmSend {
    /// Handed to a warm connection.
    Sent,
    /// No warm connection: the caller dials inline.
    Cold,
    /// A warm connection exists, but its selected path is the relay and the
    /// relay is lookup only. Dialing would find the same connection.
    Refused,
}

impl UnicastPool {
    /// A pool wired to `endpoint`, able to dial and carry unicast traffic.
    pub(crate) fn new(endpoint: Endpoint, relay_transport: bool) -> Self {
        Self::with_timeouts(
            endpoint,
            relay_transport,
            Duration::from_secs(DIRECT_IDLE_BACKSTOP_SECS),
            Duration::from_secs(PROBE_HOLD_SECS),
        )
    }

    /// [`Self::new`] with the idle timeout spelled out, for tests that must not
    /// wait the real one.
    #[cfg(test)]
    pub(crate) fn with_idle(endpoint: Endpoint, relay_transport: bool, idle: Duration) -> Self {
        Self::with_timeouts(
            endpoint,
            relay_transport,
            idle,
            Duration::from_secs(PROBE_HOLD_SECS),
        )
    }

    /// [`Self::new`] with the idle timeout and the probe hold spelled out.
    pub(crate) fn with_timeouts(
        endpoint: Endpoint,
        relay_transport: bool,
        idle: Duration,
        probe_hold: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(PoolInner {
                endpoint: Some(endpoint),
                conns: Mutex::new(HashMap::new()),
                idle,
                probe_hold,
                sweeping: AtomicBool::new(false),
                dial_failures: Mutex::new(Cooldown::new(DIAL_FAILURE_COOLDOWN)),
                dial_attempts: AtomicU64::new(0),
                dialing: std::sync::Mutex::new(HashSet::new()),
                addrs: std::sync::Mutex::new(HashMap::new()),
                relay_transport,
                admission: std::sync::OnceLock::new(),
            }),
        }
    }

    /// Report the sends of this pool to `admission`, so that a connection with a send in
    /// flight is never evicted at the ceiling and a used one is not the least recently used.
    pub(crate) fn set_admission(&self, admission: super::admission::SignalAdmission) {
        let _ = self.inner.admission.set(admission);
    }

    /// [`send_one`], marked busy in the ledger for as long as it runs.
    async fn send_marked(&self, eid: EndpointId, conn: &Connection, bytes: &[u8]) -> Result<()> {
        let busy = self.inner.admission.get().map(|table| table.busy(eid));
        send_one(conn, bytes, busy).await
    }

    /// A detached pool with no endpoint — every operation is a no-op. The
    /// default an [`EventLoopState`](crate::daemon::state::EventLoopState) holds
    /// until the real loop installs an endpoint-backed pool; also what the
    /// lower-level unit tests (which never run the transport) get.
    pub(crate) fn disconnected() -> Self {
        Self {
            inner: Arc::new(PoolInner {
                endpoint: None,
                conns: Mutex::new(HashMap::new()),
                idle: Duration::from_secs(DIRECT_IDLE_BACKSTOP_SECS),
                probe_hold: Duration::from_secs(PROBE_HOLD_SECS),
                sweeping: AtomicBool::new(false),
                dial_failures: Mutex::new(Cooldown::new(DIAL_FAILURE_COOLDOWN)),
                dial_attempts: AtomicU64::new(0),
                dialing: std::sync::Mutex::new(HashSet::new()),
                addrs: std::sync::Mutex::new(HashMap::new()),
                relay_transport: false,
                admission: std::sync::OnceLock::new(),
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
    /// at-most-once (an app-level concern: waiter timeouts, and anti-entropy,
    /// which re-sends a directed frame point-to-point to its addressee).
    pub(crate) async fn send_if_warm(&self, eid: EndpointId, bytes: Bytes) -> WarmSend {
        let Some(conn) = self.warm(eid).await else {
            return WarmSend::Cold;
        };
        if !payload_allowed_on(&conn, self.inner.relay_transport) {
            return WarmSend::Refused;
        }
        let pool = self.clone();
        n0_future::task::spawn(async move {
            let Err(error) = pool.send_marked(eid, &conn, &bytes).await else {
                return;
            };
            tracing::debug!(target: LOG_TARGET, %error, "unicast send failed; dropping connection and redialing");
            pool.inner.conns.lock().await.remove(&eid);
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
            Ok(conn) => super::path::wait_ip(&conn, PATH_SELECT_TIMEOUT).await,
            Err(_) => false,
        };
        self.probe_done(eid).await;
        won
    }

    /// Remember `addr` as the address to dial its peer at.
    pub(crate) fn note_addr(&self, addr: &EndpointAddr) {
        if let Ok(mut addrs) = self.inner.addrs.lock() {
            addrs.insert(addr.id, addr.clone());
        }
    }

    /// The open pooled connection to `eid`, whoever opened it. A contended lock
    /// reads as none.
    #[cfg(test)]
    pub(crate) fn connection(&self, eid: EndpointId) -> Option<Connection> {
        self.inner.conns.try_lock().ok().and_then(|conns| {
            conns
                .get(&eid)
                .map(|pooled| &pooled.conn)
                .filter(|conn| conn.close_reason().is_none())
                .cloned()
        })
    }

    /// The open pooled connection to `eid` that a send opened or used. A
    /// connection that only a direct-path probe opened is not one: the pair was
    /// never sent to. A contended lock reads as none.
    pub(crate) fn used_connection(&self, eid: EndpointId) -> Option<Connection> {
        self.inner.conns.try_lock().ok().and_then(|conns| {
            conns
                .get(&eid)
                .filter(|pooled| pooled.hold == Hold::Used)
                .map(|pooled| &pooled.conn)
                .filter(|conn| conn.close_reason().is_none())
                .cloned()
        })
    }

    /// Whether the pooled connection to `eid` is on a selected UDP path. The
    /// offer decisions read the admission table instead, which sees every
    /// connection of the peer and not only the pooled one.
    #[cfg(test)]
    pub(crate) fn selected_is_ip(&self, eid: EndpointId) -> bool {
        self.inner.conns.try_lock().is_ok_and(|conns| {
            conns.get(&eid).is_some_and(|pooled| {
                pooled.conn.close_reason().is_none() && super::path::selected_is_ip(&pooled.conn)
            })
        })
    }

    /// The pooled connection to `eid`, if one is open. Taking it counts as
    /// using it: every caller is about to send or probe on it.
    async fn warm(&self, eid: EndpointId) -> Option<Connection> {
        let mut conns = self.inner.conns.lock().await;
        let pooled = conns
            .get_mut(&eid)
            .filter(|pooled| pooled.conn.close_reason().is_none())?;
        pooled.last_used = PoolInstant::now();
        pooled.hold = Hold::Used;
        Some(pooled.conn.clone())
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
        n0_future::task::spawn(async move {
            loop {
                n0_future::time::sleep(period).await;
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
                        pooled.conn.close(IDLE.into(), b"idle");
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

    /// Start a [`Self::dial_and_send`] to `eid` on a spawned task, and return
    /// whether one was started. `false` when `eid` is on the dial-failure
    /// cooldown, or when a background dial to it is already in flight; this
    /// frame is then not sent, and the caller can try again later.
    pub(crate) async fn dial_and_send_in_background(&self, eid: EndpointId, bytes: Bytes) -> bool {
        if self
            .inner
            .dial_failures
            .lock()
            .await
            .on_cooldown(&eid, Instant::now())
        {
            return false;
        }
        if !self
            .inner
            .dialing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(eid)
        {
            return false;
        }
        let in_flight = InFlightDial {
            pool: self.clone(),
            eid,
        };
        n0_future::task::spawn(async move {
            if let Err(error) = in_flight.pool.dial_and_send(eid, bytes).await {
                tracing::debug!(target: LOG_TARGET, %eid, %error, "background send not delivered");
            }
            drop(in_flight);
        });
        true
    }

    /// Send `frames` to `eid` in order, from one spawned task: one stream per
    /// frame, in sequence. [`Self::dial_and_send_in_background`] takes one
    /// frame, and while its dial is in flight every further call for the same
    /// peer is refused, so a batch sent that way loses all but its first frame
    /// to a cold peer. A warm connection takes a batch at once, even with
    /// another batch to the same peer still going: a node sends its state and
    /// meta digests back to back, so a holder answers it twice at once. A cold
    /// peer is dialed first, and only one dial to it runs at a time. Returns
    /// `false`, sending nothing, when the warm connection's path may not carry
    /// payload, or `eid` is cold and on the dial-failure cooldown or already
    /// being dialed. `true` means handed off, not delivered: a dial, path or
    /// write failure after it is only logged, and a write can succeed into a
    /// connection that died silently.
    pub(crate) async fn send_batch_in_background(
        &self,
        eid: EndpointId,
        frames: Vec<Bytes>,
    ) -> bool {
        if let Some(conn) = self.warm(eid).await {
            if !payload_allowed_on(&conn, self.inner.relay_transport) {
                return false;
            }
            let pool = self.clone();
            n0_future::task::spawn(async move {
                pool.send_batch(eid, &conn, &frames).await;
            });
            return true;
        }
        if self
            .inner
            .dial_failures
            .lock()
            .await
            .on_cooldown(&eid, Instant::now())
        {
            return false;
        }
        if !self
            .inner
            .dialing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(eid)
        {
            return false;
        }
        let in_flight = InFlightDial {
            pool: self.clone(),
            eid,
        };
        n0_future::task::spawn(async move {
            let pool = &in_flight.pool;
            let conn = match pool.warm_or_dial(eid).await {
                Ok(conn) => conn,
                Err(error) => {
                    tracing::debug!(target: LOG_TARGET, %eid, %error, "batch not delivered: no connection");
                    return;
                }
            };
            if !pool.inner.relay_transport && !wait_direct(&conn, PATH_SELECT_TIMEOUT).await {
                tracing::debug!(target: LOG_TARGET, %eid, "batch not delivered: {RELAY_REFUSED}");
                return;
            }
            pool.send_batch(eid, &conn, &frames).await;
        });
        true
    }

    /// Write `frames` to `conn` one stream at a time, in order, stopping and
    /// dropping the connection at the first write error.
    async fn send_batch(&self, eid: EndpointId, conn: &Connection, frames: &[Bytes]) {
        for bytes in frames {
            if let Err(error) = self.send_marked(eid, conn, bytes).await {
                tracing::debug!(target: LOG_TARGET, %eid, %error, "batch cut short; dropping the connection");
                self.inner.conns.lock().await.remove(&eid);
                return;
            }
        }
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
        let conn = self.warm_or_dial(eid).await?;
        // A connection this call just dialed is milliseconds old: its
        // non-relay path (the punch, or a WebRTC path opened right after
        // `AddConnection`) is still forming, and the synchronous check read
        // "no path selected yet" as relay — refusing the *first* directed
        // frame to every peer without a warm connection. Wait like the
        // accept side does, on a dial-sized budget.
        if !self.inner.relay_transport && !wait_direct(&conn, PATH_SELECT_TIMEOUT).await {
            bail!("{RELAY_REFUSED}");
        }
        if let Err(error) = self.send_marked(eid, &conn, &bytes).await {
            self.inner.conns.lock().await.remove(&eid);
            return Err(error);
        }
        Ok(())
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
        if let Some(conn) = self.warm(eid).await {
            return Ok(conn);
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
        let existing = self
            .inner
            .conns
            .lock()
            .await
            .get(&eid)
            .map(|pooled| &pooled.conn)
            .filter(|conn| conn.close_reason().is_none())
            .cloned();
        if let Some(conn) = existing {
            return Ok(conn);
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

    /// Dial `eid` and pool the connection under `hold`.
    async fn dial_pooled(&self, eid: EndpointId, hold: Hold) -> Result<Connection> {
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
            bail!("unicast dial on cooldown after a recent failure");
        }
        let addr = self
            .inner
            .addrs
            .lock()
            .ok()
            .and_then(|addrs| addrs.get(&eid).cloned())
            .unwrap_or_else(|| EndpointAddr::new(eid));
        match dial(&endpoint, addr).await {
            Ok(conn) => {
                self.inner.dial_failures.lock().await.forget(&eid);
                self.inner.conns.lock().await.insert(
                    eid,
                    Pooled {
                        conn: conn.clone(),
                        last_used: PoolInstant::now(),
                        hold,
                    },
                );
                self.ensure_sweeper();
                Ok(conn)
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
            pooled.conn.close(0u32.into(), b"peer left");
        }
        self.inner.dial_failures.lock().await.forget(&eid);
        // A rejoin may come back at another address; its `PeerInfo` notes it.
        if let Ok(mut addrs) = self.inner.addrs.lock() {
            addrs.remove(&eid);
        }
    }
}

/// An endpoint's entry in the in-flight dial set, removed on drop: a dial that
/// panics or is dropped with its runtime must not leave the peer marked in
/// flight, which would refuse every later background send to it.
struct InFlightDial {
    pool: UnicastPool,
    eid: EndpointId,
}

impl Drop for InFlightDial {
    fn drop(&mut self) {
        self.pool
            .inner
            .dialing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.eid);
    }
}

/// Dial `eid` on the unicast ALPN within [`DIAL_TIMEOUT`]. The endpoint already
/// knows the peer's address (registered via `add_peer_addr`), so a bare-id
/// `EndpointAddr` resolves through the endpoint's address book + lookups.
async fn dial(endpoint: &Endpoint, addr: EndpointAddr) -> Result<Connection> {
    match n0_future::time::timeout(DIAL_TIMEOUT, endpoint.connect(addr, UNICAST_ALPN)).await {
        Ok(Ok(conn)) => Ok(conn),
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
async fn send_one(
    conn: &Connection,
    bytes: &[u8],
    busy: Option<super::admission::BusyGuard>,
) -> Result<()> {
    let mut stream = conn.open_uni().await?;
    stream.write_all(bytes).await?;
    stream.finish()?;
    // `finish()` returns while the frame is still in flight. The busy mark moves to a task that waits
    // until the peer has read the stream (at most `BUSY_AFTER_FINISH`), so that the ledger does not
    // evict the connection under a slow reader. The sender does not wait: it would block the event
    // loop on the inline path.
    if let Some(busy) = busy {
        n0_future::task::spawn(async move {
            let _ = n0_future::time::timeout(BUSY_AFTER_FINISH, stream.stopped()).await;
            drop(busy);
        });
    }
    Ok(())
}

/// How long a connection stays busy after a send finished, if the peer has not read the frame. A
/// reader that is slower than this is not protected: the connection can be evicted under its frame.
const BUSY_AFTER_FINISH: Duration = Duration::from_secs(2);

#[cfg(test)]
mod tests {
    use crate::testing::endpoint_id;
    use crate::util::clock::Instant;
    use std::time::Duration;

    use super::{Cooldown, DIAL_FAILURE_COOLDOWN};

    #[test]
    fn a_fresh_failure_puts_the_endpoint_on_cooldown() {
        let mut failures = Cooldown::new(DIAL_FAILURE_COOLDOWN);
        let bob = endpoint_id(1);
        let now = Instant::now();
        failures.note(bob, now);
        assert!(failures.on_cooldown(&bob, now));
        // Another endpoint is unaffected.
        assert!(!failures.on_cooldown(&endpoint_id(2), now));
    }

    #[test]
    fn an_expired_failure_allows_the_dial_and_is_pruned() {
        let mut failures = Cooldown::new(DIAL_FAILURE_COOLDOWN);
        let bob = endpoint_id(1);
        let failed_at = Instant::now();
        failures.note(bob, failed_at);
        let later = failed_at + DIAL_FAILURE_COOLDOWN + Duration::from_millis(1);
        assert!(!failures.on_cooldown(&bob, later));
        // Pruning happens on the next write rather than on the read, so the
        // table still cannot grow without bound.
        failures.note(endpoint_id(2), later);
        assert_eq!(
            failures.len(),
            1,
            "the stale entry is dropped, not retained"
        );
    }

    /// The offer decision reads the pooled connection synchronously: a UDP
    /// connection reads `true`, while a busy lock or an unknown peer reads
    /// `false`, so the node offers rather than wrongly skipping the race.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pooled_udp_connection_reads_as_udp_selected() {
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                conn.closed().await;
                Ok(())
            }
        }
        let bind = || async {
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, Hold)
            .spawn();
        let client = bind().await;
        crate::lookup::add_peer_addr(&client, server.addr()).expect("register the server");
        let pool = super::UnicastPool::new(client.clone(), false);

        assert!(!pool.selected_is_ip(server.id()), "nothing pooled yet");
        pool.warm_or_dial(server.id()).await.expect("dial");
        let started = Instant::now();
        while !pool.selected_is_ip(server.id()) {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "udp never selected"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let held = pool.inner.conns.lock().await;
        assert!(
            !pool.selected_is_ip(server.id()),
            "a busy lock reads as not selected"
        );
        drop(held);

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// A loopback server that holds every unicast connection open, and a pool
    /// dialed to it with the given idle timeout.
    async fn pool_with_idle(
        idle: Duration,
    ) -> (
        super::UnicastPool,
        iroh::EndpointId,
        iroh::protocol::Router,
        iroh::Endpoint,
    ) {
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                conn.closed().await;
                Ok(())
            }
        }
        let bind = || async {
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, Hold)
            .spawn();
        let client = bind().await;
        crate::lookup::add_peer_addr(&client, server.addr()).expect("register the server");
        let pool = super::UnicastPool::with_idle(client.clone(), false, idle);
        (pool, server.id(), router, client)
    }

    /// Step the paused clock a second at a time, so the sweeper's timer fires
    /// in order with the connection's own.
    async fn advance_secs(seconds: u64) {
        for _ in 0..seconds {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
    }

    /// Closed by this side, not timed out by QUIC and not closed by the peer.
    fn closed_as_idle(conn: &iroh::endpoint::Connection) -> bool {
        matches!(
            conn.close_reason(),
            Some(iroh::endpoint::ConnectionError::LocallyClosed)
        )
    }

    #[tokio::test]
    async fn a_pooled_connection_nothing_sends_on_is_closed_after_the_idle_timeout() {
        let (pool, server, router, client) = pool_with_idle(Duration::from_secs(8)).await;
        let conn = pool.warm_or_dial(server).await.expect("dial");
        tokio::time::pause();

        advance_secs(6).await;
        assert!(
            conn.close_reason().is_none() && pool.connection(server).is_some(),
            "inside the idle timeout the connection stays pooled"
        );

        advance_secs(6).await;
        assert!(
            pool.inner.conns.lock().await.is_empty(),
            "an unused connection leaves the pool"
        );
        assert!(closed_as_idle(&conn), "and is closed, not just dropped");

        tokio::time::resume();
        pool.warm_or_dial(server).await.expect("a send dials again");
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    #[tokio::test]
    async fn a_send_restarts_the_idle_timeout() {
        let (pool, server, router, client) = pool_with_idle(Duration::from_secs(8)).await;
        let conn = pool.warm_or_dial(server).await.expect("dial");
        tokio::time::pause();

        advance_secs(5).await;
        assert!(
            pool.warm(server).await.is_some(),
            "a send takes the connection"
        );
        advance_secs(5).await;
        assert!(
            conn.close_reason().is_none() && pool.connection(server).is_some(),
            "five seconds after a send is inside the timeout"
        );

        advance_secs(7).await;
        assert!(closed_as_idle(&conn), "then it idles out as well");

        tokio::time::resume();
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// A loopback server that holds every unicast connection open, and a pool
    /// dialed to it with the given idle timeout and probe hold.
    async fn pool_with_holds(
        idle: Duration,
        probe_hold: Duration,
    ) -> (
        super::UnicastPool,
        iroh::EndpointId,
        iroh::protocol::Router,
        iroh::Endpoint,
    ) {
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                conn.closed().await;
                Ok(())
            }
        }
        let bind = || async {
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint")
        };
        let server = bind().await;
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, Hold)
            .spawn();
        let client = bind().await;
        crate::lookup::add_peer_addr(&client, server.addr()).expect("register the server");
        let pool = super::UnicastPool::with_timeouts(client.clone(), false, idle, probe_hold);
        (pool, server.id(), router, client)
    }

    /// The connection of a direct-path probe is not a send: it counts as no use,
    /// and is closed a fixed hold after the probe ends, long before the idle
    /// timeout, unless a send takes it first.
    #[tokio::test]
    async fn a_probe_connection_is_closed_after_the_hold_unless_a_send_takes_it() {
        let (pool, server, router, client) =
            pool_with_holds(Duration::from_secs(80), Duration::from_secs(8)).await;
        let conn = pool.probe_connection(server).await.expect("dial");
        assert!(
            pool.used_connection(server).is_none(),
            "a probe is not a send"
        );
        pool.probe_done(server).await;
        tokio::time::pause();

        advance_secs(6).await;
        assert!(
            conn.close_reason().is_none() && pool.connection(server).is_some(),
            "inside the hold the probe connection stays, so the graft can form on it"
        );
        advance_secs(6).await;
        assert!(
            pool.inner.conns.lock().await.is_empty(),
            "after the hold the connection leaves the pool"
        );
        assert!(closed_as_idle(&conn), "and is closed, not just dropped");

        tokio::time::resume();
        let probed = pool.probe_connection(server).await.expect("probe again");
        pool.probe_done(server).await;
        tokio::time::pause();
        advance_secs(5).await;
        assert!(
            pool.warm_or_dial(server).await.is_ok(),
            "a send takes the probe connection"
        );
        assert!(pool.used_connection(server).is_some(), "and now it is used");
        advance_secs(20).await;
        assert!(
            probed.close_reason().is_none(),
            "a used connection follows the idle timeout, not the hold"
        );

        tokio::time::resume();
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// A background dial that ends early — dropped with its runtime here, the
    /// same unwinding a panic in the dial gives — must still clear its
    /// in-flight entry, or every later cold send to that peer is refused.
    #[test]
    fn a_background_dial_dropped_mid_flight_clears_its_in_flight_entry() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a silent socket");
        let bob = iroh::SecretKey::generate().public();
        let pool = runtime.block_on(async {
            let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .expect("bind a loopback endpoint");
            let bob_addr = iroh::EndpointAddr::from_parts(
                bob,
                [iroh::TransportAddr::Ip(
                    silent.local_addr().expect("silent addr"),
                )],
            );
            crate::lookup::add_peer_addr(&endpoint, bob_addr).expect("register bob");
            let pool = super::UnicastPool::new(endpoint, false);
            assert!(
                pool.dial_and_send_in_background(bob, bytes::Bytes::new())
                    .await
            );
            tokio::task::yield_now().await;
            pool
        });

        drop(runtime);

        let still_in_flight = pool.inner.dialing.lock().expect("lock").contains(&bob);
        let cleanup = tokio::runtime::Runtime::new().expect("a cleanup runtime");
        let _entered = cleanup.enter();
        drop(pool);
        assert!(
            !still_in_flight,
            "the dropped dial left {bob} marked in flight"
        );
    }

    /// A graceful `Left` forgets the peer's pool slots: the dial cooldown is
    /// cleared so a rejoin dials immediately, and forgetting an unknown
    /// endpoint is a no-op. (Closing a warm `Connection` needs a live
    /// endpoint pair; that path is covered by the network suite.)
    #[tokio::test]
    async fn forget_clears_the_cooldown_and_tolerates_absence() {
        let pool = super::UnicastPool::disconnected();
        let bob = endpoint_id(1);
        pool.inner
            .dial_failures
            .lock()
            .await
            .note(bob, Instant::now());

        pool.forget(bob).await;

        assert!(pool.inner.dial_failures.lock().await.is_empty());
        assert!(pool.inner.conns.lock().await.is_empty());
        // Absent endpoint: nothing to drop, nothing panics.
        pool.forget(endpoint_id(2)).await;
    }

    /// A send over a pooled connection is a use of it: the ledger of the ceiling moves its
    /// last use to the end of the send, so the connection of a peer that is being talked to
    /// is not the least recently used.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_send_marks_its_connection_as_used_in_the_ledger() {
        use iroh::protocol::Router;

        use super::super::accept::UnicastAcceptor;
        use super::super::admission::SignalAdmission;

        let (tx, _frames) = tokio::sync::mpsc::channel(8);
        let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, UnicastAcceptor::new(tx, true))
            .spawn();
        let admission = SignalAdmission::new(8);
        let node = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .hooks(admission.connection_hook())
            .bind()
            .await
            .expect("bind a loopback endpoint");
        crate::lookup::add_peer_addr(&node, server.addr()).expect("register the server");
        let pool = super::UnicastPool::new(node.clone(), true);
        pool.set_admission(admission.clone());

        pool.dial_and_send(server.id(), bytes::Bytes::from_static(b"one"))
            .await
            .expect("the first send");
        let first = admission
            .last_use(server.id())
            .expect("the ledger holds it");
        tokio::time::sleep(Duration::from_millis(300)).await;
        pool.dial_and_send(server.id(), bytes::Bytes::from_static(b"two"))
            .await
            .expect("the second send");
        let second = admission
            .last_use(server.id())
            .expect("the ledger holds it");

        assert!(second > first, "the second send is a later use");
        router.shutdown().await.expect("shutdown");
        node.close().await;
    }

    /// A peer that evicted us is left alone by the proactive dial of a probe, and a send to
    /// it dials at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_evicting_peer_is_not_probed_but_a_send_dials_it() {
        use iroh::protocol::Router;

        use super::super::accept::UnicastAcceptor;
        use super::super::admission::SignalAdmission;

        let (tx, _frames) = tokio::sync::mpsc::channel(8);
        let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, UnicastAcceptor::new(tx, true))
            .spawn();
        let admission = SignalAdmission::new(8);
        let node = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .hooks(admission.connection_hook())
            .bind()
            .await
            .expect("bind a loopback endpoint");
        crate::lookup::add_peer_addr(&node, server.addr()).expect("register the server");
        let pool = super::UnicastPool::new(node.clone(), true);
        pool.set_admission(admission.clone());
        admission.note_evicted(server.id());

        assert!(
            pool.probe_connection(server.id()).await.is_err(),
            "the probe waits"
        );
        pool.dial_and_send(server.id(), bytes::Bytes::from_static(b"now"))
            .await
            .expect("a send dials at once");

        router.shutdown().await.expect("shutdown");
        node.close().await;
    }

    /// The idle close of a pooled connection is the one backstop of the direct connections.
    #[test]
    fn a_pool_closes_an_idle_connection_after_the_one_backstop() {
        assert_eq!(
            super::UnicastPool::disconnected().inner.idle,
            Duration::from_secs(crate::util::tuning::DIRECT_IDLE_BACKSTOP_SECS)
        );
    }

    /// **The busy mark lasts until the peer has read the frame.** `finish()` returns while the frame
    /// is still in flight, so a mark that ended there left a connection with a slow reader open to
    /// eviction, with its frame in the air. The mark now ends when the peer has read the stream to the
    /// end, or after 2 s.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_send_keeps_its_connection_busy_until_the_peer_has_read_the_frame() {
        use iroh::protocol::{AcceptError, ProtocolHandler, Router};

        use super::super::admission::SignalAdmission;

        #[derive(Debug, Clone)]
        struct SlowReader;
        impl ProtocolHandler for SlowReader {
            async fn accept(&self, conn: iroh::endpoint::Connection) -> Result<(), AcceptError> {
                let mut stream = conn.accept_uni().await.map_err(AcceptError::from_err)?;
                tokio::time::sleep(Duration::from_millis(800)).await;
                let _ = stream.read_to_end(1 << 20).await;
                conn.closed().await;
                Ok(())
            }
        }

        let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .expect("bind a loopback endpoint");
        let router = Router::builder(server.clone())
            .accept(super::super::UNICAST_ALPN, SlowReader)
            .spawn();
        let admission = SignalAdmission::new(8);
        let node = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .hooks(admission.connection_hook())
            .bind()
            .await
            .expect("bind a loopback endpoint");
        crate::lookup::add_peer_addr(&node, server.addr()).expect("register the server");
        let pool = super::UnicastPool::new(node.clone(), true);
        pool.set_admission(admission.clone());

        pool.dial_and_send(server.id(), bytes::Bytes::from(vec![7u8; 3000]))
            .await
            .expect("the send");
        assert!(
            admission.is_busy(server.id()),
            "the frame is in flight: the peer has not read it"
        );

        let mut idle = false;
        for _ in 0..60 {
            if !admission.is_busy(server.id()) {
                idle = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(idle, "the mark ends once the peer has read the frame");

        router.shutdown().await.expect("shutdown");
        node.close().await;
    }
}
