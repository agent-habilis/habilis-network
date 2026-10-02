//! Multi-session browser `WebRTC` transport.
//!
//! The consumer and the producer share one shape: a hub that owns zero or more
//! data channels, keyed by remote [`EndpointId`]. The consumer attaches one
//! session after offering; the producer attaches each peer that signals in.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::SinkExt as _;
use futures::StreamExt as _;
use futures::channel::mpsc;
use iroh::EndpointId;
use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use iroh_base::CustomAddr;
use js_sys::Reflect;
use n0_watcher::Watchable;
use wasm_bindgen::JsCast as _;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{MessageEvent, RtcDataChannel, RtcPeerConnection, RtcPeerConnectionState};

use super::jsep::{now_ms, sleep_ms};
use crate::custom_addr;
use crate::liveness::{ConnectionPhase, DISCONNECT_GRACE_MS, Verdict, judge_state};
use crate::registry::Registry;
use crate::{IN_QUEUE, OUT_QUEUE};

/// Stop queueing into the channel above this much buffered data.
const BUFFER_CAP: u32 = 1 << 20;
/// The suffix an mDNS candidate address carries, which the browser hands out
/// in place of a private IP once it has anonymized the candidate.
const MDNS_SUFFIX: &str = ".local";

pub(crate) struct InboundPacket {
    pub(crate) from: EndpointId,
    pub(crate) payload: Vec<u8>,
}

/// What one session's outbound lane did with the datagrams QUIC handed it.
///
/// Every drop on this lane is silent by construction: `poll_send` must not
/// park (it would stall iroh's shared send loop across every transport), so it
/// discards and reports success, and the pump discards again when the channel
/// is congested or refuses the write. That is a defensible design and an
/// undiagnosable one — a stalled transfer and a healthy idle one produce the
/// same absence of evidence.
///
/// These are that evidence. Read them through
/// [`BrowserHubTransport::session_counters`]; a consumer deciding whether to
/// demote a peer to the relay can then say *why* rather than inferring it from
/// a transfer that did not finish.
#[derive(Debug, Default)]
pub struct SessionCounters {
    /// Datagrams handed to `RTCDataChannel.send` without it throwing.
    pub sent: AtomicU64,
    /// Dropped by `poll_send`: the outbound queue was full, which means the
    /// pump had not been scheduled since the queue drained. QUIC is told the
    /// send succeeded, so these are invisible above.
    pub dropped_queue_full: AtomicU64,
    /// Dropped by the pump: `bufferedAmount` was at or over [`BUFFER_CAP`].
    pub dropped_congested: AtomicU64,
    /// Dropped by the pump: `send` threw. A non-zero count here means the
    /// channel is refusing traffic, not merely slow.
    pub dropped_refused: AtomicU64,
}

/// A snapshot of [`SessionCounters`], since the counters themselves are not
/// `Clone` and reading four atomics separately would not be one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionCounts {
    pub sent: u64,
    pub dropped_queue_full: u64,
    pub dropped_congested: u64,
    pub dropped_refused: u64,
}

impl SessionCounts {
    /// Total datagrams discarded on this lane, by any of the three routes.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped_queue_full + self.dropped_congested + self.dropped_refused
    }
}

/// Cumulative counters from the session's `data-channel` stats row, `f64`
/// because that is what `getStats` reports. Named fields rather than a
/// positional tuple: every value shares one type, so a swapped pair would
/// compile silently.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DataChannelCounters {
    pub bytes_sent: f64,
    pub bytes_received: f64,
    pub messages_sent: f64,
    pub messages_received: f64,
}

/// What crossed the selected ICE candidate pair, for the same reason
/// [`DataChannelCounters`] is named: the byte counters share one type, so a
/// swapped pair would compile silently.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct SelectedPairStats {
    pub bytes_sent: f64,
    pub bytes_received: f64,
    /// `None` when the browser reports no round-trip time yet — distinct from a
    /// real 0 ms, which should not render alike.
    pub round_trip: Option<f64>,
}

#[derive(Debug)]
struct SessionHandle {
    out_tx: mpsc::Sender<Vec<u8>>,
    counters: Arc<SessionCounters>,
    /// Keeps the peer connection and data channel alive.
    keepalive: SessionKeepalive,
}

/// Opaque hold on browser handles that must outlive the QUIC path.
#[derive(Debug)]
struct SessionKeepalive {
    peer_connection: RtcPeerConnection,
    data_channel: RtcDataChannel,
    _callbacks: Vec<JsValue>,
}

impl Drop for SessionKeepalive {
    fn drop(&mut self) {
        // Clear the handlers before the closures in `callbacks` drop, so a
        // late browser event cannot invoke a destroyed closure.
        self.data_channel.set_onmessage(None);
        self.data_channel.set_onclose(None);
        self.data_channel.set_onerror(None);
        self.peer_connection.set_onconnectionstatechange(None);
        self.data_channel.close();
        self.peer_connection.close();
    }
}

type SessionMap = Arc<Registry<SessionHandle>>;

/// [`DISCONNECT_GRACE_MS`] for `sleep_ms`, which takes the browser's `i32`
/// milliseconds. Written out rather than cast so the two cannot drift.
const DISCONNECT_GRACE_MS_I32: i32 = 10_000;
const _: () = assert!(DISCONNECT_GRACE_MS_I32 as f64 == DISCONNECT_GRACE_MS);

fn phase_of(state: RtcPeerConnectionState) -> ConnectionPhase {
    match state {
        RtcPeerConnectionState::Failed | RtcPeerConnectionState::Closed => ConnectionPhase::Dead,
        RtcPeerConnectionState::Disconnected => ConnectionPhase::Disconnected,
        // `RtcPeerConnectionState` is a generated web-sys enum that can grow a
        // variant without us touching anything; a state we have not heard of
        // is not evidence of death.
        RtcPeerConnectionState::New
        | RtcPeerConnectionState::Connecting
        | RtcPeerConnectionState::Connected
        | _ => ConnectionPhase::Healthy,
    }
}

/// The `connectionstatechange` hook for one session.
///
/// `failed`/`closed` evict at once. `disconnected` gets [`DISCONNECT_GRACE_MS`]
/// to recover: the state is re-read after the grace rather than remembered,
/// so a recovery cancels the eviction with no bookkeeping, and a second
/// `disconnected` inside the window only re-reads again.
fn watch_connection_state(
    sessions: SessionMap,
    remote: EndpointId,
    generation: u64,
    peer_connection: &RtcPeerConnection,
) -> Closure<dyn FnMut()> {
    let watched = peer_connection.clone();
    Closure::<dyn FnMut()>::new(move || {
        let now = watched.connection_state();
        match judge_state(phase_of(now), None) {
            Verdict::Keep => {}
            Verdict::Remove => {
                let sessions = Arc::clone(&sessions);
                wasm_bindgen_futures::spawn_local(async move {
                    evict_if_generation(&sessions, remote, generation, now, 0.0);
                });
            }
            Verdict::Wait => {
                let sessions = Arc::clone(&sessions);
                let watched = watched.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let since = now_ms();
                    sleep_ms(DISCONNECT_GRACE_MS_I32).await;
                    let after = watched.connection_state();
                    let elapsed = now_ms() - since;
                    if judge_state(phase_of(after), Some(elapsed)) == Verdict::Remove {
                        evict_if_generation(&sessions, remote, generation, after, elapsed);
                    }
                });
            }
        }
    })
}

/// Drop `remote`'s slot if it is still the one stamped `generation`, and say
/// why: the state that condemned it and how long it was given.
fn evict_if_generation(
    sessions: &SessionMap,
    remote: EndpointId,
    generation: u64,
    state: RtcPeerConnectionState,
    grace_ms: f64,
) {
    if sessions.remove_if_generation(&remote, generation) {
        web_sys::console::log_1(&JsValue::from_str(&format!(
            "[habilis-network webrtc] session for {remote} detached (peer connection {state:?} \
             after {grace_ms:.0} ms grace)"
        )));
    }
}

/// Why [`BrowserHubTransport::attach`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachError {
    /// Someone already holds this peer's slot — a live session, or another
    /// negotiation partway through attaching one.
    ///
    /// Not necessarily a fault. The mount lane and the mesh lane share one
    /// registry, so either can reach a peer first; the loser should use the
    /// winner's session rather than treat this as a failure.
    ///
    /// The handles passed to `attach` have already been closed.
    AlreadyAttached(EndpointId),
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyAttached(remote) => {
                write!(formatter, "a WebRTC session for {remote} already exists")
            }
        }
    }
}

impl std::error::Error for AttachError {}

/// A session that is attached but not yet proven to carry traffic.
///
/// Attaching happens *before* the data channel opens — deliberately, because
/// the browser has no inbound buffer and a QUIC Initial that lands before
/// `onmessage` is installed is lost. This guard is what makes that early attach
/// safe: dropping it without [`Self::commit`] removes the session and closes
/// the peer connection, so a negotiation that never gets its channel open
/// leaves nothing behind.
#[derive(Debug)]
#[must_use = "an uncommitted session guard tears the session down when dropped"]
pub struct BrowserSessionGuard(crate::registry::SessionGuard<SessionHandle>);

impl BrowserSessionGuard {
    /// The peer this session is for.
    #[must_use]
    pub fn remote(&self) -> EndpointId {
        self.0.remote()
    }

    /// The channel is open and carrying traffic: keep the session.
    pub fn commit(self) {
        self.0.commit();
    }
}

/// Factory for the browser `WebRTC` datagram lane of one iroh endpoint.
pub struct BrowserHubTransport {
    local_id: EndpointId,
    sessions: SessionMap,
    inbound_tx: mpsc::Sender<InboundPacket>,
    inbound_rx: Mutex<Option<mpsc::Receiver<InboundPacket>>>,
    local_addrs: Watchable<Vec<CustomAddr>>,
}

impl BrowserHubTransport {
    #[must_use]
    pub fn new(local_id: EndpointId) -> Arc<Self> {
        let (inbound_tx, inbound_rx) = mpsc::channel(IN_QUEUE);
        Arc::new(Self {
            local_id,
            sessions: Registry::new(),
            inbound_tx,
            inbound_rx: Mutex::new(Some(inbound_rx)),
            local_addrs: Watchable::new(vec![custom_addr(local_id)]),
        })
    }

    #[must_use]
    pub fn local_id(&self) -> EndpointId {
        self.local_id
    }

    /// Adopt an open data channel for `remote` and start its pumps.
    ///
    /// Returns a guard, not `()`. The session is in the registry the moment
    /// this returns — it has to be, so no inbound QUIC Initial is lost — but it
    /// is not yet *proven*, and the caller must [`BrowserSessionGuard::commit`]
    /// once the channel opens. Dropping the guard instead removes the session
    /// and closes the handles.
    ///
    /// # Errors
    /// [`AttachError::AlreadyAttached`] when someone already holds this peer's
    /// slot. The handles passed in are closed before returning: `attach` took
    /// ownership of them, so the caller has no way to.
    pub fn attach(
        &self,
        remote: EndpointId,
        peer_connection: RtcPeerConnection,
        data_channel: RtcDataChannel,
        mut callbacks: Vec<JsValue>,
    ) -> Result<BrowserSessionGuard, AttachError> {
        // Claim the slot first, before a single handler is installed.
        //
        // The old order was install-then-check, and the refused path was a trap:
        // `Closure::into_js_value` forgets each closure into JS, so dropping the
        // local `callbacks` vec detached nothing. A duplicate left behind an
        // unclosed peer connection, an inbound pump still injecting packets
        // tagged as this remote, and — worst — a live `onclose` hook that would
        // later remove the *surviving* session, killing a working data path
        // mid-transfer.
        //
        // Nothing between here and `fulfil` below awaits or re-enters the
        // registry (`spawn_local` only queues), so the reserved slot is never
        // observable from outside this function.
        let Some(reservation) = self.sessions.reserve(remote) else {
            data_channel.close();
            peer_connection.close();
            return Err(AttachError::AlreadyAttached(remote));
        };
        let generation = reservation.generation();

        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(OUT_QUEUE);
        let (mut inbound_sender, mut inbound_receiver) = mpsc::channel::<Vec<u8>>(IN_QUEUE);
        let counters = Arc::new(SessionCounters::default());

        let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(bytes) = message_bytes(&event) else {
                return;
            };
            let _ = inbound_sender.try_send(bytes);
        });
        data_channel.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        callbacks.push(onmessage.into_js_value());

        // Self-remove when the channel dies, so a reconnecting peer is not
        // refused with "a live session already exists" and the map cannot
        // grow without bound. Removal is deferred to a task: it drops this
        // very closure (it lives in the session's keepalive), which must not
        // happen while the closure is executing.
        //
        // Scoped to `generation`, so a hook can only ever remove the session it
        // was born into. An unscoped hook on a channel that outlived its
        // session — an orphan from a refused duplicate, or a channel whose
        // close event arrives after the peer reconnected — would take out the
        // replacement instead.
        for event in ["close", "error"] {
            let sessions = Arc::clone(&self.sessions);
            let hook = Closure::<dyn FnMut()>::new(move || {
                let sessions = Arc::clone(&sessions);
                wasm_bindgen_futures::spawn_local(async move {
                    if sessions.remove_if_generation(&remote, generation) {
                        web_sys::console::log_1(&JsValue::from_str(&format!(
                            "[habilis-network webrtc] session for {remote} detached (channel closed)"
                        )));
                    }
                });
            });
            match event {
                "close" => data_channel.set_onclose(Some(hook.as_ref().unchecked_ref())),
                _ => data_channel.set_onerror(Some(hook.as_ref().unchecked_ref())),
            }
            callbacks.push(hook.into_js_value());
        }

        // The channel's own `close` is not enough: when ICE dies underneath it
        // the channel keeps reading `open` and never fires. Watch the peer
        // connection too, through the same generation-scoped removal path.
        let hook = watch_connection_state(
            Arc::clone(&self.sessions),
            remote,
            generation,
            &peer_connection,
        );
        peer_connection.set_onconnectionstatechange(Some(hook.as_ref().unchecked_ref()));
        callbacks.push(hook.into_js_value());

        {
            let mut inbound_tx = self.inbound_tx.clone();
            wasm_bindgen_futures::spawn_local(async move {
                while let Some(payload) = inbound_receiver.next().await {
                    // Await rather than try_send: a single full queue used to
                    // tear down the whole pump and kill the WebRTC lane.
                    if inbound_tx
                        .send(InboundPacket {
                            from: remote,
                            payload,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }

        {
            let data_channel = data_channel.clone();
            let counters = Arc::clone(&counters);
            wasm_bindgen_futures::spawn_local(async move {
                // Rate-limited visibility for the lossy gate: without it a
                // congested channel is indistinguishable from a broken one.
                let mut congested: u64 = 0;
                let mut refused: u64 = 0;
                while let Some(datagram) = out_rx.next().await {
                    if data_channel.buffered_amount() >= BUFFER_CAP {
                        congested += 1;
                        counters.dropped_congested.fetch_add(1, Ordering::Relaxed);
                        if crate::should_log_drop(congested) {
                            web_sys::console::warn_1(&JsValue::from_str(&format!(
                                "[habilis-network webrtc] dropping outbound datagrams \
                                 (bufferedAmount over cap); total {congested} for {remote}"
                            )));
                        }
                        continue;
                    }
                    // `send` throws, and this used to swallow it. Chrome raises
                    // `InvalidStateError` once the channel is no longer open and
                    // `OperationError` when its send buffer is exceeded, and a
                    // channel that has started refusing every write is
                    // indistinguishable from a healthy idle one if nobody looks
                    // — a stall with no error anywhere, which is precisely the
                    // shape of report this lane has been getting.
                    if let Err(error) = data_channel.send_with_u8_array(&datagram) {
                        refused += 1;
                        counters.dropped_refused.fetch_add(1, Ordering::Relaxed);
                        if crate::should_log_drop(refused) {
                            web_sys::console::warn_1(&JsValue::from_str(&format!(
                                "[habilis-network webrtc] data channel refused a send for \
                                 {remote} (ready_state={:?}, bufferedAmount={}); \
                                 total {refused}: {error:?}",
                                data_channel.ready_state(),
                                data_channel.buffered_amount(),
                            )));
                        }
                    } else {
                        counters.sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if congested > 0 || refused > 0 {
                    web_sys::console::log_1(&JsValue::from_str(&format!(
                        "[habilis-network webrtc] session for {remote} dropped {congested} \
                         outbound datagrams to congestion and {refused} to refused \
                         sends over its lifetime"
                    )));
                }
            });
        }

        // `None` means the reservation stopped being ours while negotiation
        // ran. The handle drops here, closing the channel and the peer
        // connection, rather than recording a session over a retired slot.
        reservation
            .fulfil(SessionHandle {
                out_tx,
                counters,
                keepalive: SessionKeepalive {
                    peer_connection,
                    data_channel,
                    _callbacks: callbacks,
                },
            })
            .map(BrowserSessionGuard)
            .ok_or(AttachError::AlreadyAttached(remote))
    }

    /// Whether a *usable* session for `remote` exists.
    ///
    /// The mirror of `WebRtcTransport::has_session` on the host side. A session
    /// manager needs this to answer "have I already negotiated with this peer?"
    /// without attempting a duplicate `attach` and reading the error.
    ///
    /// A session still waiting for its channel to open does not count. It is
    /// not yet a path anything can be sent over, and reporting it as one is how
    /// a failed ICE run used to pin a pair to the relay forever.
    #[must_use]
    pub fn has_session(&self, remote: &EndpointId) -> bool {
        self.sessions.is_live(remote)
    }

    /// How many live sessions this hub holds — the tab's direct-peer count.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.live_len()
    }

    /// Endpoint ids of every live session.
    #[must_use]
    pub fn live_peer_ids(&self) -> Vec<EndpointId> {
        self.sessions.live_ids()
    }

    /// Selected ICE remote candidate for `remote`, if a live session exists.
    ///
    /// Returns `(address, candidate_type)` where `candidate_type` is the
    /// browser's string (`host` / `srflx` / `relay` / `prflx`). Address may be
    /// an mDNS `.local` name — browsers redact LAN IPs that way.
    pub async fn selected_remote_candidate(&self, remote: &EndpointId) -> Option<(String, String)> {
        let peer_connection = self
            .sessions
            .with_live(remote, |handle| handle.keepalive.peer_connection.clone())?;
        selected_candidate_from_stats(&peer_connection, "remoteCandidateId").await
    }

    /// Counters and round-trip time on the selected candidate pair.
    ///
    /// Returns `(bytes_sent, bytes_received, rtt_seconds)`. Wire bytes, not
    /// payload: SCTP, DTLS and STUN framing are included, so this is what
    /// actually crossed the network rather than what the application handed
    /// over — the number that says where traffic really went.
    ///
    /// The counters are cumulative; a rate is the caller's job, from two
    /// samples. WebRTC exposes no instantaneous throughput for a data channel
    /// (`availableOutgoingBitrate` is media-bandwidth-estimation driven and is
    /// absent here), so differencing is the only route.
    ///
    pub async fn selected_pair_stats(&self, remote: &EndpointId) -> Option<SelectedPairStats> {
        let peer_connection = self
            .sessions
            .with_live(remote, |handle| handle.keepalive.peer_connection.clone())?;
        let (_, pair) = selected_pair_from_stats(&peer_connection).await?;
        let read = |key: &str| {
            Reflect::get(&pair, &JsValue::from_str(key))
                .ok()
                .and_then(|value| value.as_f64())
        };
        Some(SelectedPairStats {
            bytes_sent: read("bytesSent").unwrap_or(0.0),
            bytes_received: read("bytesReceived").unwrap_or(0.0),
            round_trip: read("currentRoundTripTime"),
        })
    }

    /// Bytes and messages this session's **data channel** has carried.
    ///
    /// The counterpart to [`Self::selected_pair_stats`], and the one to reach
    /// for when the question is "did our traffic move?". That reader answers a
    /// different question — how much crossed the selected ICE candidate pair,
    /// framing included — and it is measurably not a reliable proxy for this
    /// one: on a connection that had just carried a verified megabyte, the
    /// candidate pair and its transport row were both observed reporting 7400
    /// bytes and 28 packets. Whatever the browser was describing there, it was
    /// not what the data channel had done.
    ///
    /// That matters beyond tidiness, because "wire counters stay flat" is the
    /// kind of observation a caller demotes a peer to the relay on. This row is
    /// reported by the SCTP layer that actually carries our datagrams, names
    /// this channel by its `label`, and cannot be confused with another pair.
    ///
    /// `None` when there is no live session or the browser reports no
    /// `data-channel` row for it yet.
    pub async fn data_channel_bytes(&self, remote: &EndpointId) -> Option<DataChannelCounters> {
        let peer_connection = self
            .sessions
            .with_live(remote, |handle| handle.keepalive.peer_connection.clone())?;
        for (_, stats) in stats_rows(&peer_connection).await? {
            let text = |key: &str| {
                Reflect::get(&stats, &JsValue::from_str(key))
                    .ok()
                    .and_then(|value| value.as_string())
            };
            // By label, not by "the first data-channel row": a peer connection
            // carries exactly one channel for us, but nothing stops a future
            // one from carrying more, and picking arbitrarily is how the
            // candidate-pair reader went wrong.
            if text("type").as_deref() != Some("data-channel")
                || text("label").as_deref() != Some(crate::DATA_CHANNEL_LABEL)
            {
                continue;
            }
            let number = |key: &str| {
                Reflect::get(&stats, &JsValue::from_str(key))
                    .ok()
                    .and_then(|value| value.as_f64())
                    .unwrap_or(0.0)
            };
            return Some(DataChannelCounters {
                bytes_sent: number("bytesSent"),
                bytes_received: number("bytesReceived"),
                messages_sent: number("messagesSent"),
                messages_received: number("messagesReceived"),
            });
        }
        None
    }

    /// Selected ICE **local** candidate for a live session, if any.
    ///
    /// The other half of [`Self::selected_remote_candidate`]. Without it a tab
    /// can name every peer's address but not its own, so the roster shows the
    /// local row with no ip at all — the one row where the answer is always
    /// available, since it comes from our own `getStats`.
    pub async fn selected_local_candidate(&self, remote: &EndpointId) -> Option<(String, String)> {
        let peer_connection = self
            .sessions
            .with_live(remote, |handle| handle.keepalive.peer_connection.clone())?;
        selected_candidate_from_stats(&peer_connection, "localCandidateId").await
    }

    /// What this session's outbound lane has done with the datagrams QUIC gave
    /// it — see [`SessionCounters`] for why the numbers exist at all.
    ///
    /// `None` when there is no live session. Counting starts at `attach`, so a
    /// reconnected peer's counts are its own.
    #[must_use]
    pub fn session_counters(&self, remote: &EndpointId) -> Option<SessionCounts> {
        self.sessions.with_live(remote, |handle| SessionCounts {
            sent: handle.counters.sent.load(Ordering::Relaxed),
            dropped_queue_full: handle.counters.dropped_queue_full.load(Ordering::Relaxed),
            dropped_congested: handle.counters.dropped_congested.load(Ordering::Relaxed),
            dropped_refused: handle.counters.dropped_refused.load(Ordering::Relaxed),
        })
    }

    /// Push datagrams into the inbound path as if the channel had just
    /// delivered them, tagged as coming from `remote`.
    ///
    /// For the answerer's pre-attach backlog and nothing else: the browser
    /// gives a data channel no inbound buffer, so traffic that lands between
    /// `ondatachannel` and `attach` is lost unless something holds it. See the
    /// buffering handler in `web::jsep::answer`.
    ///
    /// Non-blocking, like the live pump: a full queue drops rather than parks,
    /// because parking here would stall the negotiation that is trying to
    /// finish. Logged when it happens — silently discarding a QUIC Initial is
    /// exactly the failure this method exists to prevent.
    pub(crate) fn inject_inbound(&self, remote: EndpointId, datagrams: Vec<Vec<u8>>) {
        let mut inbound_tx = self.inbound_tx.clone();
        let mut dropped = 0usize;
        for payload in datagrams {
            if inbound_tx
                .try_send(InboundPacket {
                    from: remote,
                    payload,
                })
                .is_err()
            {
                dropped += 1;
            }
        }
        if dropped > 0 {
            web_sys::console::warn_1(&JsValue::from_str(&format!(
                "[habilis-network webrtc] inbound queue full; dropped {dropped} \
                 pre-attach datagram(s) for {remote}"
            )));
        }
    }

    /// The live session's `RTCPeerConnection`, if there is one.
    ///
    /// `RTCPeerConnection.connectionState` for `remote`, if a live session
    /// exists.
    ///
    /// What the hub's own watchdog judges; exposed so a roster can show it and
    /// a consumer need not poll the connection itself.
    #[must_use]
    pub fn session_state(&self, remote: &EndpointId) -> Option<RtcPeerConnectionState> {
        self.sessions.with_live(remote, |handle| {
            handle.keepalive.peer_connection.connection_state()
        })
    }

    /// The escape hatch for diagnostics this hub does not wrap. The readers
    /// above answer the questions a roster needs — which candidate pair, how
    /// many bytes, what round trip — by picking one row out of `getStats` and
    /// summarising it; when that summary disagrees with what demonstrably
    /// crossed the connection, the only way to find out *which* row was picked
    /// is to walk the report yourself.
    #[must_use]
    pub fn peer_connection(&self, remote: &EndpointId) -> Option<RtcPeerConnection> {
        self.sessions
            .with_live(remote, |handle| handle.keepalive.peer_connection.clone())
    }

    /// Tear down the session for `remote`, if any.
    pub fn detach(&self, remote: &EndpointId) -> bool {
        self.sessions.remove(remote)
    }

    /// Tear down every live session (producer shutdown). Returns how many
    /// sessions were closed.
    pub fn detach_all(&self) -> usize {
        self.sessions.clear()
    }
}

impl std::fmt::Debug for BrowserHubTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserHubTransport")
            .field("local_id", &self.local_id)
            .field("sessions", &self.sessions.live_len())
            .finish_non_exhaustive()
    }
}

/// Read the selected ICE pair's remote candidate via `RTCPeerConnection.getStats`.
/// Address + candidate type for one side of the selected candidate pair.
///
/// `side` is the stats field naming the candidate to follow —
/// `remoteCandidateId` for the peer, `localCandidateId` for us. Both sides come
/// from the same `getStats` walk, so the pair a row reports is the pair that is
/// actually carrying traffic.
/// Index a `getStats` report by id, and find the selected candidate pair.
///
/// Shared so the candidate reader and the byte reader agree on *which* pair
/// they are describing: an address from one pair and counters from another
/// would be a plausible-looking lie.
async fn selected_pair_from_stats(
    peer_connection: &RtcPeerConnection,
) -> Option<(
    std::collections::HashMap<String, js_sys::Object>,
    js_sys::Object,
)> {
    let by_id: std::collections::HashMap<String, js_sys::Object> =
        stats_rows(peer_connection).await?.into_iter().collect();

    let pair_id = selected_pair_id(&by_id)?;
    let pair = by_id.get(&pair_id)?.clone();
    Some((by_id, pair))
}

/// One walk of a `getStats` report into `(id, row)` pairs — the iteration
/// shape every stats reader shares. The report iterates as `[id, object]`
/// map entries; anything else-shaped is skipped rather than trusted. Shared
/// so a browser changing the entry shape is fixed once, not once per reader.
async fn stats_rows(peer_connection: &RtcPeerConnection) -> Option<Vec<(String, js_sys::Object)>> {
    let report = JsFuture::from(peer_connection.get_stats()).await.ok()?;
    let iter = js_sys::try_iter(&report).ok().flatten()?;
    let mut rows = Vec::new();
    for entry in iter.flatten() {
        let Ok(pair) = entry.dyn_into::<js_sys::Array>() else {
            continue;
        };
        if pair.length() < 2 {
            continue;
        }
        let Ok(obj) = pair.get(1).dyn_into::<js_sys::Object>() else {
            continue;
        };
        rows.push((pair.get(0).as_string().unwrap_or_default(), obj));
    }
    Some(rows)
}

/// Id of the candidate pair actually carrying traffic, in preference order.
///
/// The order matters and the *independence from iteration order* matters more.
/// This used to be a single pass over the report that took whichever answer it
/// met first, and `by_id` is a `HashMap` — so which row it met first was not
/// stable between calls. Worse, a `transport` row without a
/// `selectedCandidatePairId` assigned `None` over an id an earlier
/// `candidate-pair` row had already supplied, throwing away a correct answer.
///
/// The symptom was a reader that intermittently described a pair that was not
/// carrying anything: byte counters frozen at the handshake's few `KiB` while a
/// megabyte demonstrably crossed the connection. Caught by
/// `tests/browser_loopback.rs`, whose bulk case asserts the counters move —
/// and it is worth knowing that "wire counters stay flat" was also the evidence
/// a consumer reported for a transfer stall, which this could have produced on
/// its own.
///
/// 1. `transport.selectedCandidatePairId` — the standard field, and the only
///    one Chrome reliably populates.
/// 2. `candidate-pair.selected` — the legacy flag, still emitted by some
///    browsers and by older Chrome.
/// 3. A `succeeded` + `nominated` pair — what the other two are derived from,
///    for a browser that publishes neither.
fn selected_pair_id(by_id: &std::collections::HashMap<String, js_sys::Object>) -> Option<String> {
    let field = |stats: &js_sys::Object, key: &str| {
        Reflect::get(stats, &JsValue::from_str(key))
            .ok()
            .and_then(|value| value.as_string())
    };
    let flag = |stats: &js_sys::Object, key: &str| {
        Reflect::get(stats, &JsValue::from_str(key))
            .ok()
            .and_then(|value| value.as_bool())
            == Some(true)
    };
    let of_type = |wanted: &'static str| {
        let mut rows: Vec<&js_sys::Object> = by_id
            .values()
            .filter(|stats| field(stats, "type").as_deref() == Some(wanted))
            .collect();
        // A stable tie-break so a report with more than one candidate row
        // yields the same answer on every call.
        rows.sort_by_key(|stats| field(stats, "id").unwrap_or_default());
        rows
    };

    if let Some(id) = of_type("transport")
        .into_iter()
        .find_map(|stats| field(stats, "selectedCandidatePairId"))
    {
        return Some(id);
    }
    let pairs = of_type("candidate-pair");
    if let Some(id) = pairs
        .iter()
        .find(|stats| flag(stats, "selected"))
        .and_then(|stats| field(stats, "id"))
    {
        return Some(id);
    }
    pairs
        .iter()
        .find(|stats| {
            field(stats, "state").as_deref() == Some("succeeded") && flag(stats, "nominated")
        })
        .and_then(|stats| field(stats, "id"))
}

/// Address + candidate type for one side of the selected pair.
///
/// `side` is the stats field naming the candidate to follow —
/// `remoteCandidateId` for the peer, `localCandidateId` for us.
///
/// **The address may be empty, and a caller must render that case.** A browser
/// only reports a candidate's address in `getStats` when that address has
/// already gone out on the wire; anything it considers private it withholds,
/// leaving `address` and `ip` both null. Measured: Safari withholds it for
/// `host` *and* `prflx` and names only `srflx`; Chrome withholds it for
/// `prflx`. The candidate **type** is reported in every one of those cases, and
/// "we paired on a host candidate whose address the browser will not name" is a
/// far more useful answer than the `None` this used to return — which a caller
/// cannot tell apart from "there is no session".
async fn selected_candidate_from_stats(
    peer_connection: &RtcPeerConnection,
    side: &str,
) -> Option<(String, String)> {
    let (by_id, pair) = selected_pair_from_stats(peer_connection).await?;
    let pair = &pair;
    let remote_id = Reflect::get(pair, &JsValue::from_str(side))
        .ok()
        .and_then(|value| value.as_string())?;
    let remote = by_id.get(&remote_id)?;
    let address = Reflect::get(remote, &JsValue::from_str("address"))
        .ok()
        .and_then(|value| value.as_string())
        .or_else(|| {
            Reflect::get(remote, &JsValue::from_str("ip"))
                .ok()
                .and_then(|value| value.as_string())
        })
        .unwrap_or_default();
    let kind = Reflect::get(remote, &JsValue::from_str("candidateType"))
        .ok()
        .and_then(|value| value.as_string())
        .unwrap_or_else(|| "unknown".to_owned());
    // Suffix-compared case-insensitively: DNS labels are case-insensitive by
    // spec, and going through `str::ends_with` with a dotted literal reads to
    // clippy as a file-extension test, which this is not.
    let is_mdns = address
        .len()
        .checked_sub(MDNS_SUFFIX.len())
        .is_some_and(|start| address[start..].eq_ignore_ascii_case(MDNS_SUFFIX));
    let kind = if is_mdns { "mdns".to_owned() } else { kind };
    Some((address, kind))
}

impl CustomTransport for BrowserHubTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let receiver = self
            .inbound_rx
            .lock()
            .expect("inbound receiver mutex poisoned")
            .take()
            .ok_or_else(|| io::Error::other("BrowserHubTransport is already bound"))?;
        Ok(Box::new(BrowserHubEndpoint {
            local_addrs: self.local_addrs.clone(),
            receiver,
            sessions: Arc::clone(&self.sessions),
        }))
    }
}

struct BrowserHubEndpoint {
    local_addrs: Watchable<Vec<CustomAddr>>,
    receiver: mpsc::Receiver<InboundPacket>,
    sessions: SessionMap,
}

impl std::fmt::Debug for BrowserHubEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserHubEndpoint")
            .finish_non_exhaustive()
    }
}

impl CustomEndpoint for BrowserHubEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.local_addrs.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(BrowserHubSender {
            sessions: Arc::clone(&self.sessions),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || metas.is_empty() || recv_infos.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            match self.receiver.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::other("inbound packet channel closed")));
                }
                Poll::Ready(Some(packet)) => {
                    if bufs[0].len() < packet.payload.len() {
                        continue;
                    }
                    bufs[0][..packet.payload.len()].copy_from_slice(&packet.payload);
                    metas[0].len = packet.payload.len();
                    metas[0].stride = packet.payload.len();
                    // Match the original single-session transport: leave local
                    // unset. Some iroh paths treat a Custom local addr oddly
                    // when the path was learned only from the data channel.
                    recv_infos[0] = RecvInfo::new(custom_addr(packet.from), None);
                    return Poll::Ready(Ok(1));
                }
            }
        }
    }
}

pub(crate) fn message_bytes(event: &MessageEvent) -> Option<Vec<u8>> {
    let data = event.data();
    if let Ok(buffer) = data.clone().dyn_into::<js_sys::ArrayBuffer>() {
        return Some(js_sys::Uint8Array::new(&buffer).to_vec());
    }
    if let Ok(array) = data.dyn_into::<js_sys::Uint8Array>() {
        return Some(array.to_vec());
    }
    None
}

struct BrowserHubSender {
    sessions: SessionMap,
}

impl std::fmt::Debug for BrowserHubSender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserHubSender")
            .finish_non_exhaustive()
    }
}

impl CustomSender for BrowserHubSender {
    /// Live sessions only. A reserved slot has no pump behind it, so calling it
    /// a valid address would have QUIC write into a channel that is not open —
    /// which is exactly what a stuck phantom entry used to do, silently.
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        let Ok(remote) = crate::parse_custom_addr(addr) else {
            return false;
        };
        self.sessions.is_live(&remote)
    }

    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let Ok(remote) = crate::parse_custom_addr(dst) else {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected)));
        };
        // Clone the sender out under the lock, then queue outside it.
        let Some((mut out_tx, counters)) = self.sessions.with_live(&remote, |handle| {
            (handle.out_tx.clone(), Arc::clone(&handle.counters))
        }) else {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::NotConnected)));
        };
        for chunk in habilis_network_iroh_transport_util::datagrams(transmit) {
            // Never `Pending`: that would stall iroh's shared send loop for
            // every transport. Drop and let QUIC retransmit — but *count* it,
            // because we are about to report success for a datagram nobody
            // will ever send, and without the counter that lie leaves no trace
            // anywhere. See `SessionCounters`.
            if out_tx.try_send(chunk.to_vec()).is_err() {
                counters.dropped_queue_full.fetch_add(1, Ordering::Relaxed);
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Backward-compatible name used by the consume path and older docs.
pub type BrowserRtcTransport = BrowserHubTransport;
