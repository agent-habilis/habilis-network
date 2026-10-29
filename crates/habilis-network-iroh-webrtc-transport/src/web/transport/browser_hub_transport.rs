use super::{
    BrowserHubEndpoint, BrowserSessionGuard, DataChannelCounters, InboundPacket, SelectedPairStats,
    SessionCounters, SessionCounts, SessionHandle, SessionKeepalive, SessionMap,
};
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use futures::channel::mpsc;
use futures::{SinkExt as _, StreamExt as _};
use iroh::EndpointId;
use iroh::endpoint::transports::{CustomEndpoint, CustomTransport};
use iroh_base::CustomAddr;
use js_sys::Reflect;
use n0_watcher::Watchable;
use wasm_bindgen::prelude::{Closure, JsValue};
use web_sys::{MessageEvent, RtcDataChannel, RtcPeerConnection, RtcPeerConnectionState};

use crate::attach_error::AttachError;
use crate::registry::Registry;
use crate::{IN_QUEUE, OUT_QUEUE, custom_addr};

/// Factory for the browser `WebRTC` datagram lane of one iroh endpoint.
///
/// # Examples
///
/// It runs on a browser hub, so the doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_iroh_webrtc_transport::BrowserHubTransport;
///
/// # fn demo(transport: BrowserHubTransport) {
/// drop(transport);
/// # }
/// ```
pub struct BrowserHubTransport {
    local_id: EndpointId,
    sessions: SessionMap,
    inbound_tx: mpsc::Sender<InboundPacket>,
    inbound_rx: Mutex<Option<mpsc::Receiver<InboundPacket>>>,
    local_addrs: Watchable<Vec<CustomAddr>>,
}

impl BrowserHubTransport {
    /// A transport for `local_id`, with no sessions yet.
    #[must_use]
    // the hub is shared with the handle and the page
    pub fn new(local_id: EndpointId) -> Arc<Self> {
        let (inbound_tx, inbound_rx) = mpsc::channel(IN_QUEUE);
        // the hub is shared with the handle and the page
        Arc::new(Self {
            local_id,
            sessions: Registry::new(),
            inbound_tx,
            inbound_rx: Mutex::new(Some(inbound_rx)),
            local_addrs: Watchable::new(vec![custom_addr(local_id)]),
        })
    }

    /// The endpoint id of this node.
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
        use wasm_bindgen::JsCast as _;
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
        // the counters are shared by the hub and each session
        let counters = Arc::new(SessionCounters::default());

        let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(bytes) = super::message_bytes(&event) else {
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
            let handle: &JsValue = hook.as_ref();
            match event {
                "close" => data_channel.set_onclose(Some(handle.unchecked_ref())),
                _ => data_channel.set_onerror(Some(handle.unchecked_ref())),
            }
            callbacks.push(hook.into_js_value());
        }

        // The channel's own `close` is not enough: when ICE dies underneath it
        // the channel keeps reading `open` and never fires. Watch the peer
        // connection too, through the same generation-scoped removal path.
        let hook = super::watch_connection_state(
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
                    if data_channel.buffered_amount() >= super::BUFFER_CAP {
                        congested += 1;
                        counters.dropped_congested.fetch_add(1, Ordering::Relaxed);
                        super::console_drop(congested, || {
                            format!(
                                "[habilis-network webrtc] dropping outbound datagrams \
                                 (bufferedAmount over cap); total {congested} for {remote}"
                            )
                        });
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
                        super::console_drop(refused, || {
                            format!(
                                "[habilis-network webrtc] data channel refused a send for \
                                 {remote} (ready_state={:?}, bufferedAmount={}); \
                                 total {refused}: {error:?}",
                                data_channel.ready_state(),
                                data_channel.buffered_amount(),
                            )
                        });
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
    pub fn live_peer_ids(&self) -> impl Iterator<Item = EndpointId> {
        self.sessions.live_ids().into_iter()
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
        super::selected_candidate_from_stats(&peer_connection, "remoteCandidateId").await
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
        let (_, pair) = super::selected_pair_from_stats(&peer_connection).await?;
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
        for (_, stats) in super::stats_rows(&peer_connection).await? {
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
                let field = Reflect::get(&stats, &JsValue::from_str(key)).ok();
                field.and_then(|value| value.as_f64()).unwrap_or(0.0)
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
        super::selected_candidate_from_stats(&peer_connection, "localCandidateId").await
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
        let sessions = self.sessions.live_len();
        formatter
            .debug_struct("BrowserHubTransport")
            .field("local_id", &self.local_id)
            .field("sessions", &sessions)
            .finish_non_exhaustive()
    }
}

impl CustomTransport for BrowserHubTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let receiver = {
            let mut slot = self
                .inbound_rx
                .lock()
                .expect("inbound receiver mutex poisoned");
            slot.take()
                .ok_or_else(|| io::Error::other("BrowserHubTransport is already bound"))
        }?;
        Ok(Box::new(BrowserHubEndpoint {
            local_addrs: self.local_addrs.clone(),
            receiver,
            sessions: Arc::clone(&self.sessions),
        }))
    }
}
