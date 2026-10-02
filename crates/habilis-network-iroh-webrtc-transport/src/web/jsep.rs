//! Browser-side JSEP: drive `RTCPeerConnection` to a negotiated data channel.
//!
//! Deliberately carrier-agnostic, exactly like the host side. [`offer`] /
//! [`answer`] hand back a [`SignalEnvelope`] and the caller carries it however
//! it likes. Nothing here knows how the remote is reached.
//!
//! Vanilla ICE: candidates ride inside the SDP, so gathering must complete
//! *before* the envelope goes out. There is no trickle message to add them
//! later — and that stays fast because [`wait_ice_complete`] settles for the
//! candidates in hand once they cover NAT traversal, instead of waiting out
//! `complete` (which Chromium withholds until every STUN server answered or
//! timed out).

use wasm_bindgen::JsCast as _;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    RtcConfiguration, RtcDataChannel, RtcDataChannelEvent, RtcIceConnectionState,
    RtcIceGatheringState, RtcPeerConnection, RtcPeerConnectionState, RtcSdpType,
    RtcSessionDescriptionInit,
};

use crate::{DATA_CHANNEL_LABEL, SignalEnvelope, accept_ice_uri};

use super::transport::BrowserHubTransport;
use iroh_base::EndpointId;

/// How long to wait for the data channel after the answer is applied.
const CHANNEL_OPEN_DEADLINE_MS: f64 = 60_000.0;
/// The same deadline for `sleep_ms`, which takes the browser's own `i32`
/// milliseconds. Written out rather than cast so the two cannot drift and no
/// truncation is implied.
const CHANNEL_OPEN_DEADLINE_MS_I32: i32 = 60_000;
/// How long to let gathering run before settling for the candidates in hand.
/// This is the ceiling for the no-candidate case only: with a usable set in
/// hand, [`wait_ice_complete`] exits after [`ICE_QUIET_MS`] instead. Chromium
/// reports `complete` only once *every* configured STUN server answered or
/// exhausted its ~9.5 s retransmission ladder, so a single blocked server used
/// to cost this whole deadline on every connect.
const ICE_GATHERING_DEADLINE_MS: f64 = 10_000.0;
/// How long gathering may stay quiet — no new candidate line — before the set
/// in hand is taken as complete enough. One srflx (when servers are
/// configured) plus one host/mdns candidate is all a connect needs; the quiet
/// period lets a second prompt server still get its candidate in.
const ICE_QUIET_MS: f64 = 400.0;
const POLL_MS: i32 = 50;

/// One `RTCIceServer` entry.
///
/// No `username`/`credential`: those exist only for TURN, which this crate
/// refuses (see [`crate::accept_ice_uri`]). Dropping the fields means a
/// credentialed server cannot be expressed, let alone configured.
#[derive(Debug, Clone)]
pub struct IceServer {
    pub urls: Vec<String>,
}

/// ICE servers for the browser's own agent.
#[derive(Debug, Clone)]
pub struct IceServers(pub Vec<IceServer>);

impl Default for IceServers {
    fn default() -> Self {
        // See [`DEFAULT_STUN_HOSTS`](crate::DEFAULT_STUN_HOSTS) for why these
        // two and no others; the browser wants each as a `stun:` URI.
        Self(vec![IceServer {
            urls: crate::DEFAULT_STUN_HOSTS
                .iter()
                .map(|host| format!("stun:{host}"))
                .collect(),
        }])
    }
}

impl IceServers {
    #[must_use]
    pub fn host_only() -> Self {
        Self(Vec::new())
    }

    fn to_configuration(&self) -> RtcConfiguration {
        let config = RtcConfiguration::new();
        let servers = js_sys::Array::new();
        for server in &self.0 {
            let entry = js_sys::Object::new();
            let urls = js_sys::Array::new();
            // The enforcement point: anything `accept_ice_uri` refuses never
            // reaches the browser. TURN cannot be configured here even by
            // mistake, and a query string Safari would throw on is stripped
            // before it can take down the whole peer connection.
            for url in server.urls.iter().filter_map(|url| accept_ice_uri(url)) {
                urls.push(&JsValue::from_str(&url));
            }
            if urls.length() == 0 {
                continue;
            }
            let _ = js_sys::Reflect::set(&entry, &JsValue::from_str("urls"), &urls);
            servers.push(&entry);
        }
        config.set_ice_servers(&servers);
        config
    }
}

/// Build an `RTCPeerConnection`, degrading rather than failing when the browser
/// refuses a server entry.
///
/// The constructor validates every ICE URL and throws on the first bad one, so
/// a single unusable entry costs the whole connection. [`accept_ice_uri`]
/// filters what we control, but the configuration can still be rejected for a
/// reason we have not met yet — and a peer connection with no ICE servers still
/// gathers host candidates, which is strictly better than none at all.
/// Also reports whether the connection ended up with STUN servers, because
/// the gathering wait must not hold out for a srflx candidate that can never
/// arrive — neither on the `host_only()` config nor on this degraded retry.
fn new_peer_connection(ice: &IceServers) -> Result<(RtcPeerConnection, bool), JsValue> {
    match RtcPeerConnection::new_with_configuration(&ice.to_configuration()) {
        Ok(peer_connection) => Ok((peer_connection, !ice.0.is_empty())),
        Err(error) => {
            web_sys::console::warn_1(&JsValue::from_str(&format!(
                "[habilis-network webrtc] the browser refused the ICE configuration \
                 ({error:?}); retrying with no ICE servers (host candidates only)"
            )));
            RtcPeerConnection::new_with_configuration(&IceServers::host_only().to_configuration())
                .map(|peer_connection| (peer_connection, false))
                .map_err(|retry_error| js_err("RTCPeerConnection", &retry_error))
        }
    }
}

/// A negotiated browser session attached into a [`BrowserHubTransport`].
pub struct BrowserSession {
    pub remote: EndpointId,
}

impl std::fmt::Debug for BrowserSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserSession")
            .field("remote", &self.remote)
            .finish()
    }
}

/// An `RTCPeerConnection` that closes itself unless it is released.
///
/// Every early return on the way to a session used to drop an open peer
/// connection without closing it, leaving a live ICE agent — and, when the
/// public TURN fallback is in play, a live TURN allocation — for as long as the
/// tab lives. Failures here are routine by design (ICE fails, a peer vanishes
/// mid-handshake, the offerer never opens its channel), so "routine" was
/// leaking.
///
/// The newtype goes on the *field* rather than the outer struct because `Drop`
/// and destructuring `let Self { .. } = self` cannot coexist.
struct OpenPeerConnection {
    inner: RtcPeerConnection,
    armed: bool,
}

impl OpenPeerConnection {
    fn new(inner: RtcPeerConnection) -> Self {
        Self { inner, armed: true }
    }

    /// Hand the connection to whoever owns its lifetime from here — in
    /// practice the hub, whose session keepalive closes it on drop.
    fn release(mut self) -> RtcPeerConnection {
        self.armed = false;
        self.inner.clone()
    }
}

impl std::ops::Deref for OpenPeerConnection {
    type Target = RtcPeerConnection;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for OpenPeerConnection {
    fn drop(&mut self) {
        if self.armed {
            self.inner.close();
        }
    }
}

impl std::fmt::Debug for OpenPeerConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenPeerConnection")
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}

/// Offerer state between producing the offer and applying the answer.
pub struct PendingOffer {
    peer_connection: OpenPeerConnection,
    data_channel: RtcDataChannel,
    callbacks: Vec<JsValue>,
}

impl std::fmt::Debug for PendingOffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingOffer")
            .finish_non_exhaustive()
    }
}

/// Answerer state between sending the answer and the channel opening.
pub struct PendingAnswer {
    peer_connection: OpenPeerConnection,
    /// Filled by `ondatachannel` when the remote opens the channel.
    channel_rx: futures::channel::oneshot::Receiver<RtcDataChannel>,
    /// Datagrams that arrived before the hub's handler was installed, in
    /// arrival order — see the buffering handler in [`answer`].
    backlog: std::rc::Rc<std::cell::RefCell<PreAttachBacklog>>,
    callbacks: Vec<JsValue>,
}

/// The answerer's pre-attach buffer — see the buffering handler in [`answer`].
///
/// Bounded at [`IN_QUEUE`](crate::IN_QUEUE), the inbound queue's
/// own capacity: at handoff the whole buffer is `try_send`-delivered into a
/// queue of exactly that many slots, so anything held past it could never be
/// delivered — an unbounded buffer only grew browser memory for as long as
/// the signal round dawdled, and the excess was dropped at attach anyway.
/// When full, new datagrams are refused rather than old ones evicted: the
/// QUIC Initial and handshake flights arrive first, and losing those costs
/// the connection where losing a later datagram costs a retransmit.
pub(crate) struct PreAttachBacklog {
    datagrams: Vec<Vec<u8>>,
    dropped: usize,
}

impl PreAttachBacklog {
    pub(crate) fn new() -> Self {
        Self {
            datagrams: Vec::new(),
            dropped: 0,
        }
    }

    pub(crate) fn push(&mut self, bytes: Vec<u8>) {
        if self.datagrams.len() >= crate::IN_QUEUE {
            self.dropped += 1;
            return;
        }
        self.datagrams.push(bytes);
    }

    /// Take everything held, plus how many datagrams were refused over the
    /// cap. The buffer is empty afterwards, so it cannot deliver twice.
    pub(crate) fn take(&mut self) -> (Vec<Vec<u8>>, usize) {
        (
            std::mem::take(&mut self.datagrams),
            std::mem::take(&mut self.dropped),
        )
    }
}

impl std::fmt::Debug for PendingAnswer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingAnswer")
            .finish_non_exhaustive()
    }
}

/// Start a negotiation as the offerer.
///
/// # Errors
/// The peer connection cannot be created, SDP generation fails, or ICE
/// gathers no candidates.
pub async fn offer(
    local: EndpointId,
    ice: &IceServers,
) -> Result<(PendingOffer, SignalEnvelope), JsValue> {
    let (peer_connection, expects_srflx) = new_peer_connection(ice)?;
    let peer_connection = OpenPeerConnection::new(peer_connection);
    // Unreliable + unordered: the channel carries QUIC datagrams, and QUIC
    // already owns loss recovery and congestion control. Reliable ordered
    // SCTP underneath it would stack a second retransmission loop and
    // head-of-line-block unrelated QUIC streams. The answerer adopts this
    // config from DCEP, so the offerer is the only place it is declared.
    let channel_init = web_sys::RtcDataChannelInit::new();
    channel_init.set_ordered(false);
    channel_init.set_max_retransmits(0);
    let data_channel = peer_connection
        .create_data_channel_with_data_channel_dict(DATA_CHANNEL_LABEL, &channel_init);
    data_channel.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);
    // Do not install onmessage yet — `complete` attaches first so the hub
    // handler is live before the channel opens (avoids dropping QUIC Initials).

    let sdp_offer = JsFuture::from(peer_connection.create_offer())
        .await
        .map_err(|error| js_err("createOffer", &error))?;
    let offer_init: RtcSessionDescriptionInit = sdp_offer.unchecked_into();
    JsFuture::from(peer_connection.set_local_description(&offer_init))
        .await
        .map_err(|error| js_err("setLocalDescription", &error))?;
    wait_ice_complete(&peer_connection, expects_srflx).await;
    let local_sdp = peer_connection
        .local_description()
        .ok_or_else(|| JsValue::from_str("no local description after gathering"))?
        .sdp();
    require_candidates("offer", &local_sdp)?;

    let envelope = SignalEnvelope::offer(local, local_sdp);
    Ok((
        PendingOffer {
            peer_connection,
            data_channel,
            callbacks: Vec::new(),
        },
        envelope,
    ))
}

impl PendingOffer {
    /// Apply the remote answer, wait for the channel, attach into `hub`.
    ///
    /// # Errors
    /// A non-answer envelope, a bad SDP, the channel never opening, or attach.
    pub async fn complete(
        self,
        hub: &BrowserHubTransport,
        answer: &SignalEnvelope,
    ) -> Result<BrowserSession, JsValue> {
        let Self {
            peer_connection,
            data_channel,
            callbacks,
        } = self;

        let remote = answer
            .claimed_endpoint()
            .map_err(|error| any_err("answer endpoint id", error))?;
        let SignalEnvelope::Answer { sdp, .. } = answer else {
            return Err(JsValue::from_str("expected an answer envelope"));
        };

        let answer_init = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
        answer_init.set_sdp(sdp);
        JsFuture::from(peer_connection.set_remote_description(&answer_init))
            .await
            .map_err(|error| js_err("setRemoteDescription", &error))?;

        // Attach before Open so inbound QUIC Initials are not lost between
        // the channel opening and the onmessage handler being installed.
        //
        // The guard is what makes that early attach safe. If the channel never
        // opens — ICE failed, or the deadline passed while it was still
        // Connecting — dropping the guard on the way out removes the session
        // and closes the handles. Without it the entry stayed forever, because
        // a channel that never opened never fires `onclose` either: it counted
        // toward the direct-peer total, answered `has_session` so the pair was
        // never retried, and told QUIC it was a valid send address.
        let pc = peer_connection.release();
        let guard = hub
            .attach(remote, pc.clone(), data_channel.clone(), callbacks)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        wait_channel_open(&data_channel, &pc).await?;
        guard.commit();
        Ok(BrowserSession { remote })
    }
}

/// Answer a remote offer.
///
/// # Errors
/// A non-offer envelope, SDP / peer-connection setup fails, or ICE gathers
/// no candidates.
pub async fn answer(
    local: EndpointId,
    offer: &SignalEnvelope,
    ice: &IceServers,
) -> Result<(PendingAnswer, SignalEnvelope), JsValue> {
    let SignalEnvelope::Offer { sdp, .. } = offer else {
        return Err(JsValue::from_str("expected an offer envelope"));
    };

    let (peer_connection, expects_srflx) = new_peer_connection(ice)?;
    let peer_connection = OpenPeerConnection::new(peer_connection);

    let (channel_tx, channel_rx) = futures::channel::oneshot::channel::<RtcDataChannel>();
    let channel_tx = std::cell::RefCell::new(Some(channel_tx));
    // Everything that arrives before the hub's own `onmessage` is installed.
    //
    // The offerer has no such gap: it owns the channel from `create_data_channel`
    // and attaches before the channel opens. The answerer only meets the channel
    // in `ondatachannel` — by which time it is already `open` — and cannot attach
    // from here, because `attach` needs the hub and the authenticated remote id,
    // neither of which this closure has. Between this event and
    // `PendingAnswer::complete` there is at least one turn of the microtask
    // queue, and the browser gives a data channel no inbound buffer: whatever
    // the offerer sent in that window is simply gone.
    //
    // A QUIC Initial lost there is survivable — QUIC retransmits it. A *burst*
    // lost there is not the same thing: the channel is negotiated
    // `maxRetransmits: 0`, so SCTP will not resend, and QUIC's own recovery
    // rides the same lane. So the handler goes on immediately and buffers, and
    // `complete` hands the backlog to the hub in arrival order.
    let backlog = std::rc::Rc::new(std::cell::RefCell::new(PreAttachBacklog::new()));
    let mut callbacks: Vec<JsValue> = Vec::new();
    let early = {
        let backlog = std::rc::Rc::clone(&backlog);
        Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |event: web_sys::MessageEvent| {
            if let Some(bytes) = super::transport::message_bytes(&event) {
                backlog.borrow_mut().push(bytes);
            }
        })
    };
    let ondatachannel = {
        let early = early.as_ref().unchecked_ref::<js_sys::Function>().clone();
        Closure::<dyn FnMut(RtcDataChannelEvent)>::new(move |event: RtcDataChannelEvent| {
            let channel = event.channel();
            channel.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);
            channel.set_onmessage(Some(&early));
            if let Some(tx) = channel_tx.borrow_mut().take() {
                let _ = tx.send(channel);
            }
        })
    };
    peer_connection.set_ondatachannel(Some(ondatachannel.as_ref().unchecked_ref()));
    // Retained for the peer connection's lifetime: `attach` replaces the
    // handler, but the closure must outlive the moment it is detached or a
    // still-queued event would invoke freed memory.
    callbacks.push(early.into_js_value());

    let offer_init = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
    offer_init.set_sdp(sdp);
    JsFuture::from(peer_connection.set_remote_description(&offer_init))
        .await
        .map_err(|error| js_err("setRemoteDescription", &error))?;

    let sdp_answer = JsFuture::from(peer_connection.create_answer())
        .await
        .map_err(|error| js_err("createAnswer", &error))?;
    let answer_init: RtcSessionDescriptionInit = sdp_answer.unchecked_into();
    JsFuture::from(peer_connection.set_local_description(&answer_init))
        .await
        .map_err(|error| js_err("setLocalDescription", &error))?;
    wait_ice_complete(&peer_connection, expects_srflx).await;
    let local_sdp = peer_connection
        .local_description()
        .ok_or_else(|| JsValue::from_str("no local description after gathering"))?
        .sdp();
    require_candidates("answer", &local_sdp)?;

    let envelope = SignalEnvelope::answer(local, local_sdp);
    callbacks.push(ondatachannel.into_js_value());
    Ok((
        PendingAnswer {
            peer_connection,
            channel_rx,
            backlog,
            callbacks,
        },
        envelope,
    ))
}

impl PendingAnswer {
    /// Wait for the offerer's data channel, then attach into `hub`.
    ///
    /// `remote` is the authenticated peer id (prefer `connection.remote_id()`
    /// over the envelope claim).
    ///
    /// # Errors
    /// The channel never arrives or attach fails.
    pub async fn complete(
        self,
        hub: &BrowserHubTransport,
        remote: EndpointId,
    ) -> Result<BrowserSession, JsValue> {
        let Self {
            peer_connection,
            channel_rx,
            backlog,
            callbacks,
        } = self;

        let data_channel = match futures::future::select(
            channel_rx,
            Box::pin(async {
                sleep_ms(CHANNEL_OPEN_DEADLINE_MS_I32).await;
            }),
        )
        .await
        {
            futures::future::Either::Left((Ok(channel), _)) => channel,
            futures::future::Either::Left((Err(_), _)) => {
                return Err(JsValue::from_str("data channel sender dropped"));
            }
            futures::future::Either::Right(((), _)) => {
                return Err(JsValue::from_str("timed out waiting for ondatachannel"));
            }
        };

        // Attach before Open — same race as the offerer path: the peer may
        // dial the mount ALPN the instant its channel is open. Same guard, for
        // the same reason; see `PendingOffer::complete`. `attach` installs the
        // hub's own `onmessage`, replacing the buffering one.
        let pc = peer_connection.release();
        let guard = hub
            .attach(remote, pc.clone(), data_channel.clone(), callbacks)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        // Hand over what arrived before that handler existed, in arrival order
        // and before anything the hub receives itself — the channel is
        // unordered, so this is not a sequencing promise, only a refusal to
        // reorder what we already hold. Taken (not cloned) so the buffer cannot
        // be delivered twice if this is ever called again.
        let (early, over_cap) = backlog.borrow_mut().take();
        if over_cap > 0 {
            web_sys::console::warn_1(&JsValue::from_str(&format!(
                "[habilis-network webrtc] pre-attach backlog refused {over_cap} datagram(s) over its cap for {remote}"
            )));
        }
        if !early.is_empty() {
            web_sys::console::log_1(&JsValue::from_str(&format!(
                "[habilis-network webrtc] delivered {} datagram(s) buffered before attach for {remote}",
                early.len()
            )));
            hub.inject_inbound(remote, early);
        }
        wait_channel_open(&data_channel, &pc).await?;
        guard.commit();
        Ok(BrowserSession { remote })
    }
}

/// Log local/remote SDP snippets when a dial fails after envelopes were swapped.
pub fn log_signal_sdps(role: &str, local: &SignalEnvelope, remote: &SignalEnvelope) {
    let local_sdp = envelope_sdp(local).unwrap_or("");
    let remote_sdp = envelope_sdp(remote).unwrap_or("");
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "[habilis-network webrtc] {role} local candidates: {}",
        format_candidate_counts(local_sdp)
    )));
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "[habilis-network webrtc] {role} remote candidates: {}",
        format_candidate_counts(remote_sdp)
    )));
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "[habilis-network webrtc] {role} local SDP:\n{local_sdp}"
    )));
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "[habilis-network webrtc] {role} remote SDP:\n{remote_sdp}"
    )));
}

fn envelope_sdp(envelope: &SignalEnvelope) -> Option<&str> {
    match envelope {
        SignalEnvelope::Offer { sdp, .. } | SignalEnvelope::Answer { sdp, .. } => Some(sdp),
        SignalEnvelope::Error { .. } => None,
    }
}

fn js_err(context: &str, error: &JsValue) -> JsValue {
    JsValue::from_str(&format!("{context}: {error:?}"))
}

fn any_err(context: &str, error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&format!("{context}: {error}"))
}

/// Wait for ICE gathering — until `complete`, until the candidates in hand
/// settle, or until the deadline.
///
/// Vanilla ICE, deliberately: candidates ride inside the SDP, so gathering
/// must finish before the envelope is written. Early exit — not trickle — is
/// how that stays fast: once a usable set is quiet for [`ICE_QUIET_MS`], the
/// SDP ships with the candidates in hand, which is exactly what the browser
/// itself falls back to when a STUN server never answers. Trickle would only
/// shave the quiet period, at the price of a wire-format change plus
/// capability negotiation across every signal carrier — rejected in
/// agent-share's `docs/research/connect-latency.md`. Fewer `a=candidate`
/// lines is legal SDP, so old and new peers interop unchanged.
///
/// `expects_srflx` guards NAT traversal: with no TURN by policy, srflx is the
/// only rung that crosses a NAT, so the early exit refuses to fire before one
/// arrives — unless the connection has no STUN servers and srflx can never
/// come.
async fn wait_ice_complete(peer_connection: &RtcPeerConnection, expects_srflx: bool) {
    let deadline = now_ms() + ICE_GATHERING_DEADLINE_MS;
    let mut candidates_seen = 0usize;
    let mut last_change_ms = now_ms();
    loop {
        if peer_connection.ice_gathering_state() == RtcIceGatheringState::Complete {
            return;
        }
        let now = now_ms();
        // Always proceed after the deadline — previously we looped forever when
        // gathering stalled with zero `a=candidate` lines. Callers then check
        // for candidates and hard-fail if none landed.
        if now >= deadline {
            return;
        }
        // The browser keeps `localDescription` current as candidates gather,
        // so polling it needs no event plumbing beyond the loop that must
        // exist for the deadline anyway.
        if let Some(description) = peer_connection.local_description() {
            let (host, mdns, srflx, relay, other) = count_candidates(&description.sdp());
            let total = host + mdns + srflx + relay + other;
            if total != candidates_seen {
                candidates_seen = total;
                last_change_ms = now;
            }
            if gathering_settled(host + mdns, srflx, now - last_change_ms, expects_srflx) {
                return;
            }
        }
        sleep_ms(POLL_MS).await;
    }
}

/// Whether the candidate set in hand is enough to stop gathering early.
///
/// `local` counts host plus mdns lines: Chrome obfuscates host candidates as
/// mDNS `.local` names, so counting `host` alone would never see them.
fn gathering_settled(local: usize, srflx: usize, quiet_ms: f64, expects_srflx: bool) -> bool {
    local >= 1 && (srflx >= 1 || !expects_srflx) && quiet_ms >= ICE_QUIET_MS
}

pub(super) fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// Count ICE candidates in `sdp` and refuse a candidate-less envelope.
fn require_candidates(role: &str, sdp: &str) -> Result<(), JsValue> {
    let (host, mdns, srflx, relay, other) = count_candidates(sdp);
    let total = host + mdns + srflx + relay + other;
    web_sys::console::log_1(&JsValue::from_str(&format!(
        "[habilis-network webrtc] {role} ICE candidates: host={host} mdns={mdns} srflx={srflx} relay={relay} other={other}"
    )));
    if total == 0 {
        return Err(JsValue::from_str(
            "browser gathered no ICE candidates — WebRTC/UDP blocked (Local Network permission, VPN, or policy)",
        ));
    }
    Ok(())
}

fn count_candidates(sdp: &str) -> (usize, usize, usize, usize, usize) {
    let mut host = 0;
    let mut mdns = 0;
    let mut srflx = 0;
    let mut relay = 0;
    let mut other = 0;
    for line in sdp.lines() {
        if !line.starts_with("a=candidate:") {
            continue;
        }
        // Classify on the candidate's own `typ` before looking for `.local`:
        // a srflx line can carry an mDNS-obfuscated related address
        // (`raddr abc.local`), and reading any `.local` as mdns kept srflx
        // at zero — which held `gathering_settled` open for the browser's
        // full gathering ladder. Only a host candidate is mdns-obfuscated
        // as a whole.
        if line.contains(" typ srflx") {
            srflx += 1;
        } else if line.contains(" typ relay") {
            relay += 1;
        } else if line.contains(" typ host") {
            if line.contains(".local") {
                mdns += 1;
            } else {
                host += 1;
            }
        } else if line.contains(".local") {
            mdns += 1;
        } else {
            other += 1;
        }
    }
    (host, mdns, srflx, relay, other)
}

fn format_candidate_counts(sdp: &str) -> String {
    let (host, mdns, srflx, relay, other) = count_candidates(sdp);
    format!("host={host} mdns={mdns} srflx={srflx} relay={relay} other={other}")
}

fn ice_state_label(state: RtcIceConnectionState) -> &'static str {
    match state {
        RtcIceConnectionState::New => "new",
        RtcIceConnectionState::Checking => "checking",
        RtcIceConnectionState::Connected => "connected",
        RtcIceConnectionState::Completed => "completed",
        RtcIceConnectionState::Failed => "failed",
        RtcIceConnectionState::Disconnected => "disconnected",
        RtcIceConnectionState::Closed => "closed",
        _ => "unknown",
    }
}

fn gather_state_label(state: RtcIceGatheringState) -> &'static str {
    match state {
        RtcIceGatheringState::New => "new",
        RtcIceGatheringState::Gathering => "gathering",
        RtcIceGatheringState::Complete => "complete",
        _ => "unknown",
    }
}

fn channel_state_label(state: web_sys::RtcDataChannelState) -> &'static str {
    match state {
        web_sys::RtcDataChannelState::Connecting => "connecting",
        web_sys::RtcDataChannelState::Open => "open",
        web_sys::RtcDataChannelState::Closing => "closing",
        web_sys::RtcDataChannelState::Closed => "closed",
        _ => "unknown",
    }
}

async fn wait_channel_open(
    data_channel: &RtcDataChannel,
    peer_connection: &RtcPeerConnection,
) -> Result<(), JsValue> {
    let deadline = now_ms() + CHANNEL_OPEN_DEADLINE_MS;
    loop {
        let ice = peer_connection.ice_connection_state();
        // `connectionState`, not `iceConnectionState`: it also covers a DTLS
        // failure, and it is the state the hub's watchdog judges after the
        // channel opens, so setup and steady state agree on what "failed" is.
        if peer_connection.connection_state() == RtcPeerConnectionState::Failed {
            return Err(JsValue::from_str(
                "ICE failed — no route between the peers (host/mDNS blocked and TURN did not connect)",
            ));
        }
        match data_channel.ready_state() {
            web_sys::RtcDataChannelState::Open => return Ok(()),
            web_sys::RtcDataChannelState::Closing | web_sys::RtcDataChannelState::Closed => {
                return Err(JsValue::from_str(&format!(
                    "data channel closed during setup (ready_state={}, ice_connection_state={}, ice_gathering_state={})",
                    channel_state_label(data_channel.ready_state()),
                    ice_state_label(ice),
                    gather_state_label(peer_connection.ice_gathering_state()),
                )));
            }
            // Still negotiating. `_` rides along because `RtcDataChannelState`
            // is a generated web-sys enum that can grow a variant without us
            // touching anything, and "keep waiting" is the right answer to a
            // state we have not heard of.
            web_sys::RtcDataChannelState::Connecting | _ => {}
        }
        if now_ms() >= deadline {
            return Err(JsValue::from_str(&format!(
                "data channel never opened (ready_state={}, ice_connection_state={}, ice_gathering_state={})",
                channel_state_label(data_channel.ready_state()),
                ice_state_label(ice),
                gather_state_label(peer_connection.ice_gathering_state()),
            )));
        }
        sleep_ms(POLL_MS).await;
    }
}

/// Sleep, off the global's `setTimeout` rather than the `Window`'s.
///
/// Identical inside a page. It matters everywhere else: `web_sys::window()` is
/// `None` under Node and in a worker, and the previous fallback resolved the
/// promise *immediately* rather than hang. That silently collapsed every
/// deadline built on this future to zero — `wait_ice_complete` returned before
/// a single candidate was gathered, so `require_candidates` rejected the answer
/// ~55 ms in, and the 60 s `ondatachannel` guard lost its race on the first
/// tick and reported "timed out waiting for ondatachannel". A Node peer could
/// therefore never complete a WebRTC handshake, in either role.
///
/// Resolving immediately is kept only for a global with no `setTimeout` at all,
/// where hanging really would be worse.
pub(super) async fn sleep_ms(millis: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        use wasm_bindgen::JsCast as _;
        let global = js_sys::global();
        match js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout")) {
            Ok(set_timeout) if set_timeout.is_function() => {
                let set_timeout: js_sys::Function = set_timeout.unchecked_into();
                let _ = set_timeout.call2(&global, &resolve, &JsValue::from(millis));
            }
            _ => {
                let _ = resolve.call0(&JsValue::NULL);
            }
        }
    });
    let _ = JsFuture::from(promise).await;
}

#[cfg(test)]
mod tests {
    use super::{ICE_QUIET_MS, PreAttachBacklog, count_candidates, gathering_settled};

    const QUIET: f64 = ICE_QUIET_MS;

    #[test]
    fn the_pre_attach_backlog_is_bounded_at_the_inbound_queue() {
        // `inject_inbound` try_sends into a queue of exactly IN_QUEUE slots,
        // so anything held past that could never be delivered: an unbounded
        // buffer only grew browser memory until attach, where the excess was
        // dropped anyway. The earliest datagrams are the ones kept — the QUIC
        // Initial and handshake flights arrive first, and losing those costs
        // the connection where losing a later datagram costs a retransmit.
        let cap = crate::IN_QUEUE;
        let mut backlog = PreAttachBacklog::new();
        for index in 0..cap + 3 {
            backlog.push(index.to_le_bytes().to_vec());
        }
        let (kept, dropped) = backlog.take();
        assert_eq!(
            kept.len(),
            cap,
            "held datagrams stop at the queue's own capacity"
        );
        assert_eq!(
            dropped, 3,
            "the overflow is counted, not silently forgotten"
        );
        assert_eq!(
            kept[0],
            0usize.to_le_bytes().to_vec(),
            "the earliest datagrams win"
        );
        // Taken means gone: a second take delivers nothing twice.
        assert_eq!(backlog.take().0.len(), 0);
    }

    #[test]
    fn a_srflx_with_an_mdns_raddr_counts_as_srflx() {
        // Some browsers obfuscate the related address too: `raddr abc.local`
        // on a srflx line. Reading any `.local` as mdns kept srflx at zero,
        // which held `gathering_settled` open for the browser's full
        // gathering ladder on every offer and answer.
        let sdp =
            "a=candidate:1 1 udp 1686052607 1.2.3.4 50000 typ srflx raddr abc.local rport 9\r\n";
        assert_eq!(count_candidates(sdp), (0, 0, 1, 0, 0));
    }

    #[test]
    fn an_mdns_obfuscated_host_still_counts_as_mdns() {
        let sdp = "a=candidate:1 1 udp 2113937151 abcd1234.local 54321 typ host generation 0\r\n";
        assert_eq!(count_candidates(sdp), (0, 1, 0, 0, 0));
    }

    #[test]
    fn no_candidates_never_settles() {
        assert!(!gathering_settled(0, 0, QUIET * 100.0, true));
        assert!(!gathering_settled(0, 0, QUIET * 100.0, false));
    }

    #[test]
    fn srflx_is_required_when_stun_servers_are_configured() {
        // Host-only in hand: keep waiting — srflx is the only NAT rung.
        assert!(!gathering_settled(2, 0, QUIET, true));
        assert!(gathering_settled(2, 1, QUIET, true));
    }

    #[test]
    fn srflx_is_waived_without_stun_servers() {
        // host_only() / degraded config: srflx can never arrive.
        assert!(gathering_settled(1, 0, QUIET, false));
    }

    #[test]
    fn a_fresh_candidate_resets_the_quiet_period() {
        assert!(!gathering_settled(1, 1, QUIET - 1.0, true));
        assert!(gathering_settled(1, 1, QUIET, true));
    }

    #[test]
    fn srflx_alone_is_not_enough() {
        // No host/mdns line yet means gathering only just started; the local
        // candidates are instant, so their absence says "keep waiting".
        assert!(!gathering_settled(0, 1, QUIET, true));
    }
}
