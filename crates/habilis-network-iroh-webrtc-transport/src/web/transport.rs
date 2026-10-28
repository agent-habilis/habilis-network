//! Multi-session browser `WebRTC` transport.
//!
//! The consumer and the producer share one shape: a hub that owns zero or more
//! data channels, keyed by remote [`EndpointId`]. The consumer attaches one
//! session after offering; the producer attaches each peer that signals in.

mod browser_hub_transport;
mod browser_rtc_transport;
mod browser_session_guard;
mod data_channel_counters;
mod inbound_packet;
mod selected_pair_stats;
mod session_counters;
mod session_counts;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use futures::channel::mpsc;
use iroh::EndpointId;
use iroh::endpoint::transports::{CustomEndpoint, CustomSender, RecvInfo, Transmit};
use iroh_base::CustomAddr;
use js_sys::Reflect;
use n0_watcher::Watchable;
use wasm_bindgen::JsCast as _;
use wasm_bindgen::prelude::{Closure, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{MessageEvent, RtcDataChannel, RtcPeerConnection, RtcPeerConnectionState};

use super::jsep::{now_ms, sleep_ms};
use crate::connection_phase::ConnectionPhase;
use crate::registry::Registry;
use crate::verdict::{DISCONNECT_GRACE_MS, Verdict, judge_state};

pub use browser_hub_transport::BrowserHubTransport;
pub use browser_rtc_transport::BrowserRtcTransport;
pub use browser_session_guard::BrowserSessionGuard;
pub use data_channel_counters::DataChannelCounters;
pub(crate) use inbound_packet::InboundPacket;
pub use selected_pair_stats::SelectedPairStats;
pub use session_counters::SessionCounters;
pub use session_counts::SessionCounts;

/// Stop queueing into the channel above this much buffered data.
const BUFFER_CAP: u32 = 1 << 20;
/// The suffix an mDNS candidate address carries, which the browser hands out
/// in place of a private IP once it has anonymized the candidate.
const MDNS_SUFFIX: &str = ".local";

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
const _: () = assert!(
    DISCONNECT_GRACE_MS_I32 as f64 == DISCONNECT_GRACE_MS,
    "the i32 disconnect grace constant matches the f64 one"
);

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
) -> Option<(HashMap<String, js_sys::Object>, js_sys::Object)> {
    let by_id: HashMap<String, js_sys::Object> =
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
fn selected_pair_id(by_id: &HashMap<String, js_sys::Object>) -> Option<String> {
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
        use futures::StreamExt as _;
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
                    recv_infos[0] = RecvInfo::new(crate::custom_addr(packet.from), None);
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

/// The console line for a drop counter that is worth logging: a warning once the drops are
/// sustained, a debug line before (see `drops_are_sustained`).
fn console_drop(total: u64, line: impl FnOnce() -> String) {
    if !crate::should_log_drop(total) {
        return;
    }
    let line = JsValue::from_str(&line());
    if crate::drops_are_sustained(total) {
        web_sys::console::warn_1(&line);
    } else {
        web_sys::console::debug_1(&line);
    }
}
