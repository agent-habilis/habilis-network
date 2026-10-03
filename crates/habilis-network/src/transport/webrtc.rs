//! The mesh's `WebRTC` signalling plane: how two peers that cannot reach each
//! other over IP still end up holding a direct data channel.
//!
//! The engine already carries a [`WebRtcHandle`] into `build_endpoint`
//! (`lookup::TransportHandles`), but until this module nothing ever *filled*
//! it: the transport was registered and permanently empty, because a session
//! only exists once two peers have exchanged SDP, and nothing exchanged SDP.
//! This is that exchange.
//!
//! **The relay is the rendezvous.** One short-lived connection on
//! [`MESH_WEBRTC_SIGNAL_ALPN`] carries one JSEP envelope each way and closes.
//! Any transport will do, and over the relay is the interesting case — it is a
//! browser's only way to reach a peer behind NAT, and the mesh's own bootstrap
//! already homes every member on a relay rung. No file or gossip payload ever
//! crosses it; it exists to introduce two peers to each other.
//!
//! **Why a session should exist before the peer is grafted.** A live
//! connection gains a newly attached transport's path only when another
//! connection to the peer completes: that is when iroh opens new paths and
//! re-runs selection (the pinned fork's Initial fan-out patch). Grafting on the
//! attach event gives the pair that connection. A connection that stays up
//! across a later attach, as in a re-race, is moved by a [`nudge`].
//!
//! Both roles are written once and split by target only where the JSEP APIs
//! genuinely differ (str0m natively, `RTCPeerConnection` in a tab). The wire
//! format — [`SignalEnvelope`] — is shared, so a browser and a CLI peer
//! negotiate with each other without either knowing which it is talking to.

use anyhow::{Context, Result};
use habilis_network_iroh_webrtc_transport::{MAX_ENVELOPE_BYTES, SignalEnvelope, WebRtcHandle};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};

use super::LOG_TARGET;
use super::admission::{Refusal, SignalAdmission};

/// ALPN for the JSEP exchange. Wire-load-bearing in the same way
/// [`super::UNICAST_ALPN`] is: both ends must agree, so it moves only with a
/// deliberate protocol break.
pub const MESH_WEBRTC_SIGNAL_ALPN: &[u8] = b"habilis-mesh/webrtc-signal/1";

/// How long to let one negotiation run before giving up.
///
/// Generous because it covers candidate gathering on both sides plus the
/// DTLS/SCTP handshake, and a false timeout costs the whole session. Note the
/// browser side gathers with a vanilla-ICE budget of its own (candidates ride
/// inside the SDP; there is no trickle message), so this must comfortably
/// exceed it.
///
/// Compiled on both targets so the arithmetic below is target-independent.
/// Only the native backend passes it *into* str0m — the browser backend takes
/// no deadline parameter at all, so for a tab [`SignalDeadlines::round`] is the
/// only bound that exists.
#[cfg_attr(
    target_arch = "wasm32",
    expect(
        dead_code,
        reason = "the browser backend takes no deadline; kept on both targets per the note above"
    )
)]
const JSEP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

/// One leg of the envelope exchange: dial, open, write, then wait for the
/// peer's envelope.
///
/// The wait covers the *peer's* SDP construction, which is the expensive part.
/// A browser answerer pays a TURN-credential fetch (≤1.5s) plus a full
/// vanilla-ICE gathering budget (≤10s) before its answer exists; a CLI answerer
/// pays up to two 2s STUN probes. 20s is comfortably past the worst honest path
/// and leaves room for a relay round trip on a throttled tab.
const SIGNAL_EXCHANGE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

/// The whole round, either role.
///
/// Strictly greater than the sum of the two legs, so that in every honest
/// failure an *inner* deadline fires first and names the phase; this one only
/// catches a peer that stalls somewhere with no budget of its own. It also sits
/// below two `alive` ticks, so a peer that always times out is retried on the
/// following tick rather than being skipped indefinitely.
const SIGNAL_ROUND_DEADLINE: std::time::Duration = std::time::Duration::from_secs(45);

/// The application close codes of the transport plane, in one list.
///
/// A code is wire-load-bearing only weakly: a peer too old to know it just sees
/// a closed connection and retries, which is the behaviour it had before. But
/// two meanings on one number would be a silent bug, so every code of the plane
/// lives here and a test holds them apart. Each ALPN reads its own subset.
pub(crate) mod close_code {
    /// We are at our direct-peer ceiling and no peer is idle long enough to
    /// make room.
    ///
    /// Distinct from a failure so the dialer can tell "no room" from "ICE broke"
    /// and back off instead of re-offering every tick.
    pub(crate) const CAP_REFUSED: u32 = 1;
    /// The negotiation failed.
    pub(crate) const SIGNAL_FAILED: u32 = 2;
    /// The negotiation ran out of time, or the Router is shutting down.
    pub(crate) const SIGNAL_ABORTED: u32 = 3;
    /// A gossip connection whose path may not carry payload.
    pub(crate) const GOSSIP_RELAY_REFUSED: u32 = 4;
    /// A unicast connection whose path may not carry payload.
    pub(crate) const UNICAST_RELAY_REFUSED: u32 = 5;
    /// We evicted this peer a short while ago, so its offer is not answered
    /// yet. The dialer backs off, as it does for [`CAP_REFUSED`].
    pub(crate) const EVICTED: u32 = 6;
    /// We let go of the rendezvous on purpose, having enough links to members.
    pub(crate) const RENDEZVOUS_RELEASED: u32 = 7;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn no_two_codes_share_a_number() {
            let all = [
                CAP_REFUSED,
                SIGNAL_FAILED,
                SIGNAL_ABORTED,
                GOSSIP_RELAY_REFUSED,
                UNICAST_RELAY_REFUSED,
                EVICTED,
                RENDEZVOUS_RELEASED,
            ];
            let distinct: std::collections::HashSet<_> = all.into_iter().collect();
            assert_eq!(distinct.len(), all.len());
        }
    }
}

use close_code::{CAP_REFUSED, EVICTED, SIGNAL_ABORTED, SIGNAL_FAILED};

/// Register `remote`'s `WebRTC` transport address after a session attach.
///
/// Load-bearing, not bookkeeping: an attached session is only *usable* once a
/// dial can name it — iroh fans a connect's Initial across the paths in the
/// peer's known addresses, and the custom-transport path exists nowhere else.
/// Without this registration every connection to a session-holding peer still
/// carried exactly one path, the relay, which the lookup-only accept gate then
/// (correctly) refused.
fn register_session_addr(endpoint: &Endpoint, remote: EndpointId) {
    let addr = EndpointAddr::from_parts(
        remote,
        [iroh::TransportAddr::Custom(
            habilis_network_iroh_webrtc_transport::custom_addr(remote),
        )],
    );
    if let Err(error) = crate::lookup::add_peer_addr(endpoint, addr) {
        // `warn`: a session that cannot be named is a session that cannot
        // carry anything, and this is the only line that says why.
        tracing::warn!(target: LOG_TARGET, %remote, %error, "could not register the webrtc transport address");
    } else {
        tracing::debug!(target: LOG_TARGET, %remote, "registered the webrtc transport address");
    }
}

/// The deadlines one round runs under.
///
/// Injectable so tests need not wait 45 real seconds. A `util::tuning` knob
/// would not do: that is a process-wide `OnceLock`, and these tests run in
/// parallel in one process.
///
/// [`JSEP_DEADLINE`] is deliberately *not* in here. It is consumed inside the
/// backends' `complete()`, which the browser backend does not even accept a
/// deadline for, so threading it would buy an injectability only half the
/// targets could honour. [`Self::round`] bounds it from the outside on both.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignalDeadlines {
    /// Bound on each wait for the peer's envelope.
    pub(crate) exchange: std::time::Duration,
    /// Bound on the whole round, both roles.
    pub(crate) round: std::time::Duration,
}

impl SignalDeadlines {
    pub(crate) const DEFAULT: Self = Self {
        exchange: SIGNAL_EXCHANGE_DEADLINE,
        round: SIGNAL_ROUND_DEADLINE,
    };
}

/// How far ICE may reach when gathering candidates.
///
/// A loopback mesh must make no external network call — that is the whole
/// promise of `LookupOpts::loopback()` — but `IceConfig::default()` queries two
/// public STUN servers. Without this, threading the share's real lookups into
/// the mesh derivation would have closed one hole (mDNS, DHT, a published
/// rendezvous) and left this one open.
///
/// Target-independent on purpose. The native backend maps it onto `IceConfig`;
/// the browser backend ignores it, because a tab is never a loopback peer — it
/// has no loopback peers to reach.
#[derive(Debug, Clone, Copy, Default)]
pub struct IceProfile {
    /// Gather host candidates only: no STUN, no TURN, no packets off the box.
    pub host_only: bool,
}

/// The peer refused us: it is at its direct-peer ceiling, or it evicted us
/// recently. Either way we back off for a while.
///
/// A distinct type rather than a message, because the caller has to tell a
/// refusal from an ordinary failure and the two want opposite responses: a
/// refusal quiets this peer for a while, a transient failure is retried. Matching
/// on text could not do that — `anyhow`'s `Display` shows only the outermost
/// context, so the reason was hidden behind whichever step happened to fail.
#[derive(Debug)]
struct CapRefused(EndpointId);

impl std::fmt::Display for CapRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} is at its direct-peer cap", self.0)
    }
}

impl std::error::Error for CapRefused {}

/// Whether a failed offer round was the peer refusing us at its ceiling, or
/// because it evicted us recently.
#[must_use]
pub fn is_cap_refusal(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CapRefused>().is_some()
}

/// Write our envelope and wait for theirs, on an already-open connection.
///
/// Split out so the caller can consult the connection's close reason once for
/// the whole exchange rather than per step.
async fn exchange_envelopes(
    conn: &Connection,
    offer: &[u8],
    remote: EndpointId,
    deadlines: SignalDeadlines,
) -> Result<Vec<u8>> {
    let (mut send, mut recv) = conn.open_bi().await.context("open signal stream")?;
    send.write_all(offer).await.context("send signal offer")?;
    send.finish().context("finish signal stream")?;

    match n0_future::time::timeout(deadlines.exchange, recv.read_to_end(MAX_ENVELOPE_BYTES)).await {
        Ok(raw) => raw.context("read signal answer"),
        Err(_elapsed) => {
            // Close explicitly so the answerer wakes now instead of waiting out
            // its own deadline on a round nobody is listening to any more.
            conn.close(SIGNAL_ABORTED.into(), b"signalling timed out");
            anyhow::bail!(
                "no signal answer from {remote} within {:?}",
                deadlines.exchange
            )
        }
    }
}

/// Whether the peer closed `conn` to tell us to back off.
fn refused_at_cap(conn: &Connection) -> bool {
    matches!(
        conn.close_reason(),
        Some(iroh::endpoint::ConnectionError::ApplicationClosed(ref close))
            if [CAP_REFUSED, EVICTED]
                .into_iter()
                .any(|code| close.error_code.into_inner() == u64::from(code))
    )
}

/// The `ProtocolHandler` the Router runs for [`MESH_WEBRTC_SIGNAL_ALPN`]: read
/// one offer, answer it, attach the resulting session to our hub.
///
/// Holds the hub rather than a channel to the event loop, deliberately. The
/// exchange is self-contained and the loop has nothing to decide about it — and
/// routing it through the loop would put a multi-second negotiation on the one
/// task that must never block.
#[derive(Debug, Clone)]
pub struct WebRtcSignalAcceptor {
    handle: WebRtcHandle,
    /// For registering the peer's transport address on attach; see
    /// [`register_session_addr`].
    endpoint: Endpoint,
    local: EndpointId,
    /// Shared with the dialing side, so the ceiling is one number for the node
    /// rather than one per role.
    admission: SignalAdmission,
    deadlines: SignalDeadlines,
    /// How far ICE may reach — host-only on a loopback mesh.
    ice: IceProfile,
}

impl WebRtcSignalAcceptor {
    #[must_use]
    pub fn new(
        handle: WebRtcHandle,
        endpoint: Endpoint,
        local: EndpointId,
        admission: SignalAdmission,
        ice: IceProfile,
    ) -> Self {
        Self {
            handle,
            endpoint,
            local,
            admission,
            deadlines: SignalDeadlines::DEFAULT,
            ice,
        }
    }

    /// Shorten the deadlines, for tests that must not wait 45 real seconds.
    #[cfg(test)]
    pub(crate) fn with_deadlines(mut self, deadlines: SignalDeadlines) -> Self {
        self.deadlines = deadlines;
        self
    }
}

impl ProtocolHandler for WebRtcSignalAcceptor {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        // The remote's identity comes from the *connection*, never from the
        // envelope. Over an authenticated carrier the TLS-proven id is the real
        // one, and trusting `SignalEnvelope::endpoint_id` instead would let any
        // peer attach a session under someone else's name — which, on a mesh
        // where sessions are keyed by peer, is impersonation rather than merely
        // a wasted negotiation.
        let remote = conn.remote_id();

        // An offer from a peer we already hold a session with is itself the
        // proof that *their* half is gone: a peer with a working session
        // never re-offers (admission's `HaveSession` refuses its dialer).
        // Without this, the recovery from a half-attached session cost the
        // offerer two stale ticks plus our session's idle-out per round —
        // observed as ~2 minutes of "InFlight"/refused re-offers to a
        // browser-held rendezvous. The identity is TLS-proven, so only the
        // peer itself can trigger the detach.
        if self.handle.has_session(&remote) && self.handle.detach(&remote) {
            tracing::debug!(target: LOG_TARGET, %remote, "detached a half-dead session on a fresh offer");
        }

        // Admit *before* spawning, in the synchronous prefix of `accept`. Two
        // things fall out of that ordering:
        //
        // - The ceiling now binds the answering side. The role rule makes the
        //   highest-id peer in a mesh a pure answerer, and with the cap checked
        //   only by dialers it attached everyone who asked.
        // - One peer cannot flood us. Admission is keyed by the TLS-proven id,
        //   so N connections from one peer yield one task; the rest are closed
        //   here and their `Connection`s dropped with them. Before this, a peer
        //   that connected and never opened a stream left a detached task
        //   parked on `accept_bi` forever, one per connection.
        let guard = match self.admission.try_admit(remote, &self.handle) {
            Ok(guard) => guard,
            Err(reason) => {
                let (code, why): (u32, &[u8]) = match reason {
                    Refusal::AtCap => (CAP_REFUSED, b"at the direct-peer cap"),
                    Refusal::Evicted => (EVICTED, b"evicted recently"),
                    Refusal::ShuttingDown => (SIGNAL_ABORTED, b"shutting down"),
                    Refusal::InFlight | Refusal::HaveSession | Refusal::Cooling => {
                        (SIGNAL_FAILED, b"already negotiating")
                    }
                };
                conn.close(code.into(), why);
                tracing::debug!(target: LOG_TARGET, %remote, ?reason, "refused a signal offer");
                return Ok(());
            }
        };

        let handle = self.handle.clone();
        let endpoint = self.endpoint.clone();
        let local = self.local;
        let deadlines = self.deadlines;
        let ice = self.ice;
        let admission = self.admission.clone();
        // Negotiate off the accept future, for two independent reasons. It can
        // take seconds (candidate gathering, then DTLS/SCTP), and holding the
        // Router's accept task that long would serialize inbound offers. And in
        // a browser the JSEP path holds `!Send` web-sys closures, which iroh's
        // `Send` accept future cannot carry at all — `n0_future::task::spawn` is
        // `spawn_local` there, so the requirement simply does not apply.
        //
        // The cost of spawning is that the task escapes the Router's own
        // `JoinSet`, so shutdown cannot reach it and nothing bounds how long it
        // lives. The guard and the round deadline below are what replace those
        // two guarantees.
        let task = n0_future::task::spawn(async move {
            let _guard = guard;
            // Boxed: the answer future carries the whole sans-io str0m state,
            // large enough that clippy flags it on this task's stack.
            match n0_future::time::timeout(
                deadlines.round,
                Box::pin(answer_one(&conn, local, remote, &handle, deadlines, ice)),
            )
            .await
            {
                Ok(Ok(())) => {
                    admission.note_success(remote);
                    register_session_addr(&endpoint, remote);
                    conn.close(0u32.into(), b"jsep done");
                    tracing::debug!(target: LOG_TARGET, %remote, "webrtc session attached (answerer)");
                }
                // A failed negotiation is normal operation, not a fault: ICE
                // fails, peers vanish mid-handshake, a NAT refuses. The peer
                // stays reachable over whatever path it already had.
                Ok(Err(error)) => {
                    conn.close(SIGNAL_FAILED.into(), b"answer failed");
                    tracing::debug!(target: LOG_TARGET, %remote, %error, "webrtc answer failed");
                }
                Err(_elapsed) => {
                    conn.close(SIGNAL_ABORTED.into(), b"answer timed out");
                    tracing::debug!(
                        target: LOG_TARGET,
                        %remote,
                        deadline = ?deadlines.round,
                        "webrtc answer timed out"
                    );
                }
            }
        });
        self.admission.track(remote, task.abort_handle());
        Ok(())
    }

    /// Cancel every round in flight.
    ///
    /// The trait's own hook, which `Router::shutdown` awaits *before* it closes
    /// the endpoint — so this is how the spawned answer tasks, which are not in
    /// the Router's `JoinSet`, get reached at all. Aborting rather than
    /// draining is right: the endpoint is about to go, so an in-flight
    /// negotiation has nothing left to attach to.
    ///
    /// Synchronous body inside an `async fn`, so the future stays `Send` as the
    /// trait requires and no `MutexGuard` crosses an await.
    async fn shutdown(&self) {
        self.admission.close();
    }
}

/// Read the offer off `conn`, answer it, and attach the session.
async fn answer_one(
    conn: &Connection,
    local: EndpointId,
    remote: EndpointId,
    handle: &WebRtcHandle,
    deadlines: SignalDeadlines,
    ice: IceProfile,
) -> Result<()> {
    // Bounded: a peer that connects and never opens a stream would otherwise
    // park this task forever, and its QUIC keep-alives mean the connection
    // never idles out on its own.
    let (mut send, mut recv) = n0_future::time::timeout(deadlines.exchange, conn.accept_bi())
        .await
        .context("timed out waiting for the signal stream")?
        .context("accept signal stream")?;
    let raw = n0_future::time::timeout(deadlines.exchange, recv.read_to_end(MAX_ENVELOPE_BYTES))
        .await
        .context("timed out reading the signal offer")?
        .context("read signal offer")?;
    let offer: SignalEnvelope = serde_json::from_slice(&raw).context("parse signal offer")?;

    // Order is load-bearing: put the answer on the wire *before* completing the
    // negotiation. The offerer cannot finish ICE until it has our SDP, so
    // completing first deadlocks both sides into their full gathering budget
    // and then fails — which is exactly what it did.
    let answer = build_answer(local, &offer, ice).await?;
    send.write_all(&serde_json::to_vec(answer.envelope())?)
        .await
        .context("send signal answer")?;
    send.finish().context("finish signal stream")?;
    answer.complete(remote, handle).await
}

/// Offer a session to `peer` and attach it. The caller decides *whether* to
/// dial (see the role rule in `lifecycle`); this only performs the exchange.
///
/// # Errors
/// The signalling dial fails, the peer refuses, or the negotiation does not
/// complete before the deadline.
pub async fn dial_signal(
    endpoint: &Endpoint,
    peer: EndpointAddr,
    handle: &WebRtcHandle,
    ice: IceProfile,
) -> Result<()> {
    Box::pin(dial_signal_with(
        endpoint,
        peer,
        handle,
        SignalDeadlines::DEFAULT,
        ice,
    ))
    .await
}

/// [`dial_signal`] with the deadlines spelled out, so tests need not wait them.
///
/// # Errors
/// As [`dial_signal`].
pub(crate) async fn dial_signal_with(
    endpoint: &Endpoint,
    peer: EndpointAddr,
    handle: &WebRtcHandle,
    deadlines: SignalDeadlines,
    ice: IceProfile,
) -> Result<()> {
    // Bounded as a whole, because every step below can hang and only some of
    // them have a budget of their own. Nothing here was bounded before: the old
    // `JSEP_DEADLINE` wrapped only `complete()`, which runs *after* the answer
    // is read — so a peer that accepted our connection and then stalled before
    // writing kept this future alive for the life of the process, and its QUIC
    // keep-alives meant the connection never idled out either.
    let remote = peer.id;
    match n0_future::time::timeout(
        deadlines.round,
        // Boxed for the same reason `answer_one` is: the pending session state
        // is large, and this future is held across a spawn.
        Box::pin(dial_signal_round(endpoint, peer, handle, deadlines, ice)),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => {
            anyhow::bail!(
                "webrtc signalling with {remote} exceeded {:?}",
                deadlines.round
            )
        }
    }
}

async fn dial_signal_round(
    endpoint: &Endpoint,
    peer: EndpointAddr,
    handle: &WebRtcHandle,
    deadlines: SignalDeadlines,
    ice: IceProfile,
) -> Result<()> {
    let remote = peer.id;
    let local = endpoint.id();

    // Built before the dial, not after: the answerer's `accept_bi` returns as
    // soon as our stream opens, and it then sits through our whole gathering
    // budget waiting to read. Gathering first shortens its read window by
    // several seconds and costs us nothing.
    let offer = build_offer(local, handle, ice).await?;

    let conn = endpoint
        .connect(peer, MESH_WEBRTC_SIGNAL_ALPN)
        .await
        .context("dial the mesh WebRTC signal ALPN")?;

    // Any step of the exchange can be the one that trips over a refusal: a peer
    // at its cap closes as soon as it sees the connection, often before our
    // offer is even written. Consulting the close reason once, on whichever step
    // noticed, is what makes the refusal visible — checking it on only the
    // timeout branch missed every prompt refusal, which is all of them.
    let offer_bytes = serde_json::to_vec(offer.envelope())?;
    let raw = match exchange_envelopes(&conn, &offer_bytes, remote, deadlines).await {
        Ok(raw) => raw,
        Err(error) => {
            return Err(if refused_at_cap(&conn) {
                error.context(CapRefused(remote))
            } else {
                error
            });
        }
    };
    let answer: SignalEnvelope = serde_json::from_slice(&raw).context("parse signal answer")?;

    offer.with_answer(answer).complete(remote, handle).await?;
    register_session_addr(endpoint, remote);
    // Signalling is done the moment the session is attached; the data rides its
    // own connections from here.
    conn.close(0u32.into(), b"jsep done");
    tracing::debug!(target: LOG_TARGET, %remote, "webrtc session attached (offerer)");
    Ok(())
}

/// The most direct peers one node will negotiate sessions with.
///
/// This caps the *session* mesh, which is dense by intent — we want every peer
/// we know about, not just our gossip neighbours. It is deliberately not the
/// same knob as HyParView's `active_view_capacity`: that one sizes the gossip
/// overlay and is fixed when the mesh is built, while this one is ours and can
/// move at runtime. Each session costs a peer connection and, in a browser, up
/// to a full ICE gathering budget — so the ceiling is real, not notional.
///
/// Enforced on **both** roles, and counting rounds in flight, by
/// [`super::admission::SignalAdmission`]. It was neither for a while: only
/// dialers checked it, so the highest-id peer in a mesh — which by the role
/// rule never dials — answered everyone who asked, and the header rendered
/// counts above the ceiling.
///
/// Public so the CLI and the browser render the same denominator they enforce.
/// It used to be written out three times, and the UI read a different copy from
/// the one the engine checked.
pub const MAX_DIRECT_PEERS: usize = 16;

/// Start a `WebRTC` negotiation with `peer`, if one is wanted and not already
/// running. Fire-and-forget: the caller does **not** wait, and the graft
/// proceeds over whatever path is available.
///
/// An earlier version of this gated the graft — held the peer out of the gossip
/// overlay until a direct session existed — on the theory that iroh will not
/// move a live connection onto a transport attached later, so a link formed
/// first stays on the relay. That reasoning is correct, but the cure was worse:
/// running it against a real CLI peer and two browser peers, the CLI reached
/// `link_len=0, meshed=false` and never joined the overlay at all. The
/// higher-id side waits to be dialled, the lower-id side only dials when it
/// sees a `PeerInfo`, and when that ordering does not line up the pair simply
/// never links. Mesh membership is the thing that must not be fragile.
///
/// So: gossip links form immediately, over the relay if that is what is
/// available, and the direct session is negotiated alongside. Connections
/// opened *after* attach — unicast, blob — take the `WebRTC` path. The gossip
/// link for that pair may stay relayed, which is a real cost and the reason
/// `peers_direct` and `peers_gossip` are reported separately rather than as one
/// number.
///
/// **Who offers is decided by id order** — the lower `EndpointId` dials. Both
/// sides compute the same answer with no round trip, so simultaneous mutual
/// offers (which collide on duplicate attach) cannot happen. This mirrors the
/// tie-break `lifecycle` already applies to the gossip dial itself.
/// Does this peer need the `WebRTC` lane to be reachable at all?
///
/// True only when it advertises no IP transport whatsoever — the shape of a
/// browser, which has no IP stack under wasm and so publishes relay addresses
/// only, and of a native peer deliberately run with its IP transports cleared.
///
/// A native peer still discovering its own addresses briefly advertises none.
/// That reads as "unknown" rather than "browser", so no lane is opened for it,
/// and the next `retry_sessions` round sees the settled address.
/// An address carrying *no* transports is not a browser, it is a peer we know
/// nothing about yet, and the two must not be confused. The retry pass had no
/// address to hand and built a bare one, so every native peer read as relay-only
/// and got a data channel it did not need — spending the direct-peer slots the
/// browsers were waiting for.
pub(crate) fn needs_webrtc_lane(addr: &EndpointAddr) -> bool {
    !addr.is_empty() && addr.ip_addrs().next().is_none()
}

/// The local-node twin of [`needs_webrtc_lane`]: does *this* node need the
/// lane? Answered from the node's own transport set, never from its address
/// snapshot — that snapshot is empty while the relay link is down, and empty
/// reads as "unknown" for a remote but must not for ourselves. A wasm node
/// reads `false`: `TransportOpts::within` clears UDP there.
pub(crate) fn local_needs_webrtc_lane(has_udp_transport: bool) -> bool {
    !has_udp_transport
}

/// Whether a pair needs the lane: **either** end lacking IP is enough. The
/// remote is judged by its advertised address, this node by what it knows
/// about itself.
#[must_use]
pub fn pair_needs_lane(remote: &EndpointAddr, local_has_udp_transport: bool) -> bool {
    needs_webrtc_lane(remote) || local_needs_webrtc_lane(local_has_udp_transport)
}

/// Whether a pair runs a `WebRTC` round: a pair that needs the lane always
/// does; a pair with UDP on both ends races the UDP punch, until UDP wins.
/// A UDP pair already `proven` direct with no session has proved its UDP
/// path, so a cold or idled-out pool (which reads as "UDP not selected")
/// does not start the race again on every alive tick.
pub(crate) fn wants_session(pair_needs_lane: bool, udp_selected: bool, proven: bool) -> bool {
    pair_needs_lane || !(udp_selected || proven)
}

/// Whether *this* node's rendezvous graft must wait for a data-channel
/// session: a lane-needing node on a lookup-only mesh. With the relay allowed
/// as a transport nothing needs holding.
pub(crate) fn node_graft_needs_session(relay_transport: bool, has_udp_transport: bool) -> bool {
    !relay_transport && local_needs_webrtc_lane(has_udp_transport)
}

pub(crate) fn negotiate_session(
    state: &mut crate::daemon::state::EventLoopState,
    ctx: &crate::daemon::ctx::HandlerCtx<'_>,
    peer: EndpointId,
    addr: EndpointAddr,
) {
    let Some(handle) = state.webrtc.clone() else {
        // No transport registered: the beacon, or a multihop peer.
        return;
    };
    // A pair where both ends run UDP races the punch: the data channel gives
    // 6× less throughput at 36× the latency (docs/architecture.md §11), so it is worth a
    // JSEP round only while UDP has not won. Once it has, nothing is offered,
    // and a round that finishes after it is detached (`spawn_offer_round`).
    //
    // **Either** end lacking IP makes the lane the pair's only direct path,
    // and testing only the remote is a bug: the lower id dials, so when a
    // browser is the lower id it is the browser that evaluates this. It would
    // see the native peer's IP, skip, and the native — waiting to be dialled —
    // would never offer. The pair would silently never get a channel.
    let needs_lane = pair_needs_lane(&addr, state.local_udp_transport);
    if !wants_session(
        needs_lane,
        state.unicast_pool.selected_is_ip(peer),
        state.direct.get(&peer) == Some(&crate::daemon::state::DirectState::Direct),
    ) {
        tracing::debug!(
            target: LOG_TARGET,
            %peer,
            "udp already selected; leaving this pair on iroh's own transports"
        );
        return;
    }
    // The higher id waits to be dialled, so exactly one offer crosses per pair.
    let local = ctx.endpoint.id();
    if local > peer {
        return;
    }
    // Every other gate — already have a session, already negotiating, at the
    // cap, cooling off after a refusal — is one synchronous decision under one
    // lock. That is what lets in-flight rounds count against the cap: this
    // function is called in a tight loop by `retry_sessions` with nothing
    // awaited between calls, so a check that read only `session_count()` saw
    // the same zero twenty times and spawned twenty dials.
    let guard = match state.webrtc_admission.try_admit(peer, &handle) {
        Ok(guard) => guard,
        Err(reason) => {
            tracing::debug!(target: LOG_TARGET, %peer, ?reason, "not negotiating");
            return;
        }
    };

    let offer = if needs_lane {
        Offer::Lane
    } else {
        Offer::UdpRace
    };
    spawn_offer_round(state, ctx, peer, addr, handle, guard, offer);
}

/// The ALPN a nudge connects on. Its acceptor ([`NudgeAcceptor`]) closes
/// every connection at once: the connect exists only for what iroh does when
/// it completes, which is to try the UDP punch again and re-run path selection
/// over every connection to the peer, moving them onto a newly attached
/// session's path or back to UDP. A connect that fails does neither. Not the
/// signal ALPN (its acceptor detaches a session on a fresh connection) nor
/// unicast (its acceptor holds a connection).
pub(crate) const NUDGE_ALPN: &[u8] = b"habilis-mesh/nudge/0";

/// Closes every nudge at once. See [`NUDGE_ALPN`].
#[derive(Debug, Clone)]
pub(crate) struct NudgeAcceptor;

impl ProtocolHandler for NudgeAcceptor {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        conn.close(0u32.into(), b"nudge");
        Ok(())
    }
}

/// Make iroh re-run path selection to `peer` now. Bounded, and every outcome
/// is ignored.
pub(crate) async fn nudge(endpoint: &Endpoint, peer: EndpointId) {
    if let Ok(Ok(conn)) = n0_future::time::timeout(
        super::pool::DIAL_TIMEOUT,
        endpoint.connect(EndpointAddr::new(peer), NUDGE_ALPN),
    )
    .await
    {
        conn.close(0u32.into(), b"nudge");
    }
}

/// What an offer is for, which decides what happens once its session attaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Offer {
    /// The rendezvous: graft at once, and say so.
    Rendezvous,
    /// A pair that needs the lane: graft at once.
    Lane,
    /// A pair with UDP on both ends: detach instead if UDP won. Only this kind
    /// waits on that check, which dials the unicast lane: a lane pair's graft
    /// has to fire inside the freshly proven window, and the rendezvous accepts
    /// no unicast at all. The check holds the admission slot for up to 8 s
    /// after the round (a 3 s dial, then 5 s for UDP to be selected).
    UdpRace,
}

/// The shared tail of every offer: hold the admission slot in a spawned
/// task (released by `Drop`, so the slot comes back whether the task
/// returns, is dropped, or is aborted at shutdown), run the JSEP round,
/// note a cap refusal — and on attach report the proven path, so the
/// loop's `DirectOutcome` arm grafts inside the freshly proven window.
/// Without that send nothing ever moves a webrtc-shaped peer out of
/// `Pending`: the session attaches and the graft still never fires
/// (observed native↔browser: `links_pending=1` for the life of a cell).
/// Written once — the two offer entry points had grown diverging copies.
fn spawn_offer_round(
    state: &mut crate::daemon::state::EventLoopState,
    ctx: &crate::daemon::ctx::HandlerCtx<'_>,
    peer: EndpointId,
    addr: EndpointAddr,
    handle: WebRtcHandle,
    guard: super::admission::AdmissionGuard,
    offer: Offer,
) {
    let endpoint = ctx.endpoint.clone();
    let admission = state.webrtc_admission.clone();
    let ice = state.webrtc_ice;
    let proven = state.direct_proven.clone();
    let pool = state.unicast_pool.clone();
    let task = n0_future::task::spawn(async move {
        let _guard = guard;
        if let Err(error) = Box::pin(dial_signal(&endpoint, addr, &handle, ice)).await {
            if is_cap_refusal(&error) {
                admission.note_refused(peer);
            }
            tracing::debug!(target: LOG_TARGET, %peer, %error, "webrtc offer failed");
            return;
        }
        // The peer took the round: it is not refusing us, so its wait starts over.
        admission.note_success(peer);
        if offer == Offer::UdpRace && {
            // A connection opened before the attach rides the session only
            // after a connect; the race is judged on the connection after.
            nudge(&endpoint, peer).await;
            pool.udp_won(peer).await
        } {
            // UDP won while the round ran: the session would sit unused and hold
            // one of the direct-peer slots.
            let _ = handle.detach(&peer);
            tracing::debug!(target: LOG_TARGET, %peer, "udp won the race; webrtc session detached");
        } else {
            if offer == Offer::Rendezvous {
                tracing::info!(target: LOG_TARGET, %peer, "webrtc session attached to the rendezvous");
            }
            let _ = proven.send(crate::transport::probe::DirectOutcome { peer, direct: true });
        }
    });
    state.webrtc_admission.track(peer, task.abort_handle());
}

/// Whether the periodic heal legs may graft-dial the rendezvous at all.
///
/// A webrtc-shaped node on a lookup-only mesh must never graft on a timer:
/// the beacon's accept gate holds a relay-only connection and closes it
/// after its deadline, so a timer graft costs a whole hold for nothing. (It
/// no longer wedges the link: the pinned iroh-gossip drops a peer whose
/// connection died before the handshake and redials on the next send.)
/// `has_session` is no defence either: the rival re-check rebuilds the
/// rendezvous endpoint, leaving a session that is locally held but dead on
/// the other end. The only safe
/// trigger is the **attach event itself** — a JSEP round that just completed
/// is the liveness proof — so [`negotiate_rendezvous_session`] reports it
/// through the loop's `DirectOutcome` channel and the graft fires there,
/// within the freshly proven window.
///
/// An IP-capable node joins that rule once it falls back to offering: a
/// beacon it could not punch to in a whole heal interval is a tab, and a
/// timer graft there is the same doomed dial.
pub(crate) fn rendezvous_graftable(state: &crate::daemon::state::EventLoopState) -> bool {
    state.rendezvous_wanted()
        && !state.rendezvous_graft_needs_session
        && !state.rendezvous_offer_fallback
}

/// Offer a `WebRTC` session to the **rendezvous** itself.
///
/// On a mesh whose relay is lookup only, the rendezvous link — like every
/// link — is admitted only on a non-relay path, and a browser-shaped peer
/// (no IP transports) has exactly one way to produce one: the data channel.
/// The beacon answers JSEP for precisely this case, so the tab offers.
///
/// Unlike [`negotiate_session`], the lower-id rule does not apply — the
/// beacon holds no address for a tab and can never be the dialer — and the
/// peer-address lane check is skipped: the rendezvous address is a bare
/// registered id, which reads as "unknown", not "browser". Everything else
/// (admission, the in-flight guard, the cap, the cooldown) is shared.
///
/// A no-op unless: the relay is lookup only, this node is browser-shaped,
/// and the rendezvous link is down. Driven by the heal tick, which runs
/// exactly while that link is down.
pub(crate) fn negotiate_rendezvous_session(
    state: &mut crate::daemon::state::EventLoopState,
    ctx: &crate::daemon::ctx::HandlerCtx<'_>,
) {
    if !state.rendezvous_wanted() {
        // A session the graft never used: a joiner whose links to members came
        // up before its graft to the rendezvous landed. It would hold one of
        // the beacon's slots for ever.
        if !state.rendezvous_linked
            && let Some(handle) = state.webrtc.as_ref()
            && handle.detach(&ctx.rendezvous_id)
        {
            tracing::debug!(target: LOG_TARGET, "detached a rendezvous session that is no longer wanted");
        }
        return;
    }
    if state.relay_transport || state.rendezvous_linked {
        return;
    }
    let Some(handle) = state.webrtc.clone() else {
        return;
    };
    if !local_needs_webrtc_lane(state.local_udp_transport) && !state.rendezvous_offer_fallback {
        // An IP-capable peer normally reaches the rendezvous by punching
        // inside the bootstrap connection — the data channel would be a
        // worse path — so the punch gets the first heal tick. But IP
        // capability says nothing about the *beacon*: a browser-held
        // rendezvous has no UDP to punch to, and without this fallback an
        // IP-capable native could never join a tab's mesh (observed in the
        // browser-first matrix cells). Still linkless next tick: offer.
        // Never on a mesh whose rendezvous cannot answer: a private beacon is
        // native by construction, and the fallback would hold the grafts with
        // nothing to release it.
        if state.rendezvous_answers_jsep {
            state.rendezvous_offer_fallback = true;
        }
        return;
    }
    let rendezvous = ctx.rendezvous_id;
    // A held session with an *unlinked* rendezvous is stale: the beacon's
    // rival re-check releases and re-claims the rendezvous on a fresh
    // endpoint, whose session table starts empty, and this heal tick only
    // runs while the link is down. Without a detach, admission would refuse
    // every re-offer with `HaveSession` and the peer would stay wedged for
    // the life of the process.
    //
    // But not on the *first* tick that sees it: this tick also re-grafts,
    // and the graft dial is what turns the session into a link. Detaching
    // here unconditionally killed the session moments before every dial —
    // a phase lock in which no dial ever saw an attached session. So a held
    // session gets one full tick to produce the link; only one that is
    // still linkless on the next tick is torn down and re-negotiated.
    if handle.has_session(&rendezvous) {
        if !state.rendezvous_session_stale {
            state.rendezvous_session_stale = true;
            return;
        }
        if handle.detach(&rendezvous) {
            tracing::debug!(target: LOG_TARGET, %rendezvous, "detached a stale rendezvous session before re-offering");
        }
    }
    state.rendezvous_session_stale = false;
    let guard = match state.webrtc_admission.try_admit(rendezvous, &handle) {
        Ok(guard) => guard,
        Err(reason) => {
            tracing::debug!(target: LOG_TARGET, %rendezvous, ?reason, "not negotiating with the rendezvous");
            return;
        }
    };
    // The bare id resolves through the address registered by
    // `register_rendezvous` — the relay-homed rendezvous address.
    spawn_offer_round(
        state,
        ctx,
        rendezvous,
        EndpointAddr::new(rendezvous),
        handle,
        guard,
        Offer::Rendezvous,
    );
}

/// A rendezvous offer made off the heal tick: when the loop starts, and when
/// the rendezvous link drops. The heal tick that otherwise makes it is a whole
/// interval away, and until it runs a browser-shaped node has no path onto a
/// lookup-only mesh; a beacon that re-checks inside that window finds nobody
/// negotiating and sheds.
///
/// Only a node that already offers: one that needs the lane, or an IP-capable
/// node whose fallback is armed. An IP-capable node's first call arms the
/// fallback, which holds its timer grafts, so only the heal tick may make it:
/// the punch must first have had a heal interval to land.
pub(crate) fn offer_rendezvous_off_tick(
    state: &mut crate::daemon::state::EventLoopState,
    ctx: &crate::daemon::ctx::HandlerCtx<'_>,
) {
    if offers_off_tick(state) {
        negotiate_rendezvous_session(state, ctx);
    }
}

fn offers_off_tick(state: &crate::daemon::state::EventLoopState) -> bool {
    local_needs_webrtc_lane(state.local_udp_transport) || state.rendezvous_offer_fallback
}

// ── Per-target JSEP ───────────────────────────────────────────────────────
//
// Only these two helpers differ by backend. Everything above — the ALPN, the
// envelope framing, the identity rule, the logging — is written once.

// Gated by target, not by our own `host` feature: which backend the transport
// crate compiles is decided by the target dependency table, so a
// `--no-default-features` *native* build still has str0m, not the browser hub.
#[cfg(not(target_arch = "wasm32"))]
mod backend {
    use super::{
        Context, EndpointId, IceProfile, JSEP_DEADLINE, Result, SignalEnvelope, WebRtcHandle,
    };
    use habilis_network_iroh_webrtc_transport::{
        IceConfig, PendingAnswer, PendingOffer, answer_with, offer_with,
    };

    /// An offer awaiting its answer, plus the envelope to put on the wire.
    pub(super) struct Offer {
        pending: PendingOffer,
        envelope: SignalEnvelope,
        answer: Option<SignalEnvelope>,
    }

    impl Offer {
        pub(super) fn envelope(&self) -> &SignalEnvelope {
            &self.envelope
        }

        pub(super) async fn complete(
            mut self,
            remote: EndpointId,
            handle: &WebRtcHandle,
        ) -> Result<()> {
            let answer = self.answer.take().context("answer not supplied")?;
            // Boxed: the pending session carries the whole sans-io str0m state,
            // large enough to be worth keeping off this future's stack.
            let session = Box::pin(self.pending.complete(&answer, JSEP_DEADLINE))
                .await
                .context("complete WebRTC offer")?;
            handle.attach(remote, session).context("attach session")
        }

        pub(super) fn with_answer(mut self, answer: SignalEnvelope) -> Self {
            self.answer = Some(answer);
            self
        }
    }

    pub(super) async fn build_offer(
        local: EndpointId,
        _handle: &WebRtcHandle,
        profile: IceProfile,
    ) -> Result<Offer> {
        let ice = ice_config(profile);
        let (pending, envelope) = offer_with(local, &ice)
            .await
            .context("build WebRTC offer")?;
        Ok(Offer {
            pending,
            envelope,
            answer: None,
        })
    }

    /// An answer whose envelope is ready to send, with the negotiation still to
    /// be driven. Split so the caller can put the SDP on the wire first.
    pub(super) struct Answer {
        pending: PendingAnswer,
        envelope: SignalEnvelope,
    }

    impl Answer {
        pub(super) fn envelope(&self) -> &SignalEnvelope {
            &self.envelope
        }

        pub(super) async fn complete(
            self,
            remote: EndpointId,
            handle: &WebRtcHandle,
        ) -> Result<()> {
            let session = Box::pin(self.pending.complete(JSEP_DEADLINE))
                .await
                .context("complete WebRTC answer")?;
            handle.attach(remote, session).context("attach session")
        }
    }

    /// Host candidates only when the mesh is loopback: `IceConfig::default()`
    /// queries two public STUN servers, which a loopback mesh promises not to.
    fn ice_config(profile: IceProfile) -> IceConfig {
        if profile.host_only {
            IceConfig::host_only()
        } else {
            IceConfig::default()
        }
    }

    pub(super) async fn build_answer(
        local: EndpointId,
        offer: &SignalEnvelope,
        profile: IceProfile,
    ) -> Result<Answer> {
        let ice = ice_config(profile);
        let (pending, envelope) = answer_with(local, offer, &ice)
            .await
            .context("build WebRTC answer")?;
        Ok(Answer { pending, envelope })
    }
}

#[cfg(target_arch = "wasm32")]
mod backend {
    use super::{Context, EndpointId, IceProfile, Result, SignalEnvelope, WebRtcHandle};
    use habilis_network_iroh_webrtc_transport::{
        BrowserPendingAnswer, BrowserPendingOffer, IceServers, browser_answer, browser_offer,
    };

    pub(super) struct Offer {
        pending: BrowserPendingOffer,
        envelope: SignalEnvelope,
        answer: Option<SignalEnvelope>,
    }

    impl Offer {
        pub(super) fn envelope(&self) -> &SignalEnvelope {
            &self.envelope
        }

        pub(super) async fn complete(
            mut self,
            remote: EndpointId,
            handle: &WebRtcHandle,
        ) -> Result<()> {
            let answer = self.answer.take().context("answer not supplied")?;
            // The browser `complete` attaches into the hub itself, keyed on the
            // id the *answer envelope claims*. We hold the TLS-proven id, so
            // reject a mismatch before it can plant a session under the wrong
            // peer.
            let claimed = answer
                .claimed_endpoint()
                .context("answer carries no usable endpoint id")?;
            anyhow::ensure!(
                claimed == remote,
                "signal answer claims {claimed}, but the connection is with {remote}"
            );
            self.pending
                .complete(&handle.transport(), &answer)
                .await
                .map_err(|error| anyhow::anyhow!("complete WebRTC offer: {error:?}"))?;
            Ok(())
        }

        pub(super) fn with_answer(mut self, answer: SignalEnvelope) -> Self {
            self.answer = Some(answer);
            self
        }
    }

    /// `_profile` is ignored: a tab is never a loopback peer — it has no
    /// loopback peers to reach — so there is no host-only case here.
    pub(super) async fn build_offer(
        local: EndpointId,
        _handle: &WebRtcHandle,
        _profile: IceProfile,
    ) -> Result<Offer> {
        // STUN only: TURN is refused by `habilis-network-iroh-webrtc-transport`.
        let ice = IceServers::default();
        let (pending, envelope) = browser_offer(local, &ice)
            .await
            .map_err(|error| anyhow::anyhow!("build WebRTC offer: {error:?}"))?;
        Ok(Offer {
            pending,
            envelope,
            answer: None,
        })
    }

    pub(super) struct Answer {
        pending: BrowserPendingAnswer,
        envelope: SignalEnvelope,
    }

    impl Answer {
        pub(super) fn envelope(&self) -> &SignalEnvelope {
            &self.envelope
        }

        pub(super) async fn complete(
            self,
            remote: EndpointId,
            handle: &WebRtcHandle,
        ) -> Result<()> {
            // Keyed on the TLS-proven id the caller passed, not the envelope
            // claim.
            self.pending
                .complete(&handle.transport(), remote)
                .await
                .map_err(|error| anyhow::anyhow!("complete WebRTC answer: {error:?}"))?;
            Ok(())
        }
    }

    pub(super) async fn build_answer(
        local: EndpointId,
        offer: &SignalEnvelope,
        _profile: IceProfile,
    ) -> Result<Answer> {
        // STUN only: TURN is refused by `habilis-network-iroh-webrtc-transport`.
        let ice = IceServers::default();
        let (pending, envelope) = browser_answer(local, offer, &ice)
            .await
            .map_err(|error| anyhow::anyhow!("build WebRTC answer: {error:?}"))?;
        Ok(Answer { pending, envelope })
    }
}

use backend::{build_answer, build_offer};

/// Re-attempt negotiation with every known peer we hold no session with.
///
/// Driven by a periodic tick rather than by `PeerInfo`, because `PeerInfo` is
/// the *arrival* signal and stops re-flooding once a pair is linked. A single
/// failed round would otherwise be permanent — the pair keeps a working relay
/// link and silently never gets a direct path, which is the failure mode that
/// looks like everything is fine.
///
/// Cheap: a map walk plus a `has_session` check per peer. The per-peer in-flight
/// guard and the cap inside [`negotiate_session`] do the rest of the work.
pub(crate) fn retry_sessions(
    state: &mut crate::daemon::state::EventLoopState,
    ctx: &crate::daemon::ctx::HandlerCtx<'_>,
) {
    if state.webrtc.is_none() {
        return;
    }
    // Collected first: `negotiate_session` needs `&mut state`, so the borrow of
    // `peer_endpoints` cannot be held across the calls.
    // The peer's own advertised address, not one rebuilt from its id: a
    // rebuilt address carries no transports, so every peer looked like it
    // needed the browser lane and this pass opened a data channel with all of
    // them. The cheap disqualifiers run before the clone — a peer whose
    // session is already attached (admission would refuse it with
    // `HaveSession` anyway) or a pure-IP pair costs a map walk, nothing more.
    // Judged by the address snapshot on purpose, unlike `negotiate_session`:
    // a browser's own address reads as "unknown" here, so its retry pass
    // covers relay-only peers (other tabs) and leaves natives to dial it.
    // Read through `local_needs_webrtc_lane` the pass re-offered to every
    // native each tick, colliding with the native's own dial.
    let own_addr = ctx.endpoint.addr();
    let own_needs_lane = needs_webrtc_lane(&own_addr);
    let mut peers: Vec<EndpointAddr> = state
        .peer_endpoints
        .values()
        .filter(|addr| addr.id != ctx.rendezvous_id)
        .filter(|addr| {
            wants_session(
                own_needs_lane || needs_webrtc_lane(addr),
                state.unicast_pool.selected_is_ip(addr.id),
                state.direct.get(&addr.id) == Some(&crate::daemon::state::DirectState::Direct),
            )
        })
        .filter(|addr| {
            !state
                .webrtc
                .as_ref()
                .is_some_and(|handle| handle.has_session(&addr.id))
        })
        .cloned()
        .collect();
    // Sorted because the cap now bites here: in a mesh larger than the ceiling
    // this pass decides *which* peers get direct sessions, and `HashMap`
    // iteration order would make that differ run to run on one machine.
    peers.sort_unstable_by_key(|addr| addr.id);
    for addr in peers {
        negotiate_session(state, ctx, addr.id, addr);
    }
}

// Host-only: two real loopback endpoints and a tokio runtime. The logic under
// test is written once for both targets, but a browser cannot bind an endpoint.
//
// These are in-src rather than in `tests/` because `WebRtcSignalAcceptor` is
// `pub(crate)` — and it should stay that way. Before them this whole plane
// (the ALPN, the acceptor, the dialer, the retry tick) had no coverage
// anywhere in the workspace: `habilis-network-iroh-webrtc-transport`'s loopback test
// hands envelopes over in memory, and `agent-share`'s tests exercise the
// *share's* signal ALPN, not this one.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::Duration;

    use habilis_network_iroh_webrtc_transport::WebRtcTransport;
    use iroh::protocol::Router;
    use iroh::{RelayMode, SecretKey, endpoint::presets};

    use super::*;

    fn relay_addr() -> iroh::TransportAddr {
        iroh::TransportAddr::Relay("https://relay.example".parse().unwrap())
    }

    /// A browser: relay only, because wasm has no IP stack.
    fn browser_shaped(id: EndpointId) -> EndpointAddr {
        EndpointAddr::from_parts(id, [relay_addr()])
    }

    /// A native peer: always advertises at least one IP transport.
    fn native_shaped(id: EndpointId) -> EndpointAddr {
        EndpointAddr::from_parts(
            id,
            [
                iroh::TransportAddr::Ip("127.0.0.1:4433".parse().unwrap()),
                relay_addr(),
            ],
        )
    }

    /// The lane is for peers that cannot be reached any other way.
    ///
    /// A regression guard, not a unit test of a one-liner: without this gate the
    /// mesh negotiated a data channel with *every* peer, so two native peers ran
    /// gossip over a transport measured at 6× less throughput and 36× the
    /// latency of the QUIC path they already had.
    #[test]
    fn a_udp_pair_races_until_udp_is_selected() {
        assert!(
            wants_session(false, false, false),
            "a udp pair races the punch"
        );
        assert!(!wants_session(false, true, false), "udp won; no round");
        assert!(
            wants_session(true, false, false),
            "a lane pair always negotiates"
        );
        assert!(
            wants_session(true, true, true),
            "a lane pair's session is its only direct path"
        );
    }

    // A pair proven direct with no session proved its UDP path; a cold or
    // idled-out pool must not start the race again on every alive tick.
    #[test]
    fn a_proven_udp_pair_is_not_raced_again() {
        assert!(
            !wants_session(false, false, true),
            "proven direct, no pooled connection"
        );
    }

    #[test]
    fn only_a_peer_without_ip_needs_the_webrtc_lane() {
        let id = SecretKey::from_bytes(&[5u8; 32]).public();
        assert!(needs_webrtc_lane(&browser_shaped(id)));
        assert!(!needs_webrtc_lane(&native_shaped(id)));

        // Nothing advertised at all used to be treated as browser-shaped, on
        // the grounds that a native peer with its IP transports cleared looks
        // the same. It does not: that peer keeps its relay transport, which is
        // `browser_shaped` above. An address with no transports at all only
        // ever means "not known yet", and reading it as a browser is what let
        // the retry pass open a lane with every native peer. See
        // `an_address_with_no_transports_is_unknown_not_a_browser`.
        assert!(!needs_webrtc_lane(&EndpointAddr::new(id)));
    }

    /// A mixed pair needs the lane **whichever end is looking**.
    ///
    /// This is the case the first version of the gate got wrong. The lower
    /// `EndpointId` dials, so when a browser is the lower id it is the browser
    /// that evaluates the gate — and it sees the *native* peer's IP. Testing
    /// only the remote made it skip, while the native peer sat waiting to be
    /// dialled, and the pair silently never got a channel.
    /// **An address we know nothing about is not a browser.**
    ///
    /// The retry pass had no address to hand and built a bare one, which has no
    /// transports at all. That reads as "advertises no IP", so every native peer
    /// looked like a browser and the pass opened a data channel with all of
    /// them, spending the direct-peer slots that browsers actually need.
    #[test]
    fn an_address_with_no_transports_is_unknown_not_a_browser() {
        let id = SecretKey::from_bytes(&[7u8; 32]).public();
        assert!(
            !needs_webrtc_lane(&EndpointAddr::new(id)),
            "an address carrying no transports says nothing about the peer"
        );
        // The real relay-only shape still must.
        assert!(needs_webrtc_lane(&browser_shaped(id)));
    }

    #[test]
    fn a_mixed_pair_needs_the_lane_from_either_side() {
        let browser = browser_shaped(SecretKey::from_bytes(&[6u8; 32]).public());
        let native = native_shaped(SecretKey::from_bytes(&[7u8; 32]).public());

        let pair_needs_lane = |local: &EndpointAddr, remote: &EndpointAddr| {
            needs_webrtc_lane(remote) || needs_webrtc_lane(local)
        };

        assert!(
            pair_needs_lane(&browser, &native),
            "browser looking at a native peer must still offer"
        );
        assert!(
            pair_needs_lane(&native, &browser),
            "native looking at a browser must still offer"
        );
        assert!(
            pair_needs_lane(&browser, &browser),
            "two browsers have no other transport"
        );
        assert!(
            !pair_needs_lane(&native, &native),
            "two native peers must stay on iroh's own transports"
        );
    }

    /// **A node's own lane is a fact about the node, not about its address
    /// snapshot.** A browser whose relay link just dropped has an empty
    /// endpoint address for a moment; read through `needs_webrtc_lane` that
    /// is "unknown", and a pair with a native peer was left on iroh's own
    /// transports — which a browser does not have. Observed in Safari: every
    /// probe timed out and the peer stayed relay-only for good.
    #[test]
    fn a_node_without_ip_needs_the_lane_even_while_its_own_address_is_empty() {
        let native = native_shaped(SecretKey::from_bytes(&[7u8; 32]).public());
        // The address is not consulted at all for the local end; a node
        // without IP transports needs the lane, full stop.
        assert!(
            pair_needs_lane(&native, false),
            "a node with no IP transport must offer whatever its address says"
        );
        assert!(local_needs_webrtc_lane(false));
        assert!(
            !pair_needs_lane(&native, true),
            "two IP-capable peers stay on iroh's own transports"
        );
    }

    /// Short enough that a test finishes, long enough that a loopback dial and
    /// a QUIC handshake comfortably fit inside it.
    fn quick() -> SignalDeadlines {
        SignalDeadlines {
            exchange: Duration::from_millis(400),
            round: Duration::from_millis(900),
        }
    }

    /// Offline: loopback only, no relay, no address lookup.
    async fn endpoint() -> (Endpoint, WebRtcHandle) {
        let key = SecretKey::generate();
        let handle = WebRtcHandle::new(WebRtcTransport::new(key.public()));
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .add_custom_transport(handle.transport())
            .bind()
            .await
            .expect("bind loopback endpoint");
        (endpoint, handle)
    }

    fn serve(endpoint: &Endpoint, handle: &WebRtcHandle, admission: &SignalAdmission) -> Router {
        Router::builder(endpoint.clone())
            .accept(
                MESH_WEBRTC_SIGNAL_ALPN,
                WebRtcSignalAcceptor::new(
                    handle.clone(),
                    endpoint.clone(),
                    endpoint.id(),
                    admission.clone(),
                    // Host candidates only: these tests must not touch STUN.
                    IceProfile { host_only: true },
                )
                .with_deadlines(quick()),
            )
            .spawn()
    }

    /// Wait for `check` to hold, or give up. Polling beats a fixed sleep: the
    /// release happens on a spawned task's drop, which has no completion signal
    /// to await.
    async fn until(mut check: impl FnMut() -> bool) -> bool {
        for _ in 0..100 {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        check()
    }

    /// A peer that connects and never opens a stream must not pin the answer
    /// task, and must not pin its admission slot either.
    ///
    /// Before the deadline and the guard, `answer_one` blocked on `accept_bi`
    /// forever — the peer's QUIC keep-alives meant the connection never idled
    /// out — and the task was detached from the Router's `JoinSet`, so nothing
    /// reaped it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connection_that_never_opens_a_stream_is_released() {
        let (server, server_hub) = endpoint().await;
        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let router = serve(&server, &server_hub, &admission);

        let (client, _client_hub) = endpoint().await;
        let conn = client
            .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
            .await
            .expect("dial the signal ALPN");
        assert!(
            until(|| admission.in_flight() == 1).await,
            "the offer should have been admitted"
        );

        // Never open a bi-stream; just hold the connection open.
        assert!(
            until(|| admission.in_flight() == 0).await,
            "a stalled offer must release its slot on the exchange deadline"
        );
        assert_eq!(server_hub.session_count(), 0);

        conn.close(0u32.into(), b"done");
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// One peer, many connections, one task.
    ///
    /// Admission is keyed by the TLS-proven remote id and happens *before* the
    /// spawn, so a peer cannot multiply our task count by reconnecting. It used
    /// to be able to: every connection spawned its own detached task holding
    /// its own `Connection`, with nothing bounding either.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn many_connections_from_one_peer_yield_one_task() {
        let (server, server_hub) = endpoint().await;
        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let router = serve(&server, &server_hub, &admission);

        let (client, _client_hub) = endpoint().await;
        let mut conns = Vec::new();
        for _ in 0..5 {
            conns.push(
                client
                    .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
                    .await
                    .expect("dial the signal ALPN"),
            );
        }

        // Give every accept a chance to run, then assert the ceiling held
        // throughout rather than only at the end.
        for _ in 0..12 {
            assert!(
                admission.in_flight() <= 1,
                "one peer must never hold more than one slot"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        for conn in conns {
            conn.close(0u32.into(), b"done");
        }
        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// At the ceiling, the answerer refuses before doing any JSEP work, and
    /// says *why* with a distinct close code so the dialer can back off rather
    /// than re-offer every tick.
    ///
    /// A cap of zero is the cheap way to stand at the ceiling; the arithmetic
    /// (`sessions + in-flight >= cap`) is the same at sixteen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_offer_at_the_cap_is_refused_with_the_cap_code() {
        let (server, server_hub) = endpoint().await;
        let admission = SignalAdmission::new(0);
        let router = serve(&server, &server_hub, &admission);

        let (client, _client_hub) = endpoint().await;
        let conn = client
            .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
            .await
            .expect("dial the signal ALPN");

        let reason = tokio::time::timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("the refusal must be prompt — no gathering should have happened");
        match reason {
            iroh::endpoint::ConnectionError::ApplicationClosed(close) => {
                assert_eq!(
                    close.error_code.into_inner(),
                    u64::from(CAP_REFUSED),
                    "expected the at-cap close code"
                );
            }
            other @ (iroh::endpoint::ConnectionError::VersionMismatch
            | iroh::endpoint::ConnectionError::TransportError(_)
            | iroh::endpoint::ConnectionError::ConnectionClosed(_)
            | iroh::endpoint::ConnectionError::Reset
            | iroh::endpoint::ConnectionError::TimedOut
            | iroh::endpoint::ConnectionError::LocallyClosed
            | iroh::endpoint::ConnectionError::CidsExhausted) => {
                panic!("expected an application close, got {other:?}")
            }
        }
        assert_eq!(server_hub.session_count(), 0);

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// **The dialer must recognise a prompt refusal, not just a timed-out one.**
    ///
    /// The answerer refuses at its cap by closing the connection straight away,
    /// so the offer round fails on the *read*, not on the exchange deadline.
    /// Only the timeout branch consulted the close code, so the refusal came
    /// back as a plain read error and the dialer re-ran a full gathering round
    /// against the same peer on every retry tick, forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_prompt_cap_refusal_is_recognised_by_the_dialer() {
        let (server, server_hub) = endpoint().await;
        let admission = SignalAdmission::new(0);
        let router = serve(&server, &server_hub, &admission);

        let (client, client_hub) = endpoint().await;
        let error = dial_signal_with(
            &client,
            server.addr(),
            &client_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await
        .expect_err("a server at its cap must refuse the offer");

        assert!(
            is_cap_refusal(&error),
            "the dialer must read this as an at-cap refusal, got: {error:#}"
        );

        router.shutdown().await.expect("shutdown");
        client.close().await;
        server.close().await;
    }

    /// A peer the answerer evicted a short while ago is refused with its own
    /// code, and the dialer reads it as a request to back off, like an at-cap
    /// refusal. Without that, the evicted peer would offer again on its next
    /// retry tick and take the slot back from the newcomer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_offer_from_an_evicted_peer_is_refused_with_the_evicted_code() {
        let (server, server_hub) = endpoint().await;
        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let router = serve(&server, &server_hub, &admission);

        let (client, client_hub) = endpoint().await;
        admission.note_evicted(client.id());

        let conn = client
            .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
            .await
            .expect("dial the signal ALPN");
        let reason = tokio::time::timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("the refusal must be prompt");
        assert!(
            matches!(
                reason,
                iroh::endpoint::ConnectionError::ApplicationClosed(ref close)
                    if close.error_code.into_inner() == u64::from(EVICTED)
            ),
            "expected the evicted close code, got {reason:?}"
        );

        let error = dial_signal_with(
            &client,
            server.addr(),
            &client_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await
        .expect_err("an evicted peer must be refused");
        assert!(
            is_cap_refusal(&error),
            "the dialer must back off from an evicted refusal, got: {error:#}"
        );

        router.shutdown().await.expect("shutdown");
        client.close().await;
        server.close().await;
    }

    /// `Router::shutdown` must reach the spawned answer tasks.
    ///
    /// They are not in the Router's own `JoinSet` — spawning is deliberate, so
    /// a multi-second negotiation does not serialize inbound offers, and so the
    /// browser's `!Send` JSEP future has somewhere to live. `ProtocolHandler`'s
    /// `shutdown` hook is what replaces that reachability.
    /// Like [`endpoint`], but with the address-lookup store intact, so
    /// `add_peer_addr` has somewhere to register and a bare-id dial has
    /// something to resolve through.
    async fn endpoint_with_lookup() -> (Endpoint, WebRtcHandle) {
        let key = SecretKey::generate();
        let handle = WebRtcHandle::new(WebRtcTransport::new(key.public()));
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled)
            .add_custom_transport(handle.transport())
            .bind()
            .await
            .expect("bind loopback endpoint");
        (endpoint, handle)
    }

    /// **The load-bearing assumption of the whole `WebRTC` lane**: after a
    /// session is attached and [`register_session_addr`] has run, a dial by
    /// *bare id* — which is all iroh-gossip's actor ever dials with — must
    /// resolve to the custom-transport path and connect over the data
    /// channel. No relay and no IP address exist in this test, so a success
    /// here is that resolution working and nothing else.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bare_id_dial_resolves_to_the_attached_session() {
        let (server, server_hub) = endpoint_with_lookup().await;
        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let router = serve(&server, &server_hub, &admission);

        let (client, client_hub) = endpoint_with_lookup().await;
        dial_signal_with(
            &client,
            server.addr(),
            &client_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await
        .expect("the signal round must attach a session");
        assert!(client_hub.has_session(&server.id()));

        register_session_addr(&client, server.id());

        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            client.connect(EndpointAddr::new(server.id()), MESH_WEBRTC_SIGNAL_ALPN),
        )
        .await
        .expect("a bare-id dial must not hang")
        .expect("a bare-id dial must resolve through the registered custom address");
        let direct = super::super::path::selected_is_direct(&conn);
        conn.close(0u32.into(), b"done");
        assert!(direct, "the connection's selected path must be the session");

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// The **reverse** of [`a_bare_id_dial_resolves_to_the_attached_session`],
    /// and the direction the native/web matrix caught missing: the *answerer*
    /// dialing the *offerer* by bare id. The production acceptor registers the
    /// offerer's custom address on attach, and a data channel is symmetric —
    /// so this dial must ride the session exactly like the forward one. In the
    /// matrix, every conn dialed in this direction sat on the relay until the
    /// accept gate refused it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bare_id_dial_rides_the_session_from_the_answerer_too() {
        let (server, server_hub) = endpoint_with_lookup().await;
        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let router = serve(&server, &server_hub, &admission);

        let (client, client_hub) = endpoint_with_lookup().await;
        let client_admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let client_router = serve(&client, &client_hub, &client_admission);
        dial_signal_with(
            &client,
            server.addr(),
            &client_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await
        .expect("the signal round must attach a session");
        assert!(
            until(|| server_hub.has_session(&client.id())).await,
            "the answerer's hub must hold the session"
        );
        // `register_session_addr` runs in the acceptor task right after the
        // attach the poll above observed; give it a beat to land.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            server.connect(EndpointAddr::new(client.id()), MESH_WEBRTC_SIGNAL_ALPN),
        )
        .await
        .expect("an answerer's bare-id dial must not hang")
        .expect("an answerer's bare-id dial must resolve through the registered custom address");
        let direct = super::super::path::selected_is_direct(&conn);
        conn.close(0u32.into(), b"done");
        assert!(direct, "the connection's selected path must be the session");

        router.shutdown().await.expect("shutdown");
        client_router.shutdown().await.expect("shutdown");
        server.close().await;
        client.close().await;
    }

    /// The whole lookup-only browser story in one offline test: with a
    /// session attached and its address registered, an **iroh-gossip graft
    /// by bare id** must connect over the session and pass the lookup-only
    /// accept gate. This is the layer above [`a_bare_id_dial_resolves_to_the_attached_session`]:
    /// the gossip actor does its own dialing, and it is the actor's dial —
    /// not ours — that the rendezvous link depends on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gossip_graft_by_bare_id_rides_the_attached_session() {
        use futures_util::StreamExt as _;
        use iroh_gossip::net::{GOSSIP_ALPN, Gossip};

        let (server, server_hub) = endpoint_with_lookup().await;
        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let server_gossip = Gossip::builder().spawn(server.clone());
        // One Router for both ALPNs: `Router::spawn` overrides the endpoint's
        // ALPN list, so a second Router silently unregisters the first's.
        let router = Router::builder(server.clone())
            .accept(
                MESH_WEBRTC_SIGNAL_ALPN,
                WebRtcSignalAcceptor::new(
                    server_hub.clone(),
                    server.clone(),
                    server.id(),
                    admission.clone(),
                    IceProfile { host_only: true },
                )
                .with_deadlines(quick()),
            )
            .accept(
                GOSSIP_ALPN,
                super::super::DirectOnlyGossip::new(server_gossip.clone(), false, None),
            )
            .spawn();

        let (client, client_hub) = endpoint_with_lookup().await;
        let client_gossip = Gossip::builder().spawn(client.clone());

        dial_signal_with(
            &client,
            server.addr(),
            &client_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await
        .expect("the signal round must attach a session");
        register_session_addr(&client, server.id());

        let topic = iroh_gossip::proto::TopicId::from_bytes([9u8; 32]);
        let mut server_topic = server_gossip
            .subscribe(topic, vec![])
            .await
            .expect("server subscribes");
        let mut client_topic = client_gossip
            .subscribe(topic, vec![server.id()])
            .await
            .expect("client subscribes and grafts by bare id");

        let linked = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                tokio::select! {
                    event = client_topic.next() => {
                        if matches!(
                            event,
                            Some(Ok(iroh_gossip::api::Event::NeighborUp(id))) if id == server.id()
                        ) {
                            return;
                        }
                    }
                    event = server_topic.next() => {
                        let _ = event;
                    }
                }
            }
        })
        .await;
        assert!(
            linked.is_ok(),
            "the graft dial must ride the attached session through the lookup-only gate"
        );

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// The failing browser topology, natively: both ends also hold a relay
    /// path. The graft's connection then opens over the relay first, and the
    /// lookup-only gate passes only if selection *migrates* to the attached
    /// session within the hold. This is the exact cell the matrix kept
    /// failing; everything below the relay's presence is covered by
    /// [`a_gossip_graft_by_bare_id_rides_the_attached_session`].
    #[cfg(feature = "iroh-test-utils")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gossip_graft_prefers_the_session_over_the_relay() {
        use futures_util::StreamExt as _;
        use iroh_gossip::net::{GOSSIP_ALPN, Gossip};

        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();

        let (relay_url, _relay_server) = crate::lookup::test_relay::spawn_plain()
            .await
            .expect("local relay");
        let with_relay = |key: SecretKey, handle: &WebRtcHandle, browser_shaped: bool| {
            let relay_url = relay_url.clone();
            let transport = handle.transport();
            let selector = handle.path_selector();
            async move {
                let builder = Endpoint::builder(presets::Minimal)
                    .secret_key(key)
                    .relay_mode(RelayMode::custom([relay_url]))
                    .add_custom_transport(transport)
                    .path_selector(selector);
                // A browser has no IP stack: without this, localhost punches
                // a UDP path inside the held connection and the gate passes
                // on a path a tab could never have.
                let builder = if browser_shaped {
                    builder.clear_ip_transports()
                } else {
                    builder
                };
                builder.bind().await.expect("bind endpoint with relay")
            }
        };
        let server_key = SecretKey::generate();
        let server_hub = WebRtcHandle::new(WebRtcTransport::new(server_key.public()));
        let server = with_relay(server_key, &server_hub, false).await;
        let client_key = SecretKey::generate();
        let client_hub = WebRtcHandle::new(WebRtcTransport::new(client_key.public()));
        let client = with_relay(client_key, &client_hub, true).await;

        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let server_gossip = Gossip::builder().spawn(server.clone());
        let router = Router::builder(server.clone())
            .accept(
                MESH_WEBRTC_SIGNAL_ALPN,
                WebRtcSignalAcceptor::new(
                    server_hub.clone(),
                    server.clone(),
                    server.id(),
                    admission.clone(),
                    IceProfile { host_only: true },
                ),
            )
            .accept(
                GOSSIP_ALPN,
                super::super::DirectOnlyGossip::new(server_gossip.clone(), false, None),
            )
            .spawn();

        let client_gossip = Gossip::builder().spawn(client.clone());
        // The relay-homed address, as `register_rendezvous` hands a joiner.
        let relay_addr = EndpointAddr::new(server.id()).with_relay_url(relay_url.clone());
        dial_signal_with(
            &client,
            relay_addr,
            &client_hub,
            SignalDeadlines::DEFAULT,
            IceProfile { host_only: true },
        )
        .await
        .expect("the signal round must attach a session over the relay");
        register_session_addr(&client, server.id());

        let topic = iroh_gossip::proto::TopicId::from_bytes([11u8; 32]);
        let mut server_topic = server_gossip
            .subscribe(topic, vec![])
            .await
            .expect("server subscribes");
        let mut client_topic = client_gossip
            .subscribe(topic, vec![server.id()])
            .await
            .expect("client subscribes and grafts by bare id");

        let linked = tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                tokio::select! {
                    event = client_topic.next() => {
                        if matches!(
                            event,
                            Some(Ok(iroh_gossip::api::Event::NeighborUp(id))) if id == server.id()
                        ) {
                            return;
                        }
                    }
                    event = server_topic.next() => {
                        let _ = event;
                    }
                }
            }
        })
        .await;
        assert!(
            linked.is_ok(),
            "with a session attached, the graft must not stay pinned to the relay"
        );

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// A relayed connection still open when the session attaches, which is
    /// what the beacon's accept gate does to a graft for up to its deadline:
    /// iroh then holds a selected relay path to the remote and consults no
    /// address lookup for it, so registering the session address in a lookup
    /// alone left every later bare-id dial on the relay. Observed as a
    /// browser-first mesh cell that never linked.
    #[cfg(feature = "iroh-test-utils")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bare_id_dial_rides_the_session_past_a_held_relay_link() {
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler};

        /// Keeps every accepted connection open until the dialer closes it.
        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                conn.closed().await;
                Ok(())
            }
        }
        const HOLD_ALPN: &[u8] = b"habilis-network/test-hold";

        let (relay_url, _relay_server) = crate::lookup::test_relay::spawn_plain()
            .await
            .expect("local relay");
        // No IP on either side, as between a tab and a tab-held beacon: the
        // relay and the session are the only paths there are.
        let relay_only = |key: SecretKey, handle: &WebRtcHandle| {
            let builder = Endpoint::builder(presets::Minimal)
                .secret_key(key)
                .relay_mode(RelayMode::custom([relay_url.clone()]))
                .add_custom_transport(handle.transport())
                .path_selector(handle.path_selector())
                .clear_ip_transports();
            async move { builder.bind().await.expect("bind relay-only endpoint") }
        };
        let server_key = SecretKey::generate();
        let server_hub = WebRtcHandle::new(WebRtcTransport::new(server_key.public()));
        let server = relay_only(server_key, &server_hub).await;
        let client_key = SecretKey::generate();
        let client_hub = WebRtcHandle::new(WebRtcTransport::new(client_key.public()));
        let client = relay_only(client_key, &client_hub).await;

        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let router = Router::builder(server.clone())
            .accept(
                MESH_WEBRTC_SIGNAL_ALPN,
                WebRtcSignalAcceptor::new(
                    server_hub.clone(),
                    server.clone(),
                    server.id(),
                    admission.clone(),
                    IceProfile { host_only: true },
                ),
            )
            .accept(HOLD_ALPN, Hold)
            .spawn();

        let relay_addr = EndpointAddr::new(server.id()).with_relay_url(relay_url.clone());
        let held = client
            .connect(relay_addr.clone(), HOLD_ALPN)
            .await
            .expect("a relayed connection before any session");
        dial_signal_with(
            &client,
            relay_addr,
            &client_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await
        .expect("the signal round must attach a session");

        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            client.connect(EndpointAddr::new(server.id()), HOLD_ALPN),
        )
        .await
        .expect("a bare-id dial must not hang")
        .expect("a bare-id dial must connect");
        let direct = super::super::path::wait_direct(&conn, Duration::from_secs(10)).await;
        conn.close(0u32.into(), b"done");
        held.close(0u32.into(), b"done");
        assert!(
            direct,
            "a dial after the attach must reach the session, not only the relay"
        );

        router.shutdown().await.expect("shutdown");
        client.close().await;
        server.close().await;
    }

    /// The real join order: the graft is attempted *before* any session
    /// exists — the gate holds the relayed connection for its deadline and
    /// closes it — and only then does the session attach. The re-graft after
    /// the refusal must still link; if a refused connection poisons later
    /// dials to the same peer, this is the test that says so.
    #[cfg(feature = "iroh-test-utils")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_graft_recovers_after_a_refused_relay_attempt() {
        use futures_util::StreamExt as _;
        use iroh_gossip::net::{GOSSIP_ALPN, Gossip};

        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();

        let (relay_url, _relay_server) = crate::lookup::test_relay::spawn_plain()
            .await
            .expect("local relay");
        let with_relay = |key: SecretKey, handle: &WebRtcHandle, browser_shaped: bool| {
            let relay_url = relay_url.clone();
            let transport = handle.transport();
            let selector = handle.path_selector();
            async move {
                let builder = Endpoint::builder(presets::Minimal)
                    .secret_key(key)
                    .relay_mode(RelayMode::custom([relay_url]))
                    .add_custom_transport(transport)
                    .path_selector(selector);
                // A browser has no IP stack: without this, localhost punches
                // a UDP path inside the held connection and the gate passes
                // on a path a tab could never have.
                let builder = if browser_shaped {
                    builder.clear_ip_transports()
                } else {
                    builder
                };
                builder.bind().await.expect("bind endpoint with relay")
            }
        };
        let server_key = SecretKey::generate();
        let server_hub = WebRtcHandle::new(WebRtcTransport::new(server_key.public()));
        let server = with_relay(server_key, &server_hub, false).await;
        let client_key = SecretKey::generate();
        let client_hub = WebRtcHandle::new(WebRtcTransport::new(client_key.public()));
        let client = with_relay(client_key, &client_hub, true).await;

        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let server_gossip = Gossip::builder().spawn(server.clone());
        let router = Router::builder(server.clone())
            .accept(
                MESH_WEBRTC_SIGNAL_ALPN,
                WebRtcSignalAcceptor::new(
                    server_hub.clone(),
                    server.clone(),
                    server.id(),
                    admission.clone(),
                    IceProfile { host_only: true },
                ),
            )
            .accept(
                GOSSIP_ALPN,
                super::super::DirectOnlyGossip::new(server_gossip.clone(), false, None),
            )
            .spawn();

        let client_gossip = Gossip::builder().spawn(client.clone());
        // What register_rendezvous does for a joiner: the relay-homed
        // address, registered before the first graft dial.
        crate::lookup::add_peer_addr(
            &client,
            EndpointAddr::new(server.id()).with_relay_url(relay_url.clone()),
        )
        .expect("register the relay-homed address");
        let topic = iroh_gossip::proto::TopicId::from_bytes([13u8; 32]);
        let mut server_topic = server_gossip
            .subscribe(topic, vec![])
            .await
            .expect("server subscribes");
        // The graft attempt with nothing but the relay: held, then refused.
        let (client_sender, mut client_rx) = client_gossip
            .subscribe(topic, vec![server.id()])
            .await
            .expect("client subscribes")
            .split();

        // Outlast the gate's hold (15 s) so the refusal has happened.
        tokio::time::sleep(Duration::from_secs(17)).await;

        // Now the session, as the heal tick would drive it.
        let relay_addr = EndpointAddr::new(server.id()).with_relay_url(relay_url.clone());
        dial_signal_with(
            &client,
            relay_addr,
            &client_hub,
            SignalDeadlines::DEFAULT,
            IceProfile { host_only: true },
        )
        .await
        .expect("the signal round must attach a session over the relay");
        register_session_addr(&client, server.id());

        let linked = tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                client_sender
                    .join_peers(vec![server.id()])
                    .await
                    .expect("re-graft");
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                loop {
                    tokio::select! {
                        event = client_rx.next() => {
                            if matches!(
                                event,
                                Some(Ok(iroh_gossip::api::Event::NeighborUp(id))) if id == server.id()
                            ) {
                                return;
                            }
                        }
                        event = server_topic.next() => {
                            let _ = event;
                        }
                        () = tokio::time::sleep_until(deadline) => {
                            break;
                        }
                    }
                }
            }
        })
        .await;
        assert!(
            linked.is_ok(),
            "a refused relay-only graft must not poison the re-graft over the session"
        );

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn router_shutdown_cancels_rounds_in_flight() {
        let (server, server_hub) = endpoint().await;
        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let router = serve(&server, &server_hub, &admission);

        let (client, _client_hub) = endpoint().await;
        let conn = client
            .connect(server.addr(), MESH_WEBRTC_SIGNAL_ALPN)
            .await
            .expect("dial the signal ALPN");
        assert!(
            until(|| admission.in_flight() == 1).await,
            "the offer should have been admitted"
        );

        // Well inside the round deadline, so a pass here is the abort working
        // and not the timeout firing.
        tokio::time::timeout(Duration::from_millis(500), router.shutdown())
            .await
            .expect("shutdown must not wait out the round deadline")
            .expect("shutdown");
        assert!(
            until(|| admission.in_flight() == 0).await,
            "an aborted round must give its slot back"
        );

        conn.close(0u32.into(), b"done");
        client.close().await;
    }

    /// The dialer's half: a peer that accepts the connection and reads the
    /// offer but never answers must not hold the round open forever.
    ///
    /// This is the shape that pinned a pair to the relay permanently. Nothing
    /// in `dial_signal` was bounded — `JSEP_DEADLINE` wrapped only `complete()`,
    /// which runs after the answer arrives — so the in-flight marker was never
    /// cleared and every later retry skipped that peer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dial_gives_up_when_the_answer_never_comes() {
        /// Reads the offer and then says nothing, keeping the connection alive.
        #[derive(Debug, Clone)]
        struct BlackHole;

        impl ProtocolHandler for BlackHole {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                let (_send, mut recv) = conn.accept_bi().await?;
                let _ = recv.read_to_end(MAX_ENVELOPE_BYTES).await;
                // Hold the connection open, answering nothing.
                conn.closed().await;
                Ok(())
            }
        }

        let (server, _server_hub) = endpoint().await;
        let router = Router::builder(server.clone())
            .accept(MESH_WEBRTC_SIGNAL_ALPN, BlackHole)
            .spawn();

        let (client, client_hub) = endpoint().await;
        let started = std::time::Instant::now();
        let outcome = dial_signal_with(
            &client,
            server.addr(),
            &client_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await;

        assert!(outcome.is_err(), "a silent peer must not succeed");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the dial must give up on its own deadline, not hang: took {:?}",
            started.elapsed()
        );
        assert_eq!(client_hub.session_count(), 0);

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// Off the heal tick, only a node that already offers offers again: a
    /// lane-needing node on every call, as before, and an IP-capable node only
    /// once the heal tick armed its fallback.
    #[test]
    fn only_a_node_that_already_offers_offers_off_the_heal_tick() {
        let mut state = crate::testing::fresh_state();
        state.local_udp_transport = false;
        assert!(offers_off_tick(&state), "a lane-needing node");
        state.local_udp_transport = true;
        assert!(
            !offers_off_tick(&state),
            "an IP-capable node before its fallback"
        );
        state.rendezvous_offer_fallback = true;
        assert!(
            offers_off_tick(&state),
            "an IP-capable node after its fallback"
        );
    }

    /// An IP-capable node that fell back to offering the rendezvous a
    /// session — the beacon is a tab, with no UDP to punch to — grafts on the
    /// attach, never on a timer. A timer graft dials before the session
    /// exists, so its connection has only the relay path; the tab's accept
    /// gate holds it and refuses it after `PROBE_DEADLINE`, and the attach
    /// that follows does not replace it. Observed every 30 s for a whole
    /// browser-first cell.
    #[test]
    fn an_offer_fallback_holds_the_timer_graft() {
        let mut state = crate::testing::fresh_state();
        assert!(
            rendezvous_graftable(&state),
            "an IP-capable node grafts on its timer until it falls back"
        );
        state.rendezvous_offer_fallback = true;
        assert!(!rendezvous_graftable(&state));
    }
}
