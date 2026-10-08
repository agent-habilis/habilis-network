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
    /// We are at our direct-peer ceiling.
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
    // 6 was `EVICTED` on this branch (removed in 597dedf), and builds of the PR
    // sent it. Do not reuse it while those builds can still be in a mesh.
    // 7 was `RENDEZVOUS_RELEASED`, sent by builds of the PR that closed the link
    // to the rendezvous themselves; the same applies.
    /// A unicast connection nothing sent on for the idle timeout: closed by the
    /// pool on the dial side, by the acceptor on the other.
    pub(crate) const IDLE: u32 = 8;
    /// A signal from an endpoint that is not a neighbor of the underlay. Its only sender is
    /// `underlay_webrtc`, which exists with the `multihop` feature.
    #[cfg(any(feature = "multihop", test))]
    pub(crate) const NOT_A_NEIGHBOR: u32 = 9;
    /// A direct connection closed because the node is at its ceiling of direct
    /// connections and this one was the least recently used. The dialer backs off
    /// before it dials this peer on its own again: a send still dials at once.
    pub(crate) const EVICTED: u32 = 11;
    /// A gossip connection whose selected path is the gossip rung: gossip would carry the
    /// frames that gossip needs to carry itself.
    pub(crate) const GOSSIP_ON_GOSSIP_PATH: u32 = 10;
    // The next free number is 12.

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
                IDLE,
                NOT_A_NEIGHBOR,
                GOSSIP_ON_GOSSIP_PATH,
                EVICTED,
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

/// The peer refused us: it is at its direct-peer ceiling. We back off for a
/// while.
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

/// Whether a failed offer round was the peer refusing us at its ceiling.
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

/// Whether the peer closed `conn` to tell us to back off: it refused at its cap (the code of
/// older peers), or it evicted us lately.
fn refused_at_cap(conn: &Connection) -> bool {
    matches!(
        conn.close_reason(),
        Some(iroh::endpoint::ConnectionError::ApplicationClosed(ref close))
            if [u64::from(CAP_REFUSED), u64::from(EVICTED)].contains(&close.error_code.into_inner())
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
        // Glare: when the lower id offers while our own offer to it runs, ours is given up and the
        // offer of the lower id is answered. The lower id always wins; it refuses a crossed offer
        // of the higher id, as the lower id has always done.
        if remote < self.local && self.admission.preempt_offer(remote) {
            tracing::debug!(target: LOG_TARGET, %remote, "gave up our offer for the offer of the lower id");
        }
        let guard = match self.admission.try_admit(remote, &self.handle) {
            Ok(guard) => guard,
            Err(reason) => {
                let (code, why): (u32, &[u8]) = match reason {
                    Refusal::ShuttingDown => (SIGNAL_ABORTED, b"shutting down"),
                    Refusal::Evicted => (EVICTED, b"evicted lately"),
                    Refusal::InFlight | Refusal::HaveSession | Refusal::Cooling => {
                        (SIGNAL_FAILED, b"already negotiating")
                    }
                };
                conn.close(code.into(), why);
                tracing::debug!(target: LOG_TARGET, %remote, ?reason, "refused a signal offer");
                return Ok(());
            }
        };

        let epoch = guard.epoch();
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
                    admission.report_answered(remote);
                    register_session_addr(&endpoint, remote);
                    conn.close(0u32.into(), b"jsep done");
                    // A connection that we dialed before the attach moves onto the
                    // session only after a path event of our own endpoint, and the
                    // offerer's nudge gives us none: iroh opens a new path only
                    // from the client side of a connection.
                    let nudging = endpoint.clone();
                    n0_future::task::spawn(async move { nudge_session(&nudging, remote).await });
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
        self.admission.track(remote, epoch, task.abort_handle());
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

/// The default of C, the ceiling of direct connections one node holds (64): the `WebRTC`
/// sessions and the unicast connections together. A node sets its own with
/// `SetupParams::max_direct`; `0` takes this value.
///
/// It is deliberately not the same knob as HyParView's `active_view_capacity` (G): that one
/// sizes the gossip overlay and is fixed when the mesh is built. Each direct connection costs
/// memory and, in a browser, up to a full ICE gathering budget — so the ceiling is real, not
/// notional. A newcomer past C evicts the least valuable peer, see
/// [`super::ceiling`]; no offer is refused for it.
///
/// Public so the CLI and the browser can render a denominator. A node with its
/// own ceiling reports it with [`super::admission::SignalAdmission::cap`], because
/// this constant is only the default.
pub const MAX_DIRECT_PEERS: usize = 64;

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
///
/// `kind` is the selected path of the pair, if known. A pair on multihop is proven
/// off the relay, but it has no lane of its own: a session ranks above multihop,
/// so `proven` does not count while the pair rides it.
pub(crate) fn wants_session(
    pair_needs_lane: bool,
    kind: Option<super::probe::PathKind>,
    proven: bool,
) -> bool {
    let udp_selected = kind == Some(super::probe::PathKind::Ip);
    let proven = proven && !proof_is_stale(kind, proven);
    pair_needs_lane || !(udp_selected || proven)
}

/// Detach the session of `peer` when UDP is selected again for a pair that does not need the
/// lane. Only the lower id has a path watcher, and only on a pooled connection that a send
/// opened (decision D4), so a pair that only gossips has no one to report UDP's return. The
/// reading of the admission table is the sign, and it must hold for every live connection of
/// the pair: a connection that still rides the session keeps it. Returns whether a session was
/// detached.
fn detach_session_under_udp(
    state: &mut crate::daemon::state::EventLoopState,
    peer: EndpointId,
    needs_lane: bool,
) -> bool {
    let Some(handle) = state.webrtc.clone() else {
        return false;
    };
    if needs_lane
        || state.pair_path_kind(peer) != Some(super::probe::PathKind::Ip)
        || state.webrtc_admission.any_connection_not_ip(peer)
        || !handle.detach(&peer)
    {
        return false;
    }
    tracing::info!(
        target: LOG_TARGET,
        %peer,
        detector = "admission",
        "udp selected again; webrtc session detached"
    );
    super::probe::mark_proven(state, peer);
    true
}

/// [`detach_session_under_udp`] for every session holder, on the fast ticker: the alive tick
/// (30 s) would leave a session under a selected UDP path for that long.
pub(crate) async fn detach_sessions_under_udp(
    state: &mut crate::daemon::state::EventLoopState,
    ctx: &crate::daemon::ctx::HandlerCtx<'_>,
) {
    let Some(handle) = state.webrtc.clone() else {
        return;
    };
    if handle.session_count() == 0 {
        return;
    }
    let holders: Vec<(EndpointId, bool)> = state
        .peer_endpoints
        .values()
        .filter(|addr| addr.id != ctx.rendezvous_id && handle.has_session(&addr.id))
        .map(|addr| (addr.id, pair_needs_lane(addr, state.local_udp_transport)))
        .collect();
    for (peer, needs_lane) in holders {
        if detach_session_under_udp(state, peer, needs_lane)
            && state.meshed
            && !state.pending_outbound.is_empty()
        {
            crate::gossip::flush_pending(state, ctx, "direct path back").await;
        }
    }
}

/// Whether the proof of a direct path is stale: the pair was `proven` direct, and its selected
/// path now reads as the relay, as multihop or as gossip, all below a session. Only a path
/// watcher takes a proof back, and only the lower id has one, so the reading of the admission
/// table is the only sign of the loss that a pair can have.
fn proof_is_stale(kind: Option<super::probe::PathKind>, proven: bool) -> bool {
    proven
        && matches!(
            kind,
            Some(
                super::probe::PathKind::Multihop
                    | super::probe::PathKind::Gossip
                    | super::probe::PathKind::Relay
            )
        )
}

/// Whether this node leaves the offer of a session to its peer. The higher id waits to be
/// dialled, so that one offer crosses per pair, unless a frame is held for the peer or the
/// proof of a direct path is stale.
///
/// The proof is stale when the pair was `proven` direct and the selected path reads as the
/// relay. Only the lower id has a path watcher (`ensure_watchers`), so a higher id that sends
/// is the only one that can see the direct path go, and nobody else would offer. A crossing
/// is settled in favour of the lower id (see `WebRtcSignalAcceptor::accept`).
pub(crate) fn waits_for_the_offer(
    local_is_higher: bool,
    frame_held: bool,
    kind: Option<super::probe::PathKind>,
    proven: bool,
) -> bool {
    local_is_higher && !frame_held && !proof_is_stale(kind, proven)
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
    // A cold pair stays where it is until the next send.
    if held_back(state, &addr) {
        tracing::debug!(target: LOG_TARGET, %peer, "no send yet; leaving this pair alone");
        return;
    }
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
    let kind = state.pair_path_kind(peer);
    let proven = state.direct.get(&peer) == Some(&crate::daemon::state::DirectState::Direct);
    if !wants_session(needs_lane, kind, proven) {
        if kind == Some(super::probe::PathKind::Ip) {
            if detach_session_under_udp(state, peer, needs_lane) {
                return;
            }
            tracing::debug!(
                target: LOG_TARGET,
                %peer,
                "udp already selected; leaving this pair on iroh's own transports"
            );
        } else {
            tracing::debug!(
                target: LOG_TARGET,
                %peer,
                ?kind,
                "pair proven direct; leaving it on iroh's own transports"
            );
        }
        return;
    }
    // The higher id waits to be dialled, so one offer crosses per pair. Unless a frame is held for
    // the peer: that frame cannot wait for an offer that the lower id has no reason to make. If
    // both offer at once, the lower id wins (see `WebRtcSignalAcceptor::accept`).
    let local = ctx.endpoint.id();
    let frame_held = state.lane_session_wanted(peer, crate::util::clock::Instant::now());
    if waits_for_the_offer(local > peer, frame_held, kind, proven) {
        return;
    }
    // A pair that reads as the relay is not direct, whatever the proof says: take the proof back,
    // so that a frame is parked for the session and not refused on the relay. Not while a session
    // is attached: a session carries the pair whatever one connection reads (a connection opened
    // before the attach reads the relay until a path event moves it), so the connection that reads
    // as relay is nudged onto the session, and the proof stands.
    let reads_as_relay =
        proof_is_stale(kind, proven) && kind == Some(super::probe::PathKind::Relay);
    let has_session = handle.has_session(&peer);
    if reads_as_relay && has_session {
        let endpoint = ctx.endpoint.clone();
        n0_future::task::spawn(async move { nudge_session(&endpoint, peer).await });
    }
    let demoted = reads_as_relay && !has_session;
    if demoted {
        state
            .direct
            .insert(peer, crate::daemon::state::DirectState::RelayOnly);
        tracing::info!(
            target: LOG_TARGET,
            %peer,
            detector = "admission",
            "direct path lost; racing again"
        );
    }
    // Every other gate — already have a session, already negotiating, at the
    // cap, cooling off after a refusal — is one synchronous decision under one
    // lock. That is what lets in-flight rounds count against the cap: this
    // function is called in a tight loop by `retry_sessions` with nothing
    // awaited between calls, so a check that read only `session_count()` saw
    // the same zero twenty times and spawned twenty dials.
    let guard = match state.webrtc_admission.try_admit_offer(peer, &handle) {
        Ok(guard) => guard,
        Err(reason) => {
            tracing::debug!(target: LOG_TARGET, %peer, ?reason, "not negotiating");
            return;
        }
    };

    let offer = if needs_lane {
        Offer::Lane
    } else if demoted {
        Offer::AfterLoss
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
    nudge_addr(endpoint, EndpointAddr::new(peer)).await;
}

/// [`nudge`] for a peer whose `WebRTC` session has just attached. The dial names
/// the session's custom address, so that iroh puts it in the path book of the
/// remote and opens that path on a connection that it already holds. A bare-id
/// dial finds the address only through the address lookup, and iroh does not ask
/// the lookup again for a remote it already knows.
pub(crate) async fn nudge_session(endpoint: &Endpoint, peer: EndpointId) {
    let session = super::probe::NudgeAddrs {
        session: true,
        route: None,
        gossip: false,
    };
    nudge_with(endpoint, peer, &session).await;
}

/// [`nudge`] with the addresses that `addrs` names, in one dial: the session's
/// custom address, the multihop route, or both. The one nudge path, so that what
/// teaches iroh a `WebRTC` address teaches it a multihop route the same way.
pub(crate) async fn nudge_with(
    endpoint: &Endpoint,
    peer: EndpointId,
    addrs: &super::probe::NudgeAddrs,
) {
    let known = super::probe::nudge_known(peer, addrs);
    nudge_addr(endpoint, EndpointAddr::from_parts(peer, known)).await;
}

async fn nudge_addr(endpoint: &Endpoint, addr: EndpointAddr) {
    let peer = addr.id;
    if let Ok(Ok(conn)) = n0_future::time::timeout(
        super::pool::DIAL_TIMEOUT,
        endpoint.connect(addr, NUDGE_ALPN),
    )
    .await
    {
        conn.close(0u32.into(), b"nudge");
    }
    if tracing::enabled!(target: LOG_TARGET, tracing::Level::TRACE)
        && let Some(info) = endpoint.remote_info(peer).await
    {
        let kinds: Vec<String> = info
            .addrs()
            .map(|known| {
                if let iroh::TransportAddr::Custom(custom) = known.addr() {
                    format!("custom:{}", custom.id())
                } else {
                    format!("{:?}", known.addr())
                }
            })
            .collect();
        tracing::trace!(target: LOG_TARGET, %peer, ?kinds, "nudged; the remote knows these addresses");
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
    /// A pair with UDP on both ends whose direct path is known dead (its proof was stale and
    /// was taken back): nothing to judge, so the frames parked for it flush at once. The
    /// connection that was open before the attach is nudged onto the session, as in the race.
    AfterLoss,
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
    let epoch = guard.epoch();
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
        // A connection opened before the attach rides the session only after a connect.
        if matches!(offer, Offer::UdpRace | Offer::AfterLoss) {
            nudge_session(&endpoint, peer).await;
        }
        // The race is judged on the connection after the nudge.
        if offer == Offer::UdpRace && pool.udp_won(peer).await {
            // UDP won while the round ran: the session would sit unused and hold
            // one of the direct-peer slots.
            if handle.detach(&peer) {
                tracing::debug!(target: LOG_TARGET, %peer, "udp won the race; webrtc session detached");
            }
        } else {
            if offer == Offer::Rendezvous {
                tracing::info!(target: LOG_TARGET, %peer, "webrtc session attached to the rendezvous");
            }
            let _ = proven.send(crate::transport::probe::DirectOutcome {
                peer,
                direct: true,
                answered: false,
            });
        }
    });
    state
        .webrtc_admission
        .track(peer, epoch, task.abort_handle());
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
        // A session to the rendezvous that this node does not want. The main
        // case is the release: gossip closes the link, and this detaches the
        // session once the link is down. The other is a joiner whose links to
        // members came up before its graft to the rendezvous landed. Either
        // would hold one of the beacon's slots for ever.
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
    // First let go of what nothing uses, so that a slot frees before this pass
    // decides who gets one.
    detach_idle_sessions_at(state, crate::util::clock::Instant::now());
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
                state.pair_path_kind(addr.id),
                state.direct.get(&addr.id) == Some(&crate::daemon::state::DirectState::Direct),
            )
        })
        .filter(|addr| {
            !state
                .webrtc
                .as_ref()
                .is_some_and(|handle| handle.has_session(&addr.id))
        })
        .filter(|addr| !held_back(state, addr))
        .cloned()
        .collect();
    // Sorted because the cap now bites here: in a mesh larger than the ceiling
    // this pass decides *which* peers get direct sessions, and `HashMap`
    // iteration order would make that differ run to run on one machine.
    peers.sort_unstable_by_key(|addr| addr.id);
    // The lane offers are paced like those of `retry_direct`: one helper decides how many a
    // pass starts and which, so that the two passes do not add up to a round per member.
    let (lane, rest): (Vec<_>, Vec<_>) = peers
        .into_iter()
        .partition(|addr| own_needs_lane || needs_webrtc_lane(addr));
    let pick = super::probe::lane_pick();
    let lane = super::probe::plan_lane_offers(lane, state.webrtc_admission.in_flight(), pick);
    for addr in rest.into_iter().chain(lane) {
        negotiate_session(state, ctx, addr.id, addr);
    }
}

/// Whether the pair with `addr` waits for a send before it is offered a
/// session (decision D4: direct connections are on demand). It does when the
/// peer is no gossip neighbor and the pool holds no connection that a send opened,
/// so nothing was sent to it within the idle window. A pair that needs the lane
/// waits too (decision D11), unless a frame is held for it: its session is the only
/// direct path it has, and that frame is the send that asks for it. A gossip
/// neighbor keeps its session proactive, because the gossip link is always on.
///
/// One more pair is not held back: on a mesh whose relay is lookup only, a pair
/// whose direct-path probe failed (`RelayOnly`). A directed frame to it is parked,
/// never dialed, so no send ever opens a connection, and its gossip graft waits
/// for a proven direct path. A pair behind NAT, with addresses but no punched
/// path, would wait for ever. A session is its way out.
fn held_back(state: &crate::daemon::state::EventLoopState, addr: &EndpointAddr) -> bool {
    let probe_failed = !state.relay_transport
        && state.direct.get(&addr.id) == Some(&crate::daemon::state::DirectState::RelayOnly);
    let linked = state.linked_endpoints.contains(&addr.id);
    let wanted = state.lane_session_wanted(addr.id, crate::util::clock::Instant::now());
    // A peer that evicted us lately is left alone by every proactive dial, and the offer of a
    // session is one. A held frame is a send, and a send dials at once.
    let evicted_us = !linked && !wanted && state.webrtc_admission.evicted_recently(addr.id);
    evicted_us
        || (!linked
            && !wanted
            && !probe_failed
            && state.unicast_pool.used_connection(addr.id).is_none())
}

/// Detach the sessions that nothing has held for
/// [`DIRECT_IDLE_BACKSTOP_SECS`](crate::util::tuning::DIRECT_IDLE_BACKSTOP_SECS)
/// (decision D11: the ceiling frees a place for a newcomer, this frees what nobody uses).
/// A detached pair holds no pooled connection, so [`held_back`] leaves it alone until a send dials the
/// peer.
///
/// The last use is the one of the ledger of the admission table. A round in flight holds a peer,
/// and so does a live gossip connection, so a gossip neighbor never idles out. A pair detaches its
/// session a window after its last send, plus one tick of the retry pass. A peer whose address is
/// not known keeps its session: see [`held_back`]. Returns the peers detached.
fn detach_idle_sessions_at(
    state: &mut crate::daemon::state::EventLoopState,
    now: crate::util::clock::Instant,
) -> Vec<EndpointId> {
    let Some(handle) = state.webrtc.clone() else {
        return Vec::new();
    };
    let window = std::time::Duration::from_secs(crate::util::tuning::DIRECT_IDLE_BACKSTOP_SECS);
    let mut detached = Vec::new();
    for peer in state.webrtc_admission.idle_sessions(now, window) {
        let kept = state.linked_endpoints.contains(&peer)
            || !state.peer_endpoints.values().any(|addr| addr.id == peer);
        if kept || !handle.detach(&peer) {
            continue;
        }
        tracing::debug!(target: LOG_TARGET, %peer, "detached an idle session");
        detached.push(peer);
    }
    detached
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
    use crate::transport::probe::PathKind;

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
            wants_session(false, None, false),
            "a udp pair races the punch"
        );
        assert!(
            !wants_session(false, Some(PathKind::Ip), false),
            "udp won; no round"
        );
        assert!(
            wants_session(true, None, false),
            "a lane pair always negotiates"
        );
        assert!(
            wants_session(true, Some(PathKind::Ip), true),
            "a lane pair's session is its only direct path"
        );
    }

    // A pair proven direct with no session proved its UDP path; a cold or
    // idled-out pool must not start the race again on every alive tick.
    #[test]
    fn a_proven_udp_pair_is_not_raced_again() {
        assert!(
            !wants_session(false, None, true),
            "proven direct, no live connection to read"
        );
        assert!(
            !wants_session(false, Some(PathKind::WebRtc), true),
            "proven direct, riding a session"
        );
    }

    // The proof of a direct path is a state of the engine, and only a watcher on a
    // pooled connection takes it back. When the admission table reads the relay as the
    // selected path, the proof is stale: the pair offers, as one that was never proven.
    #[test]
    fn a_proven_pair_that_reads_as_relay_is_offered_a_session() {
        assert!(wants_session(false, Some(PathKind::Relay), true));
    }

    // Only the lower id watches a pooled connection, so when the higher id is the one
    // that sends, the lower id never sees the direct path go. The higher id then offers
    // by itself, once its own reading contradicts the proof; the lower id wins a crossing.
    #[test]
    fn the_higher_id_offers_when_the_proof_of_a_direct_path_is_stale() {
        assert!(
            waits_for_the_offer(true, false, None, false),
            "nothing to say"
        );
        assert!(
            waits_for_the_offer(true, false, Some(PathKind::Ip), true),
            "the proof holds"
        );
        assert!(
            !waits_for_the_offer(true, true, None, false),
            "a frame is held for the peer"
        );
        assert!(
            !waits_for_the_offer(true, false, Some(PathKind::Relay), true),
            "the pair reads as relay although it was proven"
        );
        assert!(
            waits_for_the_offer(true, false, Some(PathKind::Relay), false),
            "never proven: the lower id offers"
        );
        assert!(
            !waits_for_the_offer(false, false, Some(PathKind::Ip), true),
            "the lower id never waits"
        );
    }

    // A pair on gossip is below a session as a pair on multihop is: its proof of a direct path is
    // stale, and it asks for a session.
    #[test]
    fn a_pair_on_gossip_is_offered_a_session_even_when_proven_direct() {
        assert!(proof_is_stale(Some(PathKind::Gossip), true));
        assert!(wants_session(false, Some(PathKind::Gossip), true));
    }

    // A pair that multihop carries is off the relay, so it is proven direct, but a
    // session ranks above multihop. The pair offers whether or not a pooled
    // connection exists: the kind comes from the watcher, or from the admission
    // table when the pool has closed an idle connection.
    #[test]
    fn a_pair_on_multihop_is_offered_a_session_even_when_proven_direct() {
        assert!(wants_session(false, Some(PathKind::Multihop), true));
        let watched_after_the_pool_closed_it = None;
        let read_from_the_admission_table = Some(PathKind::Multihop);
        let kind = crate::transport::probe::pair_kind(
            watched_after_the_pool_closed_it,
            read_from_the_admission_table,
        );
        assert!(
            wants_session(false, kind, true),
            "an idle pair on multihop still offers"
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

    /// [`endpoint`] with the key given.
    async fn endpoint_with(key: SecretKey) -> (Endpoint, WebRtcHandle) {
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

    /// **A node with a ceiling of two holds two sessions, and the third offer is answered.**
    ///
    /// The ceiling is the setting of the node (C). No offer is refused for it. The session
    /// that was used least recently is detached when the third attaches, so the node keeps
    /// two sessions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_node_with_a_ceiling_of_two_answers_a_third_offer_and_detaches_the_oldest() {
        let (server, server_hub) = endpoint().await;
        let admission = SignalAdmission::new(2);
        let router = serve(&server, &server_hub, &admission);

        let mut clients = Vec::new();
        for _ in 0..3 {
            let (client, client_hub) = endpoint().await;
            dial_signal_with(
                &client,
                server.addr(),
                &client_hub,
                quick(),
                IceProfile { host_only: true },
            )
            .await
            .expect("every offer attaches");
            clients.push((client, client_hub));
        }

        assert!(
            until(|| !server_hub.has_session(&clients[0].0.id())).await,
            "the least recently used session is detached"
        );
        assert!(server_hub.has_session(&clients[1].0.id()));
        assert!(server_hub.has_session(&clients[2].0.id()));
        assert_eq!(server_hub.session_count(), 2, "the node holds two sessions");

        router.shutdown().await.expect("shutdown");
        for (client, _) in clients {
            client.close().await;
        }
        server.close().await;
    }

    /// **The evicted peer reads code 11 on its offer.** At a ceiling of one, the second session
    /// evicts the first. The first peer offers again at once, and the dialer reads the refusal as the
    /// `EVICTED` code, so it can wait instead of taking the place back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_peer_whose_session_was_evicted_reads_the_evicted_code_on_its_next_offer() {
        let (server, server_hub) = endpoint().await;
        let admission = SignalAdmission::new(1);
        let router = serve(&server, &server_hub, &admission);

        let (first, first_hub) = endpoint().await;
        let (second, second_hub) = endpoint().await;
        for (client, hub) in [(&first, &first_hub), (&second, &second_hub)] {
            dial_signal_with(
                client,
                server.addr(),
                hub,
                quick(),
                IceProfile { host_only: true },
            )
            .await
            .expect("an offer attaches");
        }
        assert!(
            until(|| !server_hub.has_session(&first.id())).await,
            "the first session was evicted"
        );

        let error = dial_signal_with(
            &first,
            server.addr(),
            &first_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await
        .expect_err("the evicted peer is refused for a minute");
        assert!(
            is_cap_refusal(&error),
            "the dialer reads the refusal as a code to wait on: {error:#}"
        );
        assert!(
            server_hub.has_session(&second.id()),
            "the newcomer keeps its place"
        );

        router.shutdown().await.expect("shutdown");
        first.close().await;
        second.close().await;
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

    /// A pair with no UDP: the higher id (the answerer of the session round)
    /// dials a connection over the relay, and the lower id offers a session
    /// while that connection is still held. iroh opens a new path only from the
    /// client side of a connection, and only on a path event of its own
    /// endpoint. The offerer's nudge reaches the answerer's endpoint as an
    /// inbound connect, which gives it no event for the connection it dialed, so
    /// the answerer must nudge once after its attach. Without it the accepted
    /// connection stays on the relay and the relay policy closes it.
    #[cfg(feature = "iroh-test-utils")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connection_dialed_by_the_answerer_leaves_the_relay_when_the_session_attaches() {
        use iroh::protocol::{AcceptError, ProtocolHandler};

        const HOLD_ALPN: &[u8] = b"habilis-mesh/test-hold/0";

        #[derive(Debug, Clone)]
        struct Hold(tokio::sync::mpsc::Sender<bool>);
        impl ProtocolHandler for Hold {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                let direct = super::super::path::wait_direct(&conn, Duration::from_secs(12)).await;
                let _ = self.0.send(direct).await;
                conn.closed().await;
                Ok(())
            }
        }

        let (relay_url, _relay_server) = crate::lookup::test_relay::spawn_plain()
            .await
            .expect("local relay");
        let bind = |key: SecretKey, handle: &WebRtcHandle| {
            let relay_url = relay_url.clone();
            let transport = handle.transport();
            let selector = handle.path_selector();
            async move {
                Endpoint::builder(presets::Minimal)
                    .secret_key(key)
                    .relay_mode(RelayMode::custom([relay_url]))
                    .add_custom_transport(transport)
                    .path_selector(selector)
                    .clear_ip_transports()
                    .bind()
                    .await
                    .expect("bind endpoint with relay")
            }
        };
        let (mut low_key, mut high_key) = (SecretKey::generate(), SecretKey::generate());
        if low_key.public() > high_key.public() {
            std::mem::swap(&mut low_key, &mut high_key);
        }
        let low_hub = WebRtcHandle::new(WebRtcTransport::new(low_key.public()));
        let low = bind(low_key, &low_hub).await;
        let high_hub = WebRtcHandle::new(WebRtcTransport::new(high_key.public()));
        let high = bind(high_key, &high_hub).await;

        let (held_tx, mut held_rx) = tokio::sync::mpsc::channel(1);
        let low_router = Router::builder(low.clone())
            .accept(HOLD_ALPN, Hold(held_tx))
            .spawn();
        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let high_router = Router::builder(high.clone())
            .accept(
                MESH_WEBRTC_SIGNAL_ALPN,
                WebRtcSignalAcceptor::new(
                    high_hub.clone(),
                    high.clone(),
                    high.id(),
                    admission,
                    IceProfile { host_only: true },
                ),
            )
            .spawn();

        let low_on_relay = EndpointAddr::new(low.id()).with_relay_url(relay_url.clone());
        let high_on_relay = EndpointAddr::new(high.id()).with_relay_url(relay_url.clone());
        let held = high
            .connect(low_on_relay, HOLD_ALPN)
            .await
            .expect("the answerer dials the offerer over the relay");

        dial_signal_with(
            &low,
            high_on_relay,
            &low_hub,
            SignalDeadlines::DEFAULT,
            IceProfile { host_only: true },
        )
        .await
        .expect("the offerer attaches a session");
        register_session_addr(&low, high.id());
        nudge(&low, high.id()).await;

        let direct = tokio::time::timeout(Duration::from_secs(20), held_rx.recv())
            .await
            .expect("the held connection reports in time")
            .expect("the channel is open");
        assert!(
            direct,
            "the connection that the answerer dialed must leave the relay once the session is attached"
        );

        held.close(0u32.into(), b"done");
        high_router.shutdown().await.expect("shutdown");
        low_router.shutdown().await.expect("shutdown");
        low.close().await;
        high.close().await;
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
    /// A pair waits for a send before it is offered a session when it is no gossip neighbor
    /// and holds no pooled connection. A pair that needs the lane waits too, unless a frame is
    /// held for it: that frame is the send.
    #[test]
    fn a_cold_non_neighbor_pair_waits_for_a_send_unless_a_frame_is_held_for_a_lane_peer() {
        let peer = crate::testing::endpoint_id(7);
        let ip_pair = EndpointAddr::new(peer).with_ip_addr("127.0.0.1:4000".parse().expect("addr"));
        let lane_pair = EndpointAddr::new(peer)
            .with_relay_url("https://relay.invalid".parse().expect("relay url"));
        let mut state = crate::testing::fresh_state();
        state.local_udp_transport = true;

        assert!(held_back(&state, &ip_pair), "cold, no neighbor, an IP path");
        assert!(
            held_back(&state, &lane_pair),
            "a lane pair with no held frame waits as well"
        );
        state.want_lane_session(peer, crate::util::clock::Instant::now());
        assert!(
            !held_back(&state, &lane_pair),
            "a frame held for a lane peer opens its session"
        );
        state.clear_lane_wanted(peer);
        assert!(
            held_back(&state, &lane_pair),
            "the want ends with the attach"
        );
        state.linked_endpoints.insert(peer);
        assert!(
            !held_back(&state, &ip_pair),
            "a gossip neighbor is never held back"
        );
    }

    /// A pair behind NAT has IP addresses but no direct path. On a mesh whose relay
    /// is lookup only, a directed frame to it is parked, so nothing is ever sent and
    /// no connection opens, and the probe that proves a direct path fails. Waiting
    /// for a send would wait for ever. Once the probe has failed and the pair is
    /// `RelayOnly`, a session is the way out, so the pair is no longer held back.
    #[test]
    fn a_pair_whose_probe_failed_on_a_lookup_only_relay_is_offered_a_session() {
        use crate::daemon::state::DirectState;

        let peer = crate::testing::endpoint_id(7);
        let ip_pair = EndpointAddr::new(peer).with_ip_addr("127.0.0.1:4000".parse().expect("addr"));
        let mut state = crate::testing::fresh_state();
        state.local_udp_transport = true;
        state.relay_transport = false;

        for (known, held) in [
            (None, true),
            (Some(DirectState::Pending), true),
            (Some(DirectState::Direct), true),
            (Some(DirectState::RelayOnly), false),
        ] {
            match known {
                Some(known) => {
                    state.direct.insert(peer, known);
                }
                None => {
                    state.direct.remove(&peer);
                }
            }
            assert_eq!(
                held_back(&state, &ip_pair),
                held,
                "lookup-only relay, direct state {known:?}"
            );
        }

        // With the relay carrying payload the pair can talk without a session, so
        // a failed probe is no reason to open one before a send.
        state.relay_transport = true;
        state.direct.insert(peer, DirectState::RelayOnly);
        assert!(
            held_back(&state, &ip_pair),
            "the relay carries payload: wait for a send"
        );
    }

    /// A peer that evicted our connection is not offered a session by the retry pass for a while:
    /// the offer is a proactive dial, and it would take the place that the peer just freed. A frame
    /// that is held for the peer still passes, because a send dials at once.
    #[test]
    fn a_peer_that_evicted_us_is_not_offered_a_session_unless_a_frame_is_held() {
        use crate::daemon::state::DirectState;

        let peer = crate::testing::endpoint_id(7);
        let pair = EndpointAddr::new(peer).with_ip_addr("127.0.0.1:4000".parse().expect("addr"));
        let mut state = crate::testing::fresh_state();
        state.local_udp_transport = true;
        state.relay_transport = false;
        state.direct.insert(peer, DirectState::RelayOnly);
        assert!(!held_back(&state, &pair), "a failed probe offers a session");

        state.webrtc_admission.note_evicted(peer);
        assert!(held_back(&state, &pair), "the peer evicted us lately");

        state.want_lane_session(peer, crate::util::clock::Instant::now());
        assert!(!held_back(&state, &pair), "a held frame is a send");
    }

    /// A session nothing uses is detached once the idle window has passed, and
    /// the pair then waits for a send.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_nothing_uses_is_detached_and_its_pair_waits_for_a_send() {
        idle_session_detaches(|id| {
            EndpointAddr::new(id).with_ip_addr("127.0.0.1:4000".parse().expect("addr"))
        })
        .await;
    }

    /// The same for a lane peer: its session is no longer kept for ever. It goes at the backstop
    /// like any other, and the pair waits for a held frame to be offered one again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lane_session_nothing_uses_is_detached_at_the_backstop() {
        idle_session_detaches(|id| {
            EndpointAddr::new(id)
                .with_relay_url("https://relay.invalid".parse().expect("relay url"))
        })
        .await;
    }

    async fn idle_session_detaches(bob_addr: fn(EndpointId) -> EndpointAddr) {
        use crate::util::clock::Instant;

        let (server, server_hub) = endpoint_with_lookup().await;
        let admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        let router = serve(&server, &server_hub, &admission);

        let (client, client_hub) = endpoint_with_lookup().await;
        let client_admission = SignalAdmission::new(MAX_DIRECT_PEERS);
        // The round holds the slot as in production, and teaches the table its hub.
        let round = client_admission
            .try_admit(server.id(), &client_hub)
            .expect("room");
        dial_signal_with(
            &client,
            server.addr(),
            &client_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await
        .expect("the signal round must attach a session");
        drop(round);
        // Both roles tell the table of the attach, as `spawn_offer_round` does.
        client_admission.note_success(server.id());
        assert!(client_hub.has_session(&server.id()));

        let mut state = crate::testing::fresh_state();
        state.webrtc = Some(client_hub.clone());
        state.webrtc_admission = client_admission.clone();
        state.local_udp_transport = true;
        state
            .peer_endpoints
            .insert(crate::testing::nick("bob"), bob_addr(server.id()));
        let window = Duration::from_secs(crate::util::tuning::DIRECT_IDLE_BACKSTOP_SECS);
        let start = Instant::now();

        assert!(detach_idle_sessions_at(&mut state, start).is_empty());
        assert!(
            detach_idle_sessions_at(
                &mut state,
                start + window.saturating_sub(Duration::from_secs(1))
            )
            .is_empty()
        );
        assert!(client_hub.has_session(&server.id()), "not yet");
        assert_eq!(
            detach_idle_sessions_at(&mut state, start + window),
            vec![server.id()]
        );
        assert!(!client_hub.has_session(&server.id()), "the session is gone");
        assert!(
            held_back(
                &state,
                &state.peer_endpoints.values().next().expect("bob").clone()
            ),
            "the pair waits for a send again"
        );

        router.shutdown().await.expect("shutdown");
        client.close().await;
    }

    /// The retry pass offers a session to a cold pair with an IP path only after
    /// a send: while no pooled connection exists, the pair is left alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_retry_pass_offers_a_session_only_to_a_pair_that_sent() {
        use crate::protocol::MeshId;
        use crate::protocol::identity::{Identity, encode_pubkey};
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                conn.closed().await;
                Ok(())
            }
        }

        let (endpoint, handle) = endpoint().await;
        // Only the lower id offers, so the peer's key must be above ours.
        // The id of our endpoint is random: with 255 seeds, one run in 256 found no key above it.
        let key = (1u16..=u16::MAX)
            .map(|seed| {
                let mut bytes = [0u8; 32];
                bytes[..2].copy_from_slice(&seed.to_le_bytes());
                SecretKey::from_bytes(&bytes)
            })
            .find(|key| key.public() > endpoint.id())
            .expect("a key above ours");
        let server = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind()
            .await
            .expect("bind a loopback server");
        let router = Router::builder(server.clone())
            .accept(crate::transport::UNICAST_ALPN, Hold)
            .spawn();
        crate::lookup::add_peer_addr(&endpoint, server.addr()).expect("register the server");

        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mesh = MeshId::from("test");
        let identity = Identity::generate();
        let our_pubkey = encode_pubkey(&identity.public());
        let author = crate::testing::nick("alice");
        let sink = crate::gossip::event::SilentSink;
        let ctx = crate::daemon::ctx::HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey: &our_pubkey,
            max_peers: 16,
            rendezvous_id: crate::testing::endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let mut state = crate::testing::fresh_state();
        state.webrtc = Some(handle);
        state.local_udp_transport = true;
        state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
        state
            .peer_endpoints
            .insert(crate::testing::nick("bob"), server.addr());

        retry_sessions(&mut state, &ctx);
        assert_eq!(
            state.webrtc_admission.in_flight(),
            0,
            "a cold pair is not offered a session"
        );

        state
            .unicast_pool
            .warm_or_dial(server.id())
            .await
            .expect("a send dials the peer");
        retry_sessions(&mut state, &ctx);
        assert_eq!(
            state.webrtc_admission.in_flight(),
            1,
            "after a send, the pair is offered a session"
        );

        // The dial to a closed signal port would hold its slot for a long deadline.
        state.webrtc_admission.close();
        assert!(
            until(|| state.webrtc_admission.in_flight() == 0).await,
            "closing the table cancels the round"
        );
        router.shutdown().await.expect("shutdown");
        endpoint.close().await;
    }

    /// Only the lower id has a path watcher, so a pair that loses IP while the higher id sends
    /// is seen by nobody but the higher id, and by its admission table alone: the proof of a
    /// direct path is stale where the selected path reads as the relay. The higher id then
    /// offers by itself and takes the proof back, so that a frame is parked for the session
    /// instead of being refused on the relay. A pair that reads as UDP keeps its proof and gets
    /// no offer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_higher_id_offers_and_demotes_a_proven_pair_that_reads_as_relay() {
        use crate::daemon::state::DirectState;
        use crate::protocol::MeshId;
        use crate::protocol::identity::{Identity, encode_pubkey};
        use crate::transport::probe::PathKind;
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                conn.closed().await;
                Ok(())
            }
        }

        let (endpoint, handle) = endpoint().await;
        // The peer's key must be below ours, so that we are the higher id and wait to be dialled.
        let key = (1u16..=u16::MAX)
            .map(|seed| {
                let mut bytes = [0u8; 32];
                bytes[..2].copy_from_slice(&seed.to_le_bytes());
                SecretKey::from_bytes(&bytes)
            })
            .find(|key| key.public() < endpoint.id())
            .expect("a key below ours");
        let server = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind()
            .await
            .expect("bind a loopback server");
        let router = Router::builder(server.clone())
            .accept(crate::transport::UNICAST_ALPN, Hold)
            .spawn();
        crate::lookup::add_peer_addr(&endpoint, server.addr()).expect("register the server");

        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mesh = MeshId::from("test");
        let identity = Identity::generate();
        let our_pubkey = encode_pubkey(&identity.public());
        let author = crate::testing::nick("alice");
        let sink = crate::gossip::event::SilentSink;
        let ctx = crate::daemon::ctx::HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey: &our_pubkey,
            max_peers: 16,
            rendezvous_id: crate::testing::endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let mut state = crate::testing::fresh_state();
        state.webrtc = Some(handle);
        state.local_udp_transport = true;
        state.relay_transport = false;
        state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
        state
            .peer_endpoints
            .insert(crate::testing::nick("bob"), server.addr());
        let bob = server.id();
        state
            .unicast_pool
            .warm_or_dial(bob)
            .await
            .expect("a send dials the peer");
        state.direct.insert(bob, DirectState::Direct);

        state.path_kinds.insert(bob, PathKind::Ip);
        retry_sessions(&mut state, &ctx);
        assert_eq!(
            state.webrtc_admission.in_flight(),
            0,
            "UDP is selected: no offer"
        );
        assert_eq!(state.direct.get(&bob), Some(&DirectState::Direct));

        state.path_kinds.insert(bob, PathKind::Relay);
        retry_sessions(&mut state, &ctx);
        assert_eq!(
            state.webrtc_admission.in_flight(),
            1,
            "the proof is stale: the higher id offers"
        );
        assert_eq!(
            state.direct.get(&bob),
            Some(&DirectState::RelayOnly),
            "and takes the proof back, so that a frame is parked"
        );

        state.webrtc_admission.close();
        assert!(
            until(|| state.webrtc_admission.in_flight() == 0).await,
            "closing the table cancels the round"
        );
        router.shutdown().await.expect("shutdown");
        endpoint.close().await;
    }

    /// The retry pass offers a session to an idle lane peer only when a frame is held for it
    /// (decision D11): without one, the pair is left alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_retry_pass_offers_a_session_to_an_idle_lane_peer_only_for_a_held_frame() {
        use crate::protocol::MeshId;
        use crate::protocol::identity::{Identity, encode_pubkey};
        use iroh::endpoint::Connection;
        use iroh::protocol::{AcceptError, ProtocolHandler};

        #[derive(Debug, Clone)]
        struct Hold;
        impl ProtocolHandler for Hold {
            async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
                conn.closed().await;
                Ok(())
            }
        }

        let (endpoint, handle) = endpoint().await;
        // Only the lower id offers, so the peer's key must be above ours.
        // The id of our endpoint is random: with 255 seeds, one run in 256 found no key above it.
        let key = (1u16..=u16::MAX)
            .map(|seed| {
                let mut bytes = [0u8; 32];
                bytes[..2].copy_from_slice(&seed.to_le_bytes());
                SecretKey::from_bytes(&bytes)
            })
            .find(|key| key.public() > endpoint.id())
            .expect("a key above ours");
        let server = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind()
            .await
            .expect("bind a loopback server");
        let router = Router::builder(server.clone())
            .accept(crate::transport::UNICAST_ALPN, Hold)
            .spawn();
        crate::lookup::add_peer_addr(&endpoint, server.addr()).expect("register the server");

        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mesh = MeshId::from("test");
        let identity = Identity::generate();
        let our_pubkey = encode_pubkey(&identity.public());
        let author = crate::testing::nick("alice");
        let sink = crate::gossip::event::SilentSink;
        let ctx = crate::daemon::ctx::HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey: &our_pubkey,
            max_peers: 16,
            rendezvous_id: crate::testing::endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let mut state = crate::testing::fresh_state();
        state.webrtc = Some(handle);
        state.local_udp_transport = true;
        state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
        state.peer_endpoints.insert(
            crate::testing::nick("bob"),
            EndpointAddr::new(server.id())
                .with_relay_url("https://relay.invalid".parse().expect("relay url")),
        );

        retry_sessions(&mut state, &ctx);
        assert_eq!(
            state.webrtc_admission.in_flight(),
            0,
            "an idle lane peer is not offered a session"
        );

        state.want_lane_session(server.id(), crate::util::clock::Instant::now());
        retry_sessions(&mut state, &ctx);
        assert_eq!(
            state.webrtc_admission.in_flight(),
            1,
            "a frame is held for the peer: it is offered a session"
        );

        // The dial to a closed signal port would hold its slot for a long deadline.
        state.webrtc_admission.close();
        assert!(
            until(|| state.webrtc_admission.in_flight() == 0).await,
            "closing the table cancels the round"
        );
        router.shutdown().await.expect("shutdown");
        endpoint.close().await;
    }

    /// **A graft that this node asks for opens the session of a lane peer.** In a mesh where every
    /// pair needs the lane and nothing is sent, no frame is held. The graft of a member is the
    /// reason for its session: without it the pair stays `Pending` for ever and no member links
    /// to another member.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_graft_of_a_cold_lane_peer_opens_its_session() {
        use crate::protocol::MeshId;
        use crate::protocol::identity::{Identity, encode_pubkey};

        let (endpoint, handle) = endpoint().await;
        // Only the lower id offers, so the peer's key must be above ours.
        let key = (1u16..=u16::MAX)
            .map(|seed| {
                let mut bytes = [0u8; 32];
                bytes[..2].copy_from_slice(&seed.to_le_bytes());
                SecretKey::from_bytes(&bytes)
            })
            .find(|key| key.public() > endpoint.id())
            .expect("a key above ours");
        let (server, _server_hub) = endpoint_with(key).await;
        let peer = server.id();

        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mesh = MeshId::from("test");
        let identity = Identity::generate();
        let our_pubkey = encode_pubkey(&identity.public());
        let author = crate::testing::nick("alice");
        let sink = crate::gossip::event::SilentSink;
        let ctx = crate::daemon::ctx::HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey: &our_pubkey,
            max_peers: 16,
            rendezvous_id: crate::testing::endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let mut state = crate::testing::fresh_state();
        state.webrtc = Some(handle);
        state.local_udp_transport = true;
        state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
        let addr = EndpointAddr::new(peer)
            .with_relay_url("https://relay.invalid".parse().expect("relay url"));
        state
            .peer_endpoints
            .insert(crate::testing::nick("bob"), addr.clone());
        assert!(
            held_back(&state, &addr),
            "cold: nothing asks for the session yet"
        );

        let grafted = crate::transport::probe::ensure_direct(&mut state, &ctx, peer, &addr);
        assert!(!grafted, "the graft waits for the session");
        assert!(
            !held_back(&state, &addr),
            "the graft asks for the session of the lane peer"
        );
        assert_eq!(
            state.webrtc_admission.in_flight(),
            1,
            "the session is offered at once"
        );

        // The dial to a closed signal port would hold its slot for a long deadline.
        state.webrtc_admission.close();
        endpoint.close().await;
    }

    /// **A frame held on the higher-id node opens the session.** The lower id has no reason to
    /// offer, so the higher id offers when a frame is held for the peer, and the session attaches
    /// on both nodes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_frame_held_on_the_higher_id_node_opens_the_session() {
        use crate::protocol::MeshId;
        use crate::protocol::identity::{Identity, encode_pubkey};

        let (endpoint, handle) = endpoint().await;
        // Only the lower id offers unless a frame is held, and here the peer is the lower id.
        // The id of our endpoint is random, so many seeds are tried.
        let key = (1u16..=u16::MAX)
            .map(|seed| {
                let mut bytes = [0u8; 32];
                bytes[..2].copy_from_slice(&seed.to_le_bytes());
                SecretKey::from_bytes(&bytes)
            })
            .find(|key| key.public() < endpoint.id())
            .expect("a key below ours");
        let (server, server_hub) = endpoint_with(key).await;
        let server_admission = SignalAdmission::new(8);
        let router = serve(&server, &server_hub, &server_admission);

        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mesh = MeshId::from("test");
        let identity = Identity::generate();
        let our_pubkey = encode_pubkey(&identity.public());
        let author = crate::testing::nick("alice");
        let sink = crate::gossip::event::SilentSink;
        let ctx = crate::daemon::ctx::HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey: &our_pubkey,
            max_peers: 16,
            rendezvous_id: crate::testing::endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let mut state = crate::testing::fresh_state();
        state.webrtc = Some(handle.clone());
        state.local_udp_transport = false;
        state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
        state
            .peer_endpoints
            .insert(crate::testing::nick("bob"), server.addr());

        retry_sessions(&mut state, &ctx);
        assert_eq!(
            state.webrtc_admission.in_flight(),
            0,
            "an idle lane peer is not offered a session"
        );

        state.want_lane_session(server.id(), crate::util::clock::Instant::now());
        retry_sessions(&mut state, &ctx);
        assert!(
            until(|| handle.has_session(&server.id()) && server_hub.has_session(&endpoint.id()))
                .await,
            "a frame is held for the lower id: the higher id offers, and the session attaches"
        );

        router.shutdown().await.expect("shutdown");
        server.close().await;
        endpoint.close().await;
    }

    /// A session carries the pair whatever one connection reads: a connection opened before the
    /// attach reads `Relay` until a path event moves it. With a session attached the proof stands:
    /// no demotion, no offer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pair_with_a_session_keeps_its_proof_when_a_connection_reads_as_relay() {
        use crate::daemon::state::DirectState;
        use crate::protocol::MeshId;
        use crate::protocol::identity::{Identity, encode_pubkey};
        use crate::transport::probe::PathKind;

        let (endpoint, handle) = endpoint().await;
        // The peer's key must be below ours: we are the higher id, so a session is offered here
        // only for a held frame, which the test uses to attach one.
        let key = (1u16..=u16::MAX)
            .map(|seed| {
                let mut bytes = [0u8; 32];
                bytes[..2].copy_from_slice(&seed.to_le_bytes());
                SecretKey::from_bytes(&bytes)
            })
            .find(|key| key.public() < endpoint.id())
            .expect("a key below ours");
        let (server, server_hub) = endpoint_with(key).await;
        let server_admission = SignalAdmission::new(8);
        let router = serve(&server, &server_hub, &server_admission);

        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mesh = MeshId::from("test");
        let identity = Identity::generate();
        let our_pubkey = encode_pubkey(&identity.public());
        let author = crate::testing::nick("alice");
        let sink = crate::gossip::event::SilentSink;
        let ctx = crate::daemon::ctx::HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey: &our_pubkey,
            max_peers: 16,
            rendezvous_id: crate::testing::endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let mut state = crate::testing::fresh_state();
        state.webrtc = Some(handle.clone());
        state.local_udp_transport = true;
        state.relay_transport = false;
        state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
        state
            .peer_endpoints
            .insert(crate::testing::nick("bob"), server.addr());
        let bob = server.id();

        // Attach a session: a frame is held for the peer, and the higher id offers for it.
        state.want_lane_session(bob, crate::util::clock::Instant::now());
        state.direct.insert(bob, DirectState::RelayOnly);
        state.path_kinds.insert(bob, PathKind::Relay);
        retry_sessions(&mut state, &ctx);
        assert!(
            until(|| handle.has_session(&bob) && server_hub.has_session(&endpoint.id())).await,
            "the session attaches"
        );

        // The session is up and the proof is back, but a connection still reads as the relay. The
        // frame is still held, so that the pair is not left alone for want of a send.
        state.direct.insert(bob, DirectState::Direct);
        state.path_kinds.insert(bob, PathKind::Relay);
        let addr = server.addr();
        negotiate_session(&mut state, &ctx, bob, addr);
        assert_eq!(
            state.direct.get(&bob),
            Some(&DirectState::Direct),
            "a session carries the pair: the reading of one connection does not take the proof back"
        );

        router.shutdown().await.expect("shutdown");
        server.close().await;
        endpoint.close().await;
    }

    /// **UDP returns on a pair that only gossips.** Such a pair has no path watcher, so the session
    /// that the race attached would stay until the backstop. The reading of the admission table
    /// detaches it, on the fast ticker: a relay reading keeps it, an IP reading drops it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_is_detached_once_udp_is_selected_again() {
        use crate::daemon::state::DirectState;
        use crate::protocol::MeshId;
        use crate::protocol::identity::{Identity, encode_pubkey};
        use crate::transport::probe::PathKind;

        let (endpoint, handle) = endpoint().await;
        let key = (1u16..=u16::MAX)
            .map(|seed| {
                let mut bytes = [0u8; 32];
                bytes[..2].copy_from_slice(&seed.to_le_bytes());
                SecretKey::from_bytes(&bytes)
            })
            .find(|key| key.public() < endpoint.id())
            .expect("a key below ours");
        let (server, server_hub) = endpoint_with(key).await;
        let server_admission = SignalAdmission::new(8);
        let router = serve(&server, &server_hub, &server_admission);

        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mesh = MeshId::from("test");
        let identity = Identity::generate();
        let our_pubkey = encode_pubkey(&identity.public());
        let author = crate::testing::nick("alice");
        let sink = crate::gossip::event::SilentSink;
        let ctx = crate::daemon::ctx::HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey: &our_pubkey,
            max_peers: 16,
            rendezvous_id: crate::testing::endpoint_id(9),
            external_msg_tx: None,
            sink: &sink,
        };
        let mut state = crate::testing::fresh_state();
        state.webrtc = Some(handle.clone());
        state.local_udp_transport = true;
        state.relay_transport = false;
        state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
        state
            .peer_endpoints
            .insert(crate::testing::nick("bob"), server.addr());
        let bob = server.id();

        state.want_lane_session(bob, crate::util::clock::Instant::now());
        state.direct.insert(bob, DirectState::RelayOnly);
        state.path_kinds.insert(bob, PathKind::Relay);
        retry_sessions(&mut state, &ctx);
        assert!(
            until(|| handle.has_session(&bob) && server_hub.has_session(&endpoint.id())).await,
            "the session attaches"
        );

        state.path_kinds.insert(bob, PathKind::Relay);
        detach_sessions_under_udp(&mut state, &ctx).await;
        assert!(
            handle.has_session(&bob),
            "the pair still reads as the relay"
        );

        state.path_kinds.insert(bob, PathKind::Ip);
        detach_sessions_under_udp(&mut state, &ctx).await;
        assert!(!handle.has_session(&bob), "UDP is selected again");
        assert_eq!(
            state.direct.get(&bob),
            Some(&DirectState::Direct),
            "the pair is proven direct again"
        );

        router.shutdown().await.expect("shutdown");
        server.close().await;
        endpoint.close().await;
    }

    /// **A pass paces the lane offers.** Six lane members, none linked: the pass offers a session
    /// to `LANE_OFFERS_IN_FLIGHT` of them. The others are not touched: no `Pending` mark, so the
    /// next pass picks them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retry_pass_offers_to_the_budget_of_lane_members_and_leaves_the_others_alone() {
        use crate::protocol::MeshId;
        use crate::protocol::identity::{Identity, encode_pubkey};
        use crate::util::tuning::LANE_OFFERS_IN_FLIGHT;

        let (endpoint, handle) = endpoint().await;
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mesh = MeshId::from("test");
        let identity = Identity::generate();
        let our_pubkey = encode_pubkey(&identity.public());
        let author = crate::testing::nick("alice");
        let sink = crate::gossip::event::SilentSink;
        let ctx = crate::daemon::ctx::HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey: &our_pubkey,
            max_peers: 16,
            rendezvous_id: crate::testing::endpoint_id(99),
            external_msg_tx: None,
            sink: &sink,
        };
        let mut state = crate::testing::fresh_state();
        state.webrtc = Some(handle);
        state.local_udp_transport = true;
        state.relay_transport = false;
        state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
        let members: Vec<EndpointId> = (1..=6).map(crate::testing::endpoint_id).collect();
        for (index, id) in members.iter().enumerate() {
            let addr = EndpointAddr::new(*id)
                .with_relay_url("https://relay.invalid".parse().expect("relay url"));
            state
                .peer_endpoints
                .insert(crate::testing::nick(&format!("member{index}")), addr);
        }

        crate::transport::probe::retry_direct(&mut state, &ctx, false).await;

        assert_eq!(
            state.webrtc_admission.in_flight(),
            LANE_OFFERS_IN_FLIGHT,
            "the budget of rounds, not one per member"
        );
        let touched = members
            .iter()
            .filter(|id| state.direct.contains_key(*id))
            .count();
        assert_eq!(
            touched, LANE_OFFERS_IN_FLIGHT,
            "the members left out have no mark"
        );

        // The dials to a closed signal port would hold their slots for a long deadline.
        state.webrtc_admission.close();
        endpoint.close().await;
    }

    /// **A freed slot is filled.** With the budget spent, the top-up offers nothing. When one
    /// round ends, it offers to exactly one more of the members that were left out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_top_up_fills_the_slot_that_a_round_freed() {
        use crate::protocol::MeshId;
        use crate::protocol::identity::{Identity, encode_pubkey};
        use crate::util::tuning::LANE_OFFERS_IN_FLIGHT;

        let (endpoint, handle) = endpoint().await;
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let topic = gossip
            .subscribe(iroh_gossip::proto::TopicId::from_bytes([7u8; 32]), vec![])
            .await
            .expect("subscribe to a peerless topic");
        let (gossip_sender, _receiver) = topic.split();
        let sender = crate::transport::MeshSender::new(gossip_sender);
        let mesh = MeshId::from("test");
        let identity = Identity::generate();
        let our_pubkey = encode_pubkey(&identity.public());
        let author = crate::testing::nick("alice");
        let sink = crate::gossip::event::SilentSink;
        let ctx = crate::daemon::ctx::HandlerCtx {
            sender: &sender,
            endpoint: &endpoint,
            mesh: &mesh,
            author: &author,
            identity: &identity,
            our_pubkey: &our_pubkey,
            max_peers: 16,
            rendezvous_id: crate::testing::endpoint_id(99),
            external_msg_tx: None,
            sink: &sink,
        };
        let mut state = crate::testing::fresh_state();
        state.webrtc = Some(handle);
        state.local_udp_transport = true;
        state.relay_transport = false;
        state.unicast_pool = crate::transport::UnicastPool::new(endpoint.clone(), false);
        let members: Vec<EndpointId> = (1..=6).map(crate::testing::endpoint_id).collect();
        for (index, id) in members.iter().enumerate() {
            let addr = EndpointAddr::new(*id)
                .with_relay_url("https://relay.invalid".parse().expect("relay url"));
            state
                .peer_endpoints
                .insert(crate::testing::nick(&format!("member{index}")), addr);
        }

        crate::transport::probe::retry_direct(&mut state, &ctx, false).await;
        let touched = |node: &crate::daemon::state::EventLoopState| {
            members
                .iter()
                .filter(|id| node.direct.contains_key(*id))
                .count()
        };
        assert_eq!(touched(&state), LANE_OFFERS_IN_FLIGHT, "the first pass");

        crate::transport::probe::top_up_lane_offers(&mut state, &ctx).await;
        assert_eq!(
            touched(&state),
            LANE_OFFERS_IN_FLIGHT,
            "the budget is spent: the top-up offers nothing"
        );

        // One round ends: its slot is free.
        let offered = *members
            .iter()
            .find(|id| state.direct.contains_key(*id))
            .expect("an offered member");
        assert!(
            state.webrtc_admission.preempt_offer(offered),
            "a round to end"
        );
        crate::transport::probe::top_up_lane_offers(&mut state, &ctx).await;
        assert_eq!(
            touched(&state),
            LANE_OFFERS_IN_FLIGHT + 1,
            "one more member is offered"
        );
        assert_eq!(
            state.webrtc_admission.in_flight(),
            LANE_OFFERS_IN_FLIGHT,
            "the budget is spent again"
        );

        state.webrtc_admission.close();
        endpoint.close().await;
    }

    /// **Glare.** Both nodes of a pair offer at once. The lower id wins: the higher id gives its
    /// offer up when the offer of the lower id arrives, and answers it. The pair ends with exactly
    /// one session, and the offer that was given up is cancelled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_crossed_pair_ends_with_one_session_and_the_lower_id_wins() {
        let (first, first_hub) = endpoint().await;
        let (second, second_hub) = endpoint().await;
        let ((lower, lower_hub), (higher, higher_hub)) = if first.id() < second.id() {
            ((first, first_hub), (second, second_hub))
        } else {
            ((second, second_hub), (first, first_hub))
        };
        let lower_admission = SignalAdmission::new(8);
        let higher_admission = SignalAdmission::new(8);
        let lower_router = serve(&lower, &lower_hub, &lower_admission);
        let higher_router = serve(&higher, &higher_hub, &higher_admission);

        // The higher id has an offer to the lower id in flight that never ends on its own.
        let offer = higher_admission
            .try_admit_offer(lower.id(), &higher_hub)
            .expect("the higher id offers");
        let epoch = offer.epoch();
        let offering = tokio::spawn(async move {
            let _offer = offer;
            std::future::pending::<()>().await;
        });
        higher_admission.track(lower.id(), epoch, offering.abort_handle());

        dial_signal_with(
            &lower,
            higher.addr(),
            &lower_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await
        .expect("the offer of the lower id is answered");

        assert!(
            until(|| higher_hub.has_session(&lower.id())).await,
            "the higher id answered"
        );
        assert!(lower_hub.has_session(&higher.id()));
        assert_eq!(lower_hub.session_count(), 1);
        assert_eq!(higher_hub.session_count(), 1);
        assert!(
            offering
                .await
                .expect_err("the offer is cancelled")
                .is_cancelled(),
            "the higher id gave its offer up"
        );

        higher_router.shutdown().await.expect("shutdown");
        lower_router.shutdown().await.expect("shutdown");
        higher.close().await;
        lower.close().await;
    }

    /// **The answering side reports the attach.** A frame parked on the higher id of a crossed pair
    /// is flushed when the session attaches, although the node answered and did not offer: the
    /// answerer tells the event loop, through the table, which flushes what is held for the peer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_answering_side_reports_the_attach_to_the_event_loop() {
        let (first, first_hub) = endpoint().await;
        let (second, second_hub) = endpoint().await;
        let ((lower, lower_hub), (higher, higher_hub)) = if first.id() < second.id() {
            ((first, first_hub), (second, second_hub))
        } else {
            ((second, second_hub), (first, first_hub))
        };
        let higher_admission = SignalAdmission::new(8);
        let (sink, mut attached) = tokio::sync::mpsc::unbounded_channel();
        higher_admission.set_proven_sink(sink);
        let higher_router = serve(&higher, &higher_hub, &higher_admission);

        dial_signal_with(
            &lower,
            higher.addr(),
            &lower_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await
        .expect("the offer of the lower id is answered");

        let outcome = tokio::time::timeout(Duration::from_secs(5), attached.recv())
            .await
            .expect("the answerer reports the attach")
            .expect("the sink stays open");
        assert_eq!(outcome.peer, lower.id());
        assert!(outcome.direct && outcome.answered);

        higher_router.shutdown().await.expect("shutdown");
        higher.close().await;
        lower.close().await;
    }

    /// The loop acts on an answered session only when a frame is held for the peer.
    #[test]
    fn an_answered_session_is_applied_only_when_a_frame_is_held_for_the_peer() {
        use crate::transport::probe::DirectOutcome;

        let peer = crate::testing::endpoint_id(7);
        let now = crate::util::clock::Instant::now();
        let mut state = crate::testing::fresh_state();
        let answered = DirectOutcome {
            peer,
            direct: true,
            answered: true,
        };
        let offered = DirectOutcome {
            answered: false,
            ..answered
        };

        assert!(
            !answered.applies(&state, now),
            "nothing is held for the peer"
        );
        assert!(
            offered.applies(&state, now),
            "our own verdict always applies"
        );
        state.want_lane_session(peer, now);
        assert!(
            answered.applies(&state, now),
            "a frame is held for the peer"
        );
    }

    /// The offer of the lower id is refused as before when the round that runs is an answer, not
    /// an offer of the higher id.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_lower_id_still_refuses_a_crossed_offer() {
        let (first, first_hub) = endpoint().await;
        let (second, second_hub) = endpoint().await;
        let ((lower, lower_hub), (higher, higher_hub)) = if first.id() < second.id() {
            ((first, first_hub), (second, second_hub))
        } else {
            ((second, second_hub), (first, first_hub))
        };
        let lower_admission = SignalAdmission::new(8);
        let lower_router = serve(&lower, &lower_hub, &lower_admission);

        // The lower id has its own offer to the higher id in flight.
        let _offer = lower_admission
            .try_admit_offer(higher.id(), &lower_hub)
            .expect("the lower id offers");

        let outcome = dial_signal_with(
            &higher,
            lower.addr(),
            &higher_hub,
            quick(),
            IceProfile { host_only: true },
        )
        .await;

        assert!(outcome.is_err(), "the lower id keeps its own offer");
        assert_eq!(lower_hub.session_count(), 0);

        lower_router.shutdown().await.expect("shutdown");
        higher.close().await;
        lower.close().await;
    }

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
