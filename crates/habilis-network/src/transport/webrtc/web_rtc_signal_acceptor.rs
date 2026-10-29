//! The signal acceptor of the WebRTC plane: answers an inbound offer.

use super::ice_profile::IceProfile;
use super::nudge_acceptor;
use super::signal_deadlines::SignalDeadlines;

use anyhow::{Context, Result};
use habilis_network_iroh_webrtc_transport::{MAX_ENVELOPE_BYTES, SignalEnvelope, WebRtcHandle};
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};

use crate::transport::LOG_TARGET;
use crate::transport::admission::{Refusal, SignalAdmission};

use crate::lookup::EndpointError;

#[cfg(any(feature = "multihop", test))]
use super::close_code;
use super::close_code::{CAP_REFUSED, EVICTED, SIGNAL_ABORTED, SIGNAL_FAILED};

use crate::lookup;
use iroh::endpoint::ConnectionError;
use n0_future::{task, time};
/// Register `remote`'s `WebRTC` transport address after a session attach.
///
/// Load-bearing, not bookkeeping: an attached session is only *usable* once a
/// dial can name it — iroh fans a connect's Initial across the paths in the
/// peer's known addresses, and the custom-transport path exists nowhere else.
/// Without this registration every connection to a session-holding peer still
/// carried exactly one path, the relay, which the lookup-only accept gate then
/// (correctly) refused.
pub(crate) fn register_session_addr(book: &MemoryLookup, remote: EndpointId) {
    let address = EndpointAddr::from_parts(
        remote,
        [iroh::TransportAddr::Custom(
            habilis_network_iroh_webrtc_transport::custom_addr(remote),
        )],
    );
    lookup::add_peer_addr(book, address);
    tracing::debug!(target: LOG_TARGET, %remote, "registered the webrtc transport address");
}

/// The peer refused us: it is at its direct-peer ceiling. We back off for a
/// while.
///
/// A distinct type rather than a message, because the caller has to tell a
/// refusal from an ordinary failure and the two want opposite responses: a
/// refusal quiets this peer for a while, a transient failure is retried. Matching
/// on text could not do that — `anyhow`'s `Display` shows only the outermost
/// context, so the reason was hidden behind whichever step happened to fail.
/// The answerer of the multihop underlay turned our offer away because it holds no link vector
/// of ours yet. That is a race of two vectors that cross, not a verdict: the vector arrives a few
/// milliseconds after the offer, so the offerer tries again soon (see `underlay_webrtc`).
/// Write our envelope and wait for theirs, on an already-open connection.
///
/// Split out so the caller can consult the connection's close reason once for
/// the whole exchange rather than per step.
pub(crate) async fn exchange_envelopes(
    connection: &Connection,
    offer: &[u8],
    remote: EndpointId,
    deadlines: SignalDeadlines,
) -> Result<Vec<u8>> {
    let (mut send, mut recv) = connection.open_bi().await.context("open signal stream")?;
    send.write_all(offer).await.context("send signal offer")?;
    send.finish().context("finish signal stream")?;

    match time::timeout(deadlines.exchange, recv.read_to_end(MAX_ENVELOPE_BYTES)).await {
        Ok(raw) => raw.context("read signal answer"),
        Err(_elapsed) => {
            // Close explicitly so the answerer wakes now instead of waiting out
            // its own deadline on a round nobody is listening to any more.
            connection.close(SIGNAL_ABORTED.into(), b"signalling timed out");
            anyhow::bail!(
                "no signal answer from {remote} within {:?}",
                deadlines.exchange
            )
        }
    }
}

/// Whether the peer closed `conn` to tell us to back off: it refused at its cap (the code of
/// older peers), or it evicted us lately.
pub(crate) fn refused_at_cap(connection: &Connection) -> bool {
    matches!(
        connection.close_reason(),
        Some(ConnectionError::ApplicationClosed(ref close))
            if [u64::from(CAP_REFUSED), u64::from(EVICTED)].contains(&close.error_code.into_inner())
    )
}

/// Whether the underlay of the peer closed `conn` because we are not a neighbor of it yet.
#[cfg(any(feature = "multihop", test))]
pub(crate) fn refused_not_a_neighbor(connection: &Connection) -> bool {
    matches!(
        connection.close_reason(),
        Some(ConnectionError::ApplicationClosed(ref close))
            if close.error_code.into_inner() == u64::from(close_code::NOT_A_NEIGHBOR)
    )
}

/// The error of a failed exchange: the refusal that the close reason of `conn` names, or the
/// exchange's own cause.
pub(crate) fn with_refusal(
    connection: &Connection,
    error: anyhow::Error,
    remote: EndpointId,
) -> EndpointError {
    if refused_at_cap(connection) {
        return EndpointError::CapRefused {
            remote,
            source: error.into(),
        };
    }
    #[cfg(any(feature = "multihop", test))]
    if refused_not_a_neighbor(connection) {
        return EndpointError::NotANeighbor {
            remote,
            source: error.into(),
        };
    }
    EndpointError::internal(error)
}

/// The `ProtocolHandler` the Router runs for [`super::consts::MESH_WEBRTC_SIGNAL_ALPN`]: read
/// one offer, answer it, attach the resulting session to our hub.
///
/// Holds the hub rather than a channel to the event loop, deliberately. The
/// exchange is self-contained and the loop has nothing to decide about it — and
/// routing it through the loop would put a multi-second negotiation on the one
/// task that must never block.
///
/// # Examples
///
/// A WebRTC signal acceptor takes the signals that open a WebRTC session from a peer. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::net::direct::WebRtcSignalAcceptor;
///
/// # fn demo(acceptor: WebRtcSignalAcceptor) {
/// drop(acceptor);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct WebRtcSignalAcceptor {
    handle: WebRtcHandle,
    /// For registering the peer's transport address on attach; see
    /// [`register_session_addr`].
    endpoint: Endpoint,
    /// The address book of `endpoint`, where that address goes.
    book: MemoryLookup,
    local: EndpointId,
    /// Shared with the dialing side, so the ceiling is one number for the node
    /// rather than one per role.
    admission: SignalAdmission,
    deadlines: SignalDeadlines,
    /// How far ICE may reach — host-only on a loopback mesh.
    ice: IceProfile,
}

impl WebRtcSignalAcceptor {
    /// An acceptor that answers WebRTC offers. It shares `admission` with the dialing side, so the ceiling is one number per node.
    #[must_use]
    pub fn new(
        handle: WebRtcHandle,
        endpoint: Endpoint,
        book: MemoryLookup,
        local: EndpointId,
        admission: SignalAdmission,
        ice: IceProfile,
    ) -> Self {
        Self {
            handle,
            endpoint,
            book,
            local,
            admission,
            deadlines: SignalDeadlines::DEFAULT,
            ice,
        }
    }

    /// Shorten the deadlines, for tests that must not wait 45 real seconds.
    #[cfg(test)]
    pub(crate) fn deadlines(mut self, deadlines: SignalDeadlines) -> Self {
        self.deadlines = deadlines;
        self
    }
}

impl ProtocolHandler for WebRtcSignalAcceptor {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // The remote's identity comes from the *connection*, never from the
        // envelope. Over an authenticated carrier the TLS-proven id is the real
        // one, and trusting `SignalEnvelope::endpoint_id` instead would let any
        // peer attach a session under someone else's name — which, on a mesh
        // where sessions are keyed by peer, is impersonation rather than merely
        // a wasted negotiation.
        let remote = connection.remote_id();

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
                    Refusal::Denied => (SIGNAL_ABORTED, b"denied"),
                    Refusal::AtCapacity => (CAP_REFUSED, b"at capacity"),
                    Refusal::InFlight | Refusal::HaveSession | Refusal::Cooling => {
                        (SIGNAL_FAILED, b"already negotiating")
                    }
                };
                connection.close(code.into(), why);
                tracing::debug!(target: LOG_TARGET, %remote, ?reason, "refused a signal offer");
                return Ok(());
            }
        };

        let epoch = guard.epoch();
        let handle = self.handle.clone();
        let endpoint = self.endpoint.clone();
        let book = self.book.clone();
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
        let task = task::spawn(async move {
            let _guard = guard;
            // Boxed: the answer future carries the whole sans-io str0m state,
            // large enough that clippy flags it on this task's stack.
            match time::timeout(
                deadlines.round,
                Box::pin(answer_one(
                    &connection,
                    local,
                    remote,
                    &handle,
                    deadlines,
                    ice,
                )),
            )
            .await
            {
                Ok(Ok(())) => {
                    admission.note_success(remote);
                    admission.report_answered(remote);
                    register_session_addr(&book, remote);
                    admission.sync_gossip();
                    connection.close(0u32.into(), b"jsep done");
                    // A connection that we dialed before the attach moves onto the
                    // session only after a path event of our own endpoint, and the
                    // offerer's nudge gives us none: iroh opens a new path only
                    // from the client side of a connection.
                    let nudging = endpoint.clone();
                    task::spawn(async move {
                        nudge_acceptor::nudge_session(&nudging, remote).await;
                    });
                    tracing::debug!(target: LOG_TARGET, %remote, "webrtc session attached (answerer)");
                }
                // A failed negotiation is normal operation, not a fault: ICE
                // fails, peers vanish mid-handshake, a NAT refuses. The peer
                // stays reachable over whatever path it already had.
                Ok(Err(error)) => {
                    connection.close(SIGNAL_FAILED.into(), b"answer failed");
                    tracing::debug!(target: LOG_TARGET, %remote, %error, "webrtc answer failed");
                }
                Err(_elapsed) => {
                    connection.close(SIGNAL_ABORTED.into(), b"answer timed out");
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
pub(crate) async fn answer_one(
    connection: &Connection,
    local: EndpointId,
    remote: EndpointId,
    handle: &WebRtcHandle,
    deadlines: SignalDeadlines,
    ice: IceProfile,
) -> Result<()> {
    // Bounded: a peer that connects and never opens a stream would otherwise
    // park this task forever, and its QUIC keep-alives mean the connection
    // never idles out on its own.
    let (mut send, mut recv) = time::timeout(deadlines.exchange, connection.accept_bi())
        .await
        .context("timed out waiting for the signal stream")?
        .context("accept signal stream")?;
    let raw = time::timeout(deadlines.exchange, recv.read_to_end(MAX_ENVELOPE_BYTES))
        .await
        .context("timed out reading the signal offer")?
        .context("read signal offer")?;
    let offer: SignalEnvelope = serde_json::from_slice(&raw).context("parse signal offer")?;

    // Order is load-bearing: put the answer on the wire *before* completing the
    // negotiation. The offerer cannot finish ICE until it has our SDP, so
    // completing first deadlocks both sides into their full gathering budget
    // and then fails — which is exactly what it did.
    let answer = super::build_answer(local, &offer, ice).await?;
    send.write_all(&serde_json::to_vec(answer.envelope())?)
        .await
        .context("send signal answer")?;
    send.finish().context("finish signal stream")?;
    answer.complete(remote, handle).await
}
