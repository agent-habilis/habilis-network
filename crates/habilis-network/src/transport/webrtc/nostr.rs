//! JSEP over Nostr: the same offer and answer as the signal ALPN, carried as
//! sealed, signed events on public relays instead of over an iroh connection.
//!
//! It exists for the mesh with no iroh relay, where the ALPN has nothing to
//! ride on: two peers that have never connected cannot open a connection to
//! exchange the SDP that would let them connect.
//!
//! Identity is the one thing the ALPN got for free and Nostr does not: there
//! the remote id came from the TLS handshake, here it comes from `from`, which
//! [`Opener::open`] has checked against the sender's endpoint signature before
//! anything below reads it.
//!
//! Who offers is the caller's rule, as for the ALPN (the lower id, in
//! `negotiate_session`). Here two peers offering to each other at once each
//! refuse the other as `InFlight` and both rounds run to their deadline.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::protocol::nostr::{NostrKeys, Opener, Signal, SignalKind, seal};
use anyhow::{Context as _, Result};
use habilis_network_iroh_nostr_address_lookup::Pool;
use habilis_network_iroh_webrtc_transport::{SignalEnvelope, WebRtcHandle};
use iroh::{Endpoint, EndpointId, SecretKey};
use tokio::sync::{mpsc, oneshot};
use url::Url;

use super::super::LOG_TARGET;
use super::super::admission::{Refusal, SignalAdmission};
use super::{
    CapRefused, IceProfile, SignalDeadlines, build_answer, build_offer, register_session_addr,
};

/// Relays a node holds while it has no link, so a newcomer's first events
/// reach the relays incumbents listen on.
pub(crate) const JOINING_WIDTH: usize = 3;
/// Relays a linked node holds: the first healthy one in the shared ranking,
/// which every joiner also holds.
pub(crate) const LINKED_WIDTH: usize = 1;

/// When the `Hello`s go out, in seconds since the service started: fast while
/// a newcomer is likely alone, then every [`HELLO_STEADY`].
const HELLO_SCHEDULE_SECS: [u64; 9] = [0, 1, 3, 5, 10, 15, 20, 25, 30];
const HELLO_STEADY: std::time::Duration = std::time::Duration::from_mins(1);
/// A `Hello`'s addresses are explicit, so a slow probe is a failed one; the
/// data channel is the fallback.
const IP_PROBE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);
/// At most one wake-up `Hello` to a given peer this often.
const POKE_EVERY: std::time::Duration = std::time::Duration::from_secs(30);
/// A peer heard over Nostr this recently is offered to over Nostr.
const SEEN_FRESH: std::time::Duration = std::time::Duration::from_mins(5);
const HELLO_BACKLOG: usize = 64;
/// How long a node stays linked before it narrows to one relay, so a link
/// that flaps does not flap the relay set with it.
const LINK_SETTLE: std::time::Duration = std::time::Duration::from_secs(10);
/// Addresses a `Hello` carries; the codec refuses more.
const MAX_HELLO_ADDRS: usize = 8;

/// What the event loop needs to start the carrier: the mesh's Nostr keys and
/// its relays, ranked.
#[derive(Debug, Clone)]
pub(crate) struct NostrParams {
    pub(crate) keys: NostrKeys,
    pub(crate) relays: Vec<Url>,
}

impl NostrParams {
    /// `None` when the mesh has no Nostr lookup.
    pub(crate) fn for_mesh(
        lookups: &crate::protocol::LookupOpts,
        topic: &[u8; 32],
    ) -> Option<Self> {
        if lookups.nostr == crate::protocol::mesh::NostrChoice::Disabled {
            return None;
        }
        let keys = NostrKeys::derive(&crate::protocol::TopicId::from_bytes(*topic));
        let relays = keys.ranked_relays(&lookups.nostr);
        Some(Self { keys, relays })
    }
}

/// The Nostr signalling carrier for one mesh.
///
/// Dropping the last handle does not cut an answer short: each answer task
/// holds the carrier until its round ends, bounded by the round deadline and
/// abortable through admission.
#[derive(Clone)]
pub(crate) struct NostrSignal {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for NostrSignal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NostrSignal")
            .field("local", &self.inner.local)
            .finish_non_exhaustive()
    }
}

struct Inner {
    pool: Pool,
    keys: NostrKeys,
    secret: SecretKey,
    local: EndpointId,
    endpoint: Endpoint,
    handle: WebRtcHandle,
    admission: SignalAdmission,
    ice: IceProfile,
    deadlines: SignalDeadlines,
    /// See `NostrSignalParts::answers`.
    answers: bool,
    /// Offer rounds waiting for their answer.
    replies: Replies,
    _dispatch: n0_future::task::AbortOnDropHandle<()>,
}

/// What a [`NostrSignal`] needs from the node it serves.
pub(crate) struct NostrSignalParts {
    pub(crate) endpoint: Endpoint,
    pub(crate) handle: WebRtcHandle,
    pub(crate) admission: SignalAdmission,
    pub(crate) ice: IceProfile,
    pub(crate) keys: NostrKeys,
    /// Ranked the same way by every member (`NostrKeys::ranked_relays`).
    pub(crate) relays: Vec<Url>,
    /// `TransportOpts::webrtc`. Off, the carrier still finds peers and still
    /// offers nothing, and it answers no offer: a session would attach into a
    /// transport the endpoint never registered.
    pub(crate) answers: bool,
}

impl NostrSignal {
    /// Subscribe to the room and to our own tag, and start answering offers.
    /// `Hello`s are handed to the returned receiver: discovery is the caller's.
    pub(crate) fn start(parts: NostrSignalParts) -> (Self, mpsc::Receiver<Signal>) {
        Self::start_with(parts, SignalDeadlines::DEFAULT)
    }

    pub(crate) fn start_with(
        parts: NostrSignalParts,
        deadlines: SignalDeadlines,
    ) -> (Self, mpsc::Receiver<Signal>) {
        let local = parts.endpoint.id();
        let secret = parts.endpoint.secret_key().clone();
        let (pool, events) = Pool::open(
            parts.relays,
            JOINING_WIDTH,
            &[parts.keys.room_tag(), parts.keys.self_tag(&local)],
        );
        // Bounded: `Hello`s repeat on a timer, so one dropped while the loop
        // is busy costs nothing.
        let (hellos_tx, hellos) = mpsc::channel(HELLO_BACKLOG);
        let inner = Arc::new_cyclic(|weak: &std::sync::Weak<Inner>| {
            let dispatch = n0_future::task::spawn(dispatch(
                weak.clone(),
                events,
                Opener::new(parts.keys.clone(), local),
                hellos_tx,
            ));
            Inner {
                pool,
                keys: parts.keys,
                secret,
                local,
                endpoint: parts.endpoint,
                handle: parts.handle,
                admission: parts.admission,
                ice: parts.ice,
                deadlines,
                answers: parts.answers,
                replies: Replies::default(),
                _dispatch: n0_future::task::AbortOnDropHandle::new(dispatch),
            }
        });
        (Self { inner }, hellos)
    }

    /// Publish a signal from us. `to` set ⇒ on the addressee's own tag,
    /// otherwise on the room tag.
    pub(crate) fn send(&self, signal: &Signal) {
        let tag = signal.to.map_or_else(
            || self.inner.keys.room_tag(),
            |to| self.inner.keys.self_tag(&to),
        );
        self.inner
            .pool
            .publish(&tag, seal(&self.inner.keys, &self.inner.secret, signal));
    }

    /// A signal from us, stamped now.
    pub(crate) fn signal(&self, kind: SignalKind) -> Signal {
        Signal::new(kind, self.inner.local, now())
    }

    /// How many relays to hold; see `Pool::set_width`.
    pub(crate) fn set_width(&self, width: usize) {
        self.inner.pool.set_width(width);
    }

    /// Offer a session to `peer` over Nostr and attach it. The caller holds
    /// the admission slot for the round, as for the ALPN.
    ///
    /// # Errors
    /// No answer before the deadline, a refusal ([`CapRefused`]), or a
    /// negotiation that does not complete.
    pub(crate) async fn offer(&self, peer: EndpointId) -> Result<()> {
        let inner = &self.inner;
        match n0_future::time::timeout(inner.deadlines.round, Box::pin(self.offer_round(peer)))
            .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                anyhow::bail!(
                    "nostr signalling with {peer} exceeded {:?}",
                    inner.deadlines.round
                )
            }
        }
    }

    async fn offer_round(&self, peer: EndpointId) -> Result<()> {
        let inner = &self.inner;
        let offer = build_offer(inner.local, &inner.handle, inner.ice).await?;
        let mut signal = self.signal(SignalKind::Offer);
        signal.to = Some(peer);
        signal.envelope = Some(serde_json::to_string(offer.envelope())?);
        // Registered before the offer goes out, so the answer cannot beat it.
        let (_pending, reply) = expect_reply(&inner.replies, signal.nonce, peer);
        self.send(&signal);
        let reply = n0_future::time::timeout(inner.deadlines.exchange, reply)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "no answer from {peer} within {:?}",
                    inner.deadlines.exchange
                )
            })?
            .context("offer round dropped")?;
        if reply.kind == SignalKind::Refuse {
            return Err(anyhow::Error::new(CapRefused(peer)));
        }
        let answer: SignalEnvelope = serde_json::from_str(
            reply
                .envelope
                .as_deref()
                .context("an answer with no envelope")?,
        )
        .context("parse signal answer")?;
        offer
            .with_answer(answer)
            .complete(peer, &inner.handle)
            .await?;
        register_session_addr(&inner.endpoint, peer);
        tracing::debug!(target: LOG_TARGET, %peer, "webrtc session attached (offerer, nostr)");
        Ok(())
    }
}

/// Offer rounds waiting for their reply: the offer's nonce, the peer it went
/// to, and where to hand the reply.
type Replies = Arc<Mutex<HashMap<[u8; 16], (EndpointId, oneshot::Sender<Signal>)>>>;

/// A registered wait. Dropping it forgets the wait, however the round ends,
/// including when the round's own deadline cancels it mid-wait.
struct Pending {
    replies: Replies,
    nonce: [u8; 16],
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.replies
            .lock()
            .expect("replies map poisoned")
            .remove(&self.nonce);
    }
}

fn expect_reply(
    replies: &Replies,
    nonce: [u8; 16],
    peer: EndpointId,
) -> (Pending, oneshot::Receiver<Signal>) {
    let (sender, receiver) = oneshot::channel();
    replies
        .lock()
        .expect("replies map poisoned")
        .insert(nonce, (peer, sender));
    let pending = Pending {
        replies: Arc::clone(replies),
        nonce,
    };
    (pending, receiver)
}

/// Discovery: what the event loop does with the carrier.
///
/// Every member announces a `Hello` on the room tag. A `Hello` from a peer we
/// hold nothing with starts a link: an IP probe when both ends have IP and the
/// peer gave addresses, else (or when the probe fails) a data channel offered
/// over Nostr by the lower id. The higher id wakes the lower one with a
/// `Hello` on its own tag instead. Every path ends in a `DirectOutcome`, which
/// the loop turns into a gossip graft.
pub(crate) mod discovery {
    use iroh::{EndpointAddr, TransportAddr};

    use super::{
        EndpointId, HELLO_SCHEDULE_SECS, HELLO_STEADY, IP_PROBE_DEADLINE, JOINING_WIDTH,
        LINK_SETTLE, LINKED_WIDTH, LOG_TARGET, MAX_HELLO_ADDRS, NostrSignal, POKE_EVERY,
        SEEN_FRESH, Signal, SignalAdmission, SignalKind,
    };
    use crate::daemon::ctx::HandlerCtx;
    use crate::daemon::state::{DirectState, EventLoopState};
    use crate::transport::probe::DirectOutcome;
    use crate::util::clock::Instant;
    use n0_future::time::Instant as TokioInstant;

    /// Announce ourselves, and schedule the next announce.
    pub(crate) fn announce(state: &mut EventLoopState, ctx: &HandlerCtx<'_>) {
        let Some(nostr) = state.nostr.clone() else {
            state.next_hello = None;
            return;
        };
        let mut hello = nostr.signal(SignalKind::Hello);
        hello.webrtc = !state.local_udp_transport;
        if state.local_udp_transport {
            hello.addrs = ctx
                .endpoint
                .addr()
                .ip_addrs()
                .copied()
                .take(MAX_HELLO_ADDRS)
                .collect();
        }
        nostr.send(&hello);
        let sent = state.hellos_sent;
        state.hellos_sent = sent.saturating_add(1);
        let next = HELLO_SCHEDULE_SECS
            .get(sent as usize + 1)
            .zip(HELLO_SCHEDULE_SECS.get(sent as usize))
            .map_or(HELLO_STEADY, |(next, now)| {
                std::time::Duration::from_secs(next - now)
            });
        if next == HELLO_STEADY {
            // A Hello on our own tag, which we subscribe to: its echo is what
            // tells the pool a relay still carries directed events, which the
            // room tag's echo cannot.
            let mut probe = nostr.signal(SignalKind::Hello);
            probe.to = Some(ctx.endpoint.id());
            nostr.send(&probe);
        }
        state.next_hello = Some(TokioInstant::now() + next);
        update_width(state);
    }

    /// What a `Hello` from a peer calls for.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum HelloAction {
        Nothing,
        /// A path exists but the peer is not in the overlay: graft it.
        Graft,
        /// Both ends have IP and the peer gave addresses: try them first.
        Probe,
        /// A data channel is needed and we are the lower id: offer it.
        Offer,
        /// A data channel is needed and the peer offers: wake it.
        Poke,
    }

    /// Decide what a `Hello` calls for. Pure, so the rules can be tested.
    pub(crate) fn hello_action(
        state: &EventLoopState,
        local: EndpointId,
        hello: &Signal,
        now: Instant,
    ) -> HelloAction {
        let peer = hello.from;
        let has_session = state
            .webrtc
            .as_ref()
            .is_some_and(|handle| handle.has_session(&peer));
        if state.linked_endpoints.contains(&peer) {
            return HelloAction::Nothing;
        }
        // A path without a link: the graft failed or the view was full. The
        // loop's graft path checks the room again.
        if has_session || state.direct.get(&peer) == Some(&DirectState::Direct) {
            return HelloAction::Graft;
        }
        let addr = hello_addr(hello);
        if !hello.webrtc && !crate::transport::webrtc::peer_needs_lane(state, peer, &addr) {
            // No addresses from a peer with IP means it has not found its own
            // yet; its next `Hello` is a second or two away.
            if addr.is_empty() || state.direct.get(&peer) == Some(&DirectState::Pending) {
                return HelloAction::Nothing;
            }
            return HelloAction::Probe;
        }
        if local < peer {
            HelloAction::Offer
        } else if state
            .nostr_poked
            .get(&peer)
            .is_none_or(|at| now.duration_since(*at) >= POKE_EVERY)
        {
            HelloAction::Poke
        } else {
            HelloAction::Nothing
        }
    }

    fn hello_addr(hello: &Signal) -> EndpointAddr {
        EndpointAddr::from_parts(
            hello.from,
            hello.addrs.iter().copied().map(TransportAddr::Ip),
        )
    }

    /// A peer announced itself over Nostr; see the module note above.
    pub(crate) fn on_hello(state: &mut EventLoopState, ctx: &HandlerCtx<'_>, hello: &Signal) {
        let peer = hello.from;
        let now = Instant::now();
        state.nostr_seen.insert(peer, now);
        // Signed by the peer's endpoint key (the opener checked), so its word
        // on needing a data channel is as good as a `PeerInfo`'s.
        if hello.webrtc {
            state.lane_peers.insert(peer);
        } else {
            state.lane_peers.remove(&peer);
        }
        state.known_endpoints.insert(peer);
        match hello_action(state, ctx.endpoint.id(), hello, now) {
            HelloAction::Nothing => {}
            HelloAction::Graft => {
                let _ = state
                    .direct_proven
                    .send(DirectOutcome { peer, direct: true });
            }
            HelloAction::Probe => probe_then_offer(state, ctx, hello_addr(hello)),
            HelloAction::Offer => offer(state, peer),
            HelloAction::Poke => {
                state.nostr_poked.insert(peer, now);
                if let Some(nostr) = state.nostr.as_ref() {
                    let mut wake = nostr.signal(SignalKind::Hello);
                    wake.to = Some(peer);
                    wake.webrtc = !state.local_udp_transport;
                    nostr.send(&wake);
                }
            }
        }
    }

    /// Forget peers heard over Nostr who went quiet, so the maps are bounded
    /// by the mesh rather than by its history.
    pub(crate) fn prune(state: &mut EventLoopState, now: Instant) {
        state
            .nostr_seen
            .retain(|_, at| now.duration_since(*at) < SEEN_FRESH);
        state
            .nostr_poked
            .retain(|_, at| now.duration_since(*at) < SEEN_FRESH);
    }

    /// Try the peer's IP addresses; if they fail and we are the lower id,
    /// offer a data channel over Nostr.
    fn probe_then_offer(state: &mut EventLoopState, ctx: &HandlerCtx<'_>, addr: EndpointAddr) {
        let peer = addr.id;
        let _ = crate::lookup::add_peer_addr(ctx.endpoint, addr);
        state.direct.insert(peer, DirectState::Pending);
        let pool = state.unicast_pool.clone();
        let proven = state.direct_proven.clone();
        let fallback = (ctx.endpoint.id() < peer)
            .then(|| Some((state.nostr.clone()?, state.webrtc.clone()?)))
            .flatten();
        let admission = state.webrtc_admission.clone();
        n0_future::task::spawn(async move {
            let direct = match pool.warm_or_dial(peer).await {
                Ok(conn) => crate::transport::path::wait_direct(&conn, IP_PROBE_DEADLINE).await,
                Err(_) => false,
            };
            if direct {
                tracing::info!(target: LOG_TARGET, %peer, "linked over IP, found through nostr");
                let _ = proven.send(DirectOutcome { peer, direct: true });
                return;
            }
            let attached = match fallback {
                Some((nostr, handle)) => match admission.try_admit(peer, &handle) {
                    // Its own task, tracked, so shutdown can abort the round.
                    Ok(guard) => {
                        let round_admission = admission.clone();
                        let round = n0_future::task::spawn(async move {
                            let _guard = guard;
                            run_offer(&nostr, &round_admission, peer).await
                        });
                        admission.track(peer, round.abort_handle());
                        round.await.unwrap_or(false)
                    }
                    Err(_) => false,
                },
                None => false,
            };
            let _ = proven.send(DirectOutcome {
                peer,
                direct: attached,
            });
        });
    }

    /// Offer a data channel to `peer` over Nostr, if admission lets us.
    pub(crate) fn offer(state: &mut EventLoopState, peer: EndpointId) {
        let Some(handle) = state.webrtc.clone() else {
            return;
        };
        let Ok(guard) = state.webrtc_admission.try_admit(peer, &handle) else {
            return;
        };
        // A `Hello` offers only to a pair that needs the lane.
        spawn_offer(state, peer, guard, super::super::Offer::Lane);
    }

    /// Run an admitted offer round over Nostr and report an attach as a proven
    /// path. Shared with `negotiate_session`'s Nostr branch.
    pub(crate) fn spawn_offer(
        state: &mut EventLoopState,
        peer: EndpointId,
        guard: crate::transport::admission::AdmissionGuard,
        offer: super::super::Offer,
    ) {
        let Some(nostr) = state.nostr.clone() else {
            return;
        };
        let admission = state.webrtc_admission.clone();
        let proven = state.direct_proven.clone();
        let pool = state.unicast_pool.clone();
        let task = n0_future::task::spawn(async move {
            let _guard = guard;
            let inner = &nostr.inner;
            if run_offer(&nostr, &admission, peer).await
                && super::super::keeps_session(offer, &inner.endpoint, &pool, &inner.handle, peer)
                    .await
            {
                let _ = proven.send(DirectOutcome { peer, direct: true });
            }
        });
        state.webrtc_admission.track(peer, task.abort_handle());
    }

    async fn run_offer(nostr: &NostrSignal, admission: &SignalAdmission, peer: EndpointId) -> bool {
        match Box::pin(nostr.offer(peer)).await {
            Ok(()) => {
                tracing::info!(target: LOG_TARGET, %peer, "webrtc session attached (nostr)");
                true
            }
            Err(error) => {
                if super::super::is_cap_refusal(&error) {
                    admission.note_refused(peer);
                }
                tracing::debug!(target: LOG_TARGET, %peer, %error, "nostr offer failed");
                false
            }
        }
    }

    /// Whether to offer to `peer` over Nostr rather than the signal ALPN: we
    /// heard it over Nostr lately, or the mesh has no rendezvous for the ALPN
    /// to reach it through.
    pub(crate) fn prefer_nostr(state: &EventLoopState, peer: EndpointId) -> bool {
        state.nostr.is_some()
            && (!state.has_rendezvous
                || state
                    .nostr_seen
                    .get(&peer)
                    .is_some_and(|at| at.elapsed() < SEEN_FRESH))
    }

    /// How many relays to hold now: 3 while unlinked and for [`LINK_SETTLE`]
    /// after, then 1. A hidden browser tab holds 1: it saves the sockets, and
    /// the first-ranked relay is the one every member listens on.
    pub(crate) fn target_width(state: &EventLoopState, now: Instant, hidden: bool) -> usize {
        let wide = needs_wide(state) || state.nostr_wide_until.is_some_and(|until| now < until);
        if wide && !hidden {
            JOINING_WIDTH
        } else {
            LINKED_WIDTH
        }
    }

    /// A Worker has no `window`, and reads as visible.
    #[cfg(target_arch = "wasm32")]
    fn tab_hidden() -> bool {
        web_sys::window()
            .and_then(|window| window.document())
            .is_some_and(|document| document.visibility_state() == web_sys::VisibilityState::Hidden)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn tab_hidden() -> bool {
        false
    }

    /// Only an unlinked node needs the wide set. An offer round does not: the
    /// joiner holds our first-ranked relay too, so offers reach it at width 1,
    /// and widening per round would re-dial relays on every join.
    fn needs_wide(state: &EventLoopState) -> bool {
        state.linked_endpoints.is_empty()
    }

    /// Adjust the relay set and forget quiet peers; run on gossip events,
    /// alive ticks and announces. The wide set outlives the last unlinked
    /// moment by [`LINK_SETTLE`].
    pub(crate) fn update_width(state: &mut EventLoopState) {
        let now = Instant::now();
        prune(state, now);
        if needs_wide(state) {
            state.nostr_wide_until = Some(now + LINK_SETTLE);
        }
        let width = target_width(state, now, tab_hidden());
        let Some(nostr) = state.nostr.as_ref() else {
            return;
        };
        if width != state.nostr_width {
            state.nostr_width = width;
            nostr.set_width(width);
        }
    }
}

/// Hand a reply to the round waiting on its `re`, if it came from the peer
/// that round offered to. Checked before the wait is taken: every member can
/// read an offer's nonce off the addressee's tag, and a wait consumed by the
/// wrong sender would end the round before the real answer lands.
fn deliver_reply(replies: &Replies, reply: Signal) {
    let Some(nonce) = reply.re else { return };
    let mut waiting = replies.lock().expect("replies map poisoned");
    if waiting
        .get(&nonce)
        .is_none_or(|(peer, _)| *peer != reply.from)
    {
        return;
    }
    if let Some((_peer, sender)) = waiting.remove(&nonce) {
        let _ = sender.send(reply);
    }
}

fn now() -> u64 {
    u64::try_from(crate::util::clock::unix_secs()).unwrap_or(0)
}

/// Open every event the pool delivers and route it: replies to the round
/// waiting on them, offers to an answer, hellos to the caller.
async fn dispatch(
    inner: std::sync::Weak<Inner>,
    mut events: mpsc::UnboundedReceiver<habilis_network_iroh_nostr_address_lookup::Event>,
    mut opener: Opener,
    hellos: mpsc::Sender<Signal>,
) {
    while let Some(event) = events.recv().await {
        let signal = match opener.open(&event.content, now()) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::debug!(target: LOG_TARGET, %error, "dropped a nostr signal");
                continue;
            }
        };
        let Some(inner) = inner.upgrade() else { return };
        match signal.kind {
            SignalKind::Hello => {
                let _ = hellos.try_send(signal);
            }
            SignalKind::Answer | SignalKind::Refuse => {
                deliver_reply(&inner.replies, signal);
            }
            SignalKind::Offer => answer(&inner, signal),
        }
    }
}

/// Answer an offer: the ALPN acceptor's rules, with `from` in place of the
/// TLS-proven id.
fn answer(inner: &Arc<Inner>, offer: Signal) {
    let remote = offer.from;
    if !inner.answers {
        tracing::debug!(target: LOG_TARGET, %remote, "ignored a nostr offer: webrtc is off");
        return;
    }
    // A signed re-offer from a peer we hold a session with means its half is
    // gone; see `WebRtcSignalAcceptor::accept`. Safe on the signature alone.
    if inner.handle.has_session(&remote) && inner.handle.detach(&remote) {
        tracing::debug!(target: LOG_TARGET, %remote, "detached a half-dead session on a fresh nostr offer");
    }
    let guard = match inner.admission.try_admit(remote, &inner.handle) {
        Ok(guard) => guard,
        Err(reason) => {
            // Self-limiting, though it looks like an amplifier: the offerer
            // notes the refusal and cools off, so one offer earns one Refuse.
            if reason == Refusal::AtCap {
                let mut refuse = Signal::new(SignalKind::Refuse, inner.local, now());
                refuse.to = Some(remote);
                refuse.re = Some(offer.nonce);
                publish(inner, &refuse);
            }
            tracing::debug!(target: LOG_TARGET, %remote, ?reason, "refused a nostr offer");
            return;
        }
    };
    let this = Arc::clone(inner);
    let task = n0_future::task::spawn(async move {
        let _guard = guard;
        let round = async {
            let envelope: SignalEnvelope = serde_json::from_str(
                offer
                    .envelope
                    .as_deref()
                    .context("an offer with no envelope")?,
            )
            .context("parse signal offer")?;
            let answer = build_answer(this.local, &envelope, this.ice).await?;
            let mut reply = Signal::new(SignalKind::Answer, this.local, now());
            reply.to = Some(remote);
            reply.re = Some(offer.nonce);
            reply.envelope = Some(serde_json::to_string(answer.envelope())?);
            // The answer goes out before we complete: the offerer cannot
            // finish ICE without our SDP. The same rule as `answer_one`, whose
            // tail this mirrors; change the two together.
            publish(&this, &reply);
            answer.complete(remote, &this.handle).await
        };
        match n0_future::time::timeout(this.deadlines.round, Box::pin(round)).await {
            Ok(Ok(())) => {
                register_session_addr(&this.endpoint, remote);
                tracing::debug!(target: LOG_TARGET, %remote, "webrtc session attached (answerer, nostr)");
            }
            Ok(Err(error)) => {
                tracing::debug!(target: LOG_TARGET, %remote, %error, "nostr answer failed");
            }
            Err(_elapsed) => {
                tracing::debug!(target: LOG_TARGET, %remote, "nostr answer timed out");
            }
        }
    });
    inner.admission.track(remote, task.abort_handle());
}

fn publish(inner: &Inner, signal: &Signal) {
    let tag = signal
        .to
        .map_or_else(|| inner.keys.room_tag(), |to| inner.keys.self_tag(&to));
    inner
        .pool
        .publish(&tag, seal(&inner.keys, &inner.secret, signal));
}

// Host-only: real endpoints with only the WebRTC transport (no IP, no relay)
// and an in-process Nostr relay.
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use habilis_network_iroh_nostr_address_lookup::test_relay::TestRelay;
    use habilis_network_iroh_webrtc_transport::WebRtcTransport;
    use iroh::endpoint::presets;
    use iroh::{EndpointAddr, RelayMode, TransportAddr};

    use super::*;
    use crate::protocol::TopicId;
    use crate::transport::MAX_DIRECT_PEERS;

    const ECHO_ALPN: &[u8] = b"test/nostr-echo";

    fn quick() -> SignalDeadlines {
        SignalDeadlines {
            exchange: Duration::from_secs(8),
            round: Duration::from_secs(20),
        }
    }

    /// An endpoint that can reach nothing but a `WebRTC` session: no IP, no
    /// relay, no address lookup.
    async fn webrtc_only() -> (Endpoint, WebRtcHandle) {
        let key = SecretKey::generate();
        let handle = WebRtcHandle::new(WebRtcTransport::new(key.public()));
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .clear_address_lookup()
            .add_custom_transport(handle.transport())
            .alpns(vec![ECHO_ALPN.to_vec()])
            .bind()
            .await
            .expect("bind a webrtc-only endpoint");
        (endpoint, handle)
    }

    struct Node {
        endpoint: Endpoint,
        handle: WebRtcHandle,
        admission: SignalAdmission,
        signal: NostrSignal,
    }

    async fn node(relay: &TestRelay, topic: [u8; 32], cap: usize) -> Node {
        node_with(relay, topic, cap, true).await
    }

    async fn node_with(relay: &TestRelay, topic: [u8; 32], cap: usize, answers: bool) -> Node {
        let (endpoint, handle) = webrtc_only().await;
        node_on(endpoint, handle, relay, topic, cap, answers)
    }

    /// An endpoint with loopback UDP beside the `WebRTC` session, the shape of
    /// a native pair that races the two. It accepts every connection and
    /// holds it, so the unicast dial and the nudge land.
    async fn udp_and_webrtc() -> (Endpoint, WebRtcHandle) {
        let key = SecretKey::generate();
        let handle = WebRtcHandle::new(WebRtcTransport::new(key.public()));
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .add_custom_transport(handle.transport())
            .path_selector(handle.path_selector())
            .alpns(vec![
                crate::transport::UNICAST_ALPN.to_vec(),
                super::super::NUDGE_ALPN.to_vec(),
            ])
            .bind()
            .await
            .expect("bind a udp and webrtc endpoint");
        let server = endpoint.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(incoming) = server.accept().await {
                if let Ok(conn) = incoming.await {
                    held.push(conn);
                }
            }
        });
        (endpoint, handle)
    }

    fn loopback_addr(endpoint: &Endpoint) -> EndpointAddr {
        let addrs = endpoint
            .bound_sockets()
            .into_iter()
            .filter(std::net::SocketAddr::is_ipv4)
            .map(|socket| {
                TransportAddr::Ip(std::net::SocketAddr::new(
                    std::net::Ipv4Addr::LOCALHOST.into(),
                    socket.port(),
                ))
            });
        EndpointAddr::from_parts(endpoint.id(), addrs)
    }

    fn node_on(
        endpoint: Endpoint,
        handle: WebRtcHandle,
        relay: &TestRelay,
        topic: [u8; 32],
        cap: usize,
        answers: bool,
    ) -> Node {
        let admission = SignalAdmission::new(cap);
        let (signal, _hellos) = NostrSignal::start_with(
            NostrSignalParts {
                endpoint: endpoint.clone(),
                handle: handle.clone(),
                admission: admission.clone(),
                ice: IceProfile { host_only: true },
                keys: NostrKeys::derive(&TopicId::from_bytes(topic)),
                relays: vec![relay.url()],
                answers,
            },
            quick(),
        );
        Node {
            endpoint,
            handle,
            admission,
            signal,
        }
    }

    /// Wait until both pools hold the relay, so the first offer is not
    /// published before the answerer subscribes.
    async fn settled(relay: &TestRelay) {
        for _ in 0..100 {
            if relay.connections() >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    async fn offer(from: &Node, to: &Node) -> Result<()> {
        let peer = to.endpoint.id();
        let _guard = from
            .admission
            .try_admit(peer, &from.handle)
            .map_err(|reason| anyhow::anyhow!("not admitted: {reason:?}"))?;
        from.signal.offer(peer).await
    }

    /// Bytes over QUIC on the session, the only path either endpoint has.
    async fn echo(from: &Node, to: &Node) {
        let server = to.endpoint.clone();
        let accept = tokio::spawn(async move {
            let conn = server
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("accept");
            let (mut send, mut recv) = conn.accept_bi().await.expect("stream");
            let bytes = recv.read_to_end(64).await.expect("read");
            send.write_all(&bytes).await.expect("write");
            send.finish().expect("finish");
            conn.closed().await;
        });
        let addr = EndpointAddr::from_parts(
            to.endpoint.id(),
            [TransportAddr::Custom(
                habilis_network_iroh_webrtc_transport::custom_addr(to.endpoint.id()),
            )],
        );
        let conn = from
            .endpoint
            .connect(addr, ECHO_ALPN)
            .await
            .expect("connect over webrtc");
        let (mut send, mut recv) = conn.open_bi().await.expect("open");
        send.write_all(b"over nostr-signalled webrtc")
            .await
            .expect("write");
        send.finish().expect("finish");
        assert_eq!(
            recv.read_to_end(64).await.expect("read"),
            b"over nostr-signalled webrtc"
        );
        conn.close(0u32.into(), b"done");
        accept.abort();
    }

    fn reply(kind: SignalKind, from: EndpointId, re: [u8; 16]) -> Signal {
        let mut signal = Signal::new(kind, from, now());
        signal.re = Some(re);
        signal
    }

    /// Every member can read an offer's nonce off the addressee's tag. A reply
    /// from anyone but the addressee must not consume the wait, or one signed
    /// reply from any member ends any round.
    #[test]
    fn a_reply_from_a_third_member_does_not_take_the_wait() {
        let replies = Replies::default();
        let bob = SecretKey::generate().public();
        let mallory = SecretKey::generate().public();
        let (_pending, mut reply_rx) = expect_reply(&replies, [7u8; 16], bob);

        deliver_reply(&replies, reply(SignalKind::Answer, mallory, [7u8; 16]));
        assert!(reply_rx.try_recv().is_err(), "mallory's reply is ignored");

        deliver_reply(&replies, reply(SignalKind::Answer, bob, [7u8; 16]));
        assert_eq!(reply_rx.try_recv().expect("bob's reply lands").from, bob);
    }

    /// However the round ends, its wait is forgotten.
    #[test]
    fn a_dropped_wait_is_forgotten() {
        let replies = Replies::default();
        let (pending, _reply_rx) =
            expect_reply(&replies, [8u8; 16], SecretKey::generate().public());
        drop(pending);
        assert!(replies.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_nostr_round_attaches_a_session_with_no_iroh_path() {
        let relay = TestRelay::spawn().await.unwrap();
        let alice = node(&relay, [1u8; 32], MAX_DIRECT_PEERS).await;
        let bob = node(&relay, [1u8; 32], MAX_DIRECT_PEERS).await;
        settled(&relay).await;

        offer(&alice, &bob).await.expect("the nostr round attaches");
        assert!(alice.handle.has_session(&bob.endpoint.id()));
        for _ in 0..50 {
            if bob.handle.has_session(&alice.endpoint.id()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(bob.handle.has_session(&alice.endpoint.id()));
        echo(&alice, &bob).await;
    }

    /// One Nostr offer round from `from` to `to` as the event loop runs it,
    /// with UDP pooled beside it. Returns once the round has let go of its
    /// admission slot: whether a session is left, and whether the round
    /// reported a proven path.
    async fn race_round(from: &Node, to: &Node, offer: super::super::Offer) -> (bool, bool) {
        let peer = to.endpoint.id();
        let mut state = crate::testing::fresh_state();
        let pool = crate::transport::UnicastPool::new(from.endpoint.clone(), false);
        pool.note_addr(&loopback_addr(&to.endpoint));
        state.unicast_pool = pool;
        state.nostr = Some(from.signal.clone());
        state.webrtc = Some(from.handle.clone());
        state.webrtc_admission = from.admission.clone();
        let (proven_tx, mut proven_rx) = mpsc::unbounded_channel();
        state.direct_proven = proven_tx;
        let guard = from
            .admission
            .try_admit(peer, &from.handle)
            .expect("admitted");
        discovery::spawn_offer(&mut state, peer, guard, offer);
        for _ in 0..400 {
            if !from.admission.negotiating(peer) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!from.admission.negotiating(peer), "the round must end");
        let proven = proven_rx
            .try_recv()
            .is_ok_and(|outcome| outcome.peer == peer);
        (from.handle.has_session(&peer), proven)
    }

    /// A pair with UDP on both ends races the data channel against the punch,
    /// over Nostr as over the signal ALPN. UDP is selected on loopback at
    /// once, so the session the round attached must be detached, not kept
    /// holding a direct-peer slot. A lane round on the same pair is the
    /// control: it keeps its session, so the race round did attach one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_udp_race_over_nostr_detaches_the_session_once_udp_won() {
        let relay = TestRelay::spawn().await.unwrap();
        let (alice_endpoint, alice_handle) = udp_and_webrtc().await;
        let alice = node_on(
            alice_endpoint,
            alice_handle,
            &relay,
            [9u8; 32],
            MAX_DIRECT_PEERS,
            true,
        );
        let (bob_endpoint, bob_handle) = udp_and_webrtc().await;
        let bob = node_on(
            bob_endpoint,
            bob_handle,
            &relay,
            [9u8; 32],
            MAX_DIRECT_PEERS,
            true,
        );
        settled(&relay).await;

        let (race_kept, race_proven) = race_round(&alice, &bob, super::super::Offer::UdpRace).await;
        assert!(!race_kept, "udp won, so the data channel must be detached");
        assert!(!race_proven, "a detached session proves no path");

        let (lane_kept, lane_proven) = race_round(&alice, &bob, super::super::Offer::Lane).await;
        assert!(
            lane_kept && lane_proven,
            "a lane round keeps its session (kept {lane_kept}, proven {lane_proven})"
        );
    }

    /// Alice lost her half; her signed re-offer must replace Bob's stale half
    /// rather than be refused as "already have a session".
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_signed_reoffer_replaces_a_half_dead_session() {
        let relay = TestRelay::spawn().await.unwrap();
        let alice = node(&relay, [2u8; 32], MAX_DIRECT_PEERS).await;
        let bob = node(&relay, [2u8; 32], MAX_DIRECT_PEERS).await;
        settled(&relay).await;
        offer(&alice, &bob).await.expect("first round");
        for _ in 0..50 {
            if bob.handle.has_session(&alice.endpoint.id()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert!(alice.handle.detach(&bob.endpoint.id()));
        offer(&alice, &bob).await.expect("the re-offer attaches");
        echo(&alice, &bob).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_answerer_at_its_cap_refuses() {
        let relay = TestRelay::spawn().await.unwrap();
        let alice = node(&relay, [3u8; 32], MAX_DIRECT_PEERS).await;
        let bob = node(&relay, [3u8; 32], 0).await;
        settled(&relay).await;
        let error = offer(&alice, &bob).await.expect_err("bob is at his cap");
        assert!(super::super::is_cap_refusal(&error), "{error:#}");
    }

    /// The dispatcher runs every event through the opener: an offer sealed for
    /// another mesh is dropped before it reaches admission.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_offer_from_another_mesh_is_dropped_before_admission() {
        let relay = TestRelay::spawn().await.unwrap();
        let bob = node(&relay, [4u8; 32], MAX_DIRECT_PEERS).await;
        let stranger = node(&relay, [5u8; 32], MAX_DIRECT_PEERS).await;
        settled(&relay).await;
        // The stranger's keys, Bob's tag: the seal cannot open.
        let mut forged = stranger.signal.signal(SignalKind::Offer);
        forged.to = Some(bob.endpoint.id());
        forged.envelope = Some("{}".into());
        let content = seal(
            &stranger.signal.inner.keys,
            &stranger.signal.inner.secret,
            &forged,
        );
        let bobs_tag = bob.signal.inner.keys.self_tag(&bob.endpoint.id());
        for _ in 0..5 {
            stranger
                .signal
                .inner
                .pool
                .publish(&bobs_tag, content.clone());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(bob.admission.in_flight(), 0);
    }

    /// A node with `WebRTC` off answers no offer: the session would attach
    /// into a transport its endpoint never registered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_node_with_webrtc_off_answers_no_offer() {
        let relay = TestRelay::spawn().await.unwrap();
        let alice = node(&relay, [6u8; 32], MAX_DIRECT_PEERS).await;
        let bob = node_with(&relay, [6u8; 32], MAX_DIRECT_PEERS, false).await;
        settled(&relay).await;
        assert!(offer(&alice, &bob).await.is_err(), "no answer comes");
        assert!(!bob.handle.has_session(&alice.endpoint.id()));
    }

    mod discovery_rules {
        use std::time::Duration;

        use super::super::discovery::{HelloAction, hello_action, prune, target_width};
        use super::*;
        use crate::testing::{endpoint_id, fresh_state};
        use crate::util::clock::Instant;

        fn hello(from: EndpointId, addrs: &[&str], webrtc: bool) -> Signal {
            let mut hello = Signal::new(SignalKind::Hello, from, now());
            hello.addrs = addrs.iter().map(|addr| addr.parse().unwrap()).collect();
            hello.webrtc = webrtc;
            hello
        }

        /// A proven path to a peer that never made it into the overlay (a
        /// failed join, a full view) is grafted again on its next `Hello`,
        /// not skipped forever.
        #[test]
        fn a_direct_but_unlinked_peer_is_grafted_again() {
            let mut state = fresh_state();
            let peer = endpoint_id(9);
            state
                .direct
                .insert(peer, crate::daemon::state::DirectState::Direct);
            let unlinked = hello_action(
                &state,
                endpoint_id(1),
                &hello(peer, &[], false),
                Instant::now(),
            );
            assert_eq!(unlinked, HelloAction::Graft);

            state.linked_endpoints.insert(peer);
            let linked = hello_action(
                &state,
                endpoint_id(1),
                &hello(peer, &[], false),
                Instant::now(),
            );
            assert_eq!(linked, HelloAction::Nothing, "linked peers are left alone");
        }

        /// An IP peer's first `Hello` can go out before it knows its own
        /// addresses. That is "not yet", not "open a data channel".
        #[test]
        fn an_ip_peer_with_no_addresses_yet_is_not_offered_a_channel() {
            let state = fresh_state();
            let peer = endpoint_id(9);
            let no_addrs = hello_action(
                &state,
                endpoint_id(1),
                &hello(peer, &[], false),
                Instant::now(),
            );
            assert_eq!(no_addrs, HelloAction::Nothing);
            let with_addrs = hello_action(
                &state,
                endpoint_id(1),
                &hello(peer, &["192.0.2.1:4433"], false),
                Instant::now(),
            );
            assert_eq!(with_addrs, HelloAction::Probe, "with addresses, probe");
            let no_ip = hello_action(
                &state,
                endpoint_id(1),
                &hello(peer, &[], true),
                Instant::now(),
            );
            assert_eq!(
                no_ip,
                HelloAction::Offer,
                "a peer with no IP gets a channel"
            );
        }

        /// A node that just linked keeps its wide relay set for a while, so a
        /// flapping link does not flap the relay set.
        #[test]
        fn the_relay_set_narrows_only_after_the_link_settles() {
            let mut state = fresh_state();
            state.linked_endpoints.insert(endpoint_id(9));
            let now = Instant::now();
            state.nostr_wide_until = Some(now + Duration::from_secs(30));
            assert_eq!(target_width(&state, now, false), JOINING_WIDTH);
            assert_eq!(
                target_width(&state, now + Duration::from_secs(31), false),
                LINKED_WIDTH
            );
        }

        /// A hidden tab holds one relay even while it joins: the browser
        /// throttles its timers, and every member listens on that first relay.
        #[test]
        fn a_hidden_tab_holds_one_relay() {
            let state = fresh_state();
            let now = Instant::now();
            assert_eq!(target_width(&state, now, false), JOINING_WIDTH);
            assert_eq!(target_width(&state, now, true), LINKED_WIDTH);
        }

        #[test]
        fn peers_heard_long_ago_are_forgotten() {
            let mut state = fresh_state();
            let (old, fresh) = (endpoint_id(8), endpoint_id(9));
            let then = Instant::now();
            state.nostr_seen.insert(old, then);
            state.nostr_poked.insert(old, then);
            let later = then + Duration::from_mins(10);
            state.nostr_seen.insert(fresh, later);
            prune(&mut state, later);
            assert!(!state.nostr_seen.contains_key(&old));
            assert!(!state.nostr_poked.contains_key(&old));
            assert!(state.nostr_seen.contains_key(&fresh));
        }
    }
}
