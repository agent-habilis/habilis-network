//! The membership driver: what a `msg` frame means on the way in, and what a
//! consumer's request means on the way out.

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use crate::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent,
};
use crate::ops::{StateMergeParams, app_frame, broadcast_state_merge, send_app};
use crate::protocol::message::Authored;
use crate::protocol::{AppFrameParams, AppTag, Channel, MessageBody, MessageKind, Nickname};
use crate::util::consts::MAX_MESSAGE_SIZE;

#[cfg(all(
    feature = "iroh-test-utils",
    feature = "host",
    not(target_arch = "wasm32")
))]
use crate::daemon::event_loop;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::daemon::state::DirectState;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::transport::path;
#[cfg(all(
    feature = "iroh-test-utils",
    not(target_arch = "wasm32"),
    feature = "multihop"
))]
use crate::transport::underlay_webrtc;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::transport::webrtc;
#[cfg(all(
    feature = "iroh-test-utils",
    feature = "host",
    not(target_arch = "wasm32")
))]
use crate::util::clock;
/// The one `App`-frame tag a member sends: a whole UTF-8 text, broadcast or
/// directed. Bulk bytes do not ride gossip; they take a stream.
pub const MSG_TAG: &str = "msg";

/// Inbound messages buffered for a consumer that reads on its own schedule.
/// Bounded, because a member that only ever *sends* still receives broadcasts:
/// an unbounded queue would grow for the process's lifetime.
pub const INBOUND_CAP: usize = 256;

/// Wait before leaving, so frames just handed to the event loop go out first.
pub const DEPARTURE_GRACE: Duration = Duration::from_millis(750);

/// What a signed `App` frame costs beyond its body: ids, the pubkey, the
/// signature, the mesh id and the JSON keys. Checked by
/// `the_envelope_fits_its_reserve` against a 32-scalar author and addressee
/// and a mesh id carrying a custom relay ladder.
const ENVELOPE_RESERVE: usize = 1024;

/// The escaped-body budget one frame leaves after [`ENVELOPE_RESERVE`].
const ESCAPED_BUDGET: usize = MAX_MESSAGE_SIZE - ENVELOPE_RESERVE;

/// The longest text in bytes that always fits one frame, whatever it holds.
/// JSON escapes `"`, `\` and the allowed control characters to two bytes and
/// leaves everything else — non-ASCII included — as it is, so the worst case
/// is half the escaped budget. Most text fits well past this; ask
/// [`msg_fits`] for a given one.
pub const MAX_MSG: usize = ESCAPED_BUDGET / 2;

/// Whether `text` fits one `msg` frame. The engine's own check in `send_app` is
/// the final word; this answers early, without building and signing a frame.
#[must_use]
pub fn msg_fits(text: &str) -> bool {
    escaped_len(text) <= ESCAPED_BUDGET
}

/// The body of a `msg` frame.
///
/// # Errors
/// `text` holds a control character other than tab, newline or carriage
/// return, or does not fit one frame (see [`msg_fits`]).
pub fn msg_body(text: &str) -> Result<MessageBody> {
    anyhow::ensure!(
        msg_fits(text),
        "message too large for one frame: send it as a stream instead"
    );
    MessageBody::new(text.to_owned()).map_err(|error| anyhow::anyhow!("{error}"))
}

/// Parse an optional addressee.
///
/// # Errors
/// `to` is not a valid nickname.
pub fn parse_to(to: Option<&str>) -> Result<Option<Nickname>> {
    to.map(|nick| Nickname::new(nick.to_owned()))
        .transpose()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

/// `text` as `serde_json` writes it inside quotes.
fn escaped_len(text: &str) -> usize {
    text.chars()
        .map(|scalar| match scalar {
            '"' | '\\' | '\n' | '\t' | '\r' => 2,
            other => other.len_utf8(),
        })
        .sum()
}

/// One surfaced `msg`, flattened for a consumer outside the engine.
#[derive(Debug)]
#[non_exhaustive]
pub struct Inbound {
    /// The author's nickname.
    pub nick: String,
    /// The message was addressed to us specifically, not broadcast.
    pub directed: bool,
    /// The body of the message, as UTF-8.
    pub text: String,
}

/// A request pushed into the event loop from the consumer's side. Every arm
/// carries its own reply channel: a foreign caller needs the outcome of a send
/// as a return code, not a log line.
#[expect(
    missing_debug_implementations,
    reason = "the oneshot reply senders carry no Debug bound worth adding for a value that never reaches a log line"
)]
#[non_exhaustive]
pub enum Request {
    /// Send one `msg`. Build `body` with [`msg_body`].
    Send {
        /// The recipient, when the message is directed.
        to: Option<Nickname>,
        /// The body of the message (sealed for a directed frame on a passworded mesh).
        body: MessageBody,
        /// Gets `Ok` when the request is done, or the error text.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Tests only: send one directed `msg` the way [`Request::Send`] does, but never take the
    /// warm fast path. A pooled connection that a direct-path probe opened between a
    /// [`Request::ForgetUnicast`] and the send would answer at once, `Sent` or `Refused`, and a
    /// test that needs the send to wait on a dial would not see the wait. This one dials, or
    /// waits for a direct path on the pooled connection, as the cold path does.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    SendCold {
        /// The recipient, when the message is directed.
        to: Option<Nickname>,
        /// The body of the message (sealed for a directed frame on a passworded mesh).
        body: MessageBody,
        /// Gets `Ok` when the request is done, or the error text.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Merge a change into the shared state.
    StateMerge {
        /// The RFC 7386 merge to apply.
        merge: serde_json::Value,
        /// Gets `Ok` when the request is done, or the error text.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// The shared state as JSON.
    StateJson {
        /// Gets the text of the answer.
        reply: oneshot::Sender<String>,
    },
    /// The members of the roster.
    Peers {
        /// Gets the text of the answer.
        reply: oneshot::Sender<String>,
    },
    /// How many members there are.
    PeerCount {
        /// Gets the count.
        reply: oneshot::Sender<usize>,
    },
    /// Tests only, and the only request that is a test hook: take UDP away
    /// from (or give it back to) every connection in the process, and nudge
    /// this node's peers so path selection runs now: iroh re-selects only on
    /// path events.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    BlockUdp {
        /// Whether the block is on.
        blocked: bool,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: add `addr` to the addresses this node advertises, as an
    /// external address. The address of the node's endpoint changes, which is
    /// what a late home relay or an interface change does.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    AddExternalAddr {
        /// The address to advertise as external.
        addr: std::net::SocketAddr,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: make the beacon of this node stop answering while it keeps its rung, as a
    /// stopped process or a wedged accept loop does. Nothing happens when it holds no beacon.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    StallBeacon {
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: shed the beacon of this node at once, as a rival re-check shed does, and leave
    /// the node to re-claim or to read the holder that is there. Nothing happens when it holds no
    /// beacon.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    ShedBeacon {
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: hold this node's rendezvous claims back (`hold`), or let it claim again. A held
    /// node claims on no heal tick and in no reclaim window, and its links are untouched. A test
    /// holds the old members of a room so that a late joiner takes the free rung first.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    HoldClaims {
        /// Whether the hold is on.
        hold: bool,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: make the rung probe of this node read "not ours" whatever answers (`blind`), or
    /// let it read the truth again. It is the false negative that a loaded host gives: a node
    /// that finds its rung taken by the beacon of its own mesh then binds the next rung and holds
    /// a beacon of its own.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    BlindRungProbes {
        /// Whether the probes are blind.
        blind: bool,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: take UDP away from this node alone, to the nodes bound on
    /// `remote_ports` (see `Node::bound_ports`). An empty list gives it back.
    /// Unlike [`Request::BlockUdp`] it leaves every other node's paths alone,
    /// so a test can cut one group of nodes from another while each group
    /// keeps its own links.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    BlockIpTo {
        /// The ports of the remote side.
        remote_ports: Vec<u16>,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: take one rung of the path ladder away from this node alone
    /// (or give it back), to every remote. With [`Request::BlockIpTo`] it takes
    /// the node down the ladder one rung at a time.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    BlockRung {
        /// The rung of the path.
        rung: Rung,
        /// Whether the block is on.
        blocked: bool,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: take one rung of the path ladder away from this node alone (or
    /// give it back), to the member `peer` only. [`Request::BlockRung`] takes it
    /// from every remote. Only the `WebRTC` rung has a remote in its address, so
    /// only that rung is cut this way.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    BlockRungTo {
        /// The rung of the path.
        rung: Rung,
        /// The peer, by nickname.
        peer: String,
        /// Whether the block is on.
        blocked: bool,
        /// Gets `Ok` when the request is done, or `UnknownPeer` when no member has that nickname.
        reply: oneshot::Sender<Result<(), UnknownPeer>>,
    },
    /// Tests only: refuse every `WebRTC` session with the member `peer`, on the application
    /// endpoint and on the underlay, offered or answered, and end the ones that exist (or lift
    /// the refusal). It keeps a pair from forming a direct session, so that its traffic has to
    /// take the multihop route through a third member.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    DenyPeer {
        /// The peer, by nickname.
        peer: String,
        /// Whether the peer is denied.
        denied: bool,
        /// Gets `Ok` when the request is done, or `UnknownPeer` when no member has that nickname.
        reply: oneshot::Sender<Result<(), UnknownPeer>>,
    },
    /// Tests only: ping every member and answer with the round trip time in
    /// milliseconds of each one that answered within the ping window. A test uses it to
    /// show that a pair answers over the one path it has.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    Ping {
        /// Gets each member with its round-trip time.
        reply: oneshot::Sender<Vec<(Nickname, u64)>>,
    },
    /// Tests only: how many gossip connections the recursion rule has closed since the process
    /// started (the census field `gossip_recursion_closes_total`): a total, shared by every
    /// member of the process. A pair that cannot leave the gossip path closes and dials again,
    /// so a count that grows without a bound is that loop.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    GossipRecursionCloses {
        /// Gets the count.
        reply: oneshot::Sender<u64>,
    },
    /// Tests only: how many messages this node holds in its log, the ones that anti-entropy
    /// can serve to a peer that asks. A broadcast that a node sent itself is there only if the
    /// send path retains it.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    MessageLogLen {
        /// Gets the count.
        reply: oneshot::Sender<usize>,
    },
    /// Tests only: forget the pooled unicast connection of the member `peer`, and its dial
    /// cooldown, and keep its address, so that the next directed send to it is cold. It answers
    /// whether a connection was pooled: a test that needs a cold send asks until the answer is
    /// `false`, because a direct-path probe can pool a connection again.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    ForgetUnicast {
        /// The peer, by nickname.
        peer: String,
        /// Gets the answer, or `UnknownPeer` when no member has that nickname.
        reply: oneshot::Sender<Result<bool, UnknownPeer>>,
    },
    /// Tests only: forget that the member `peer` is proven direct, and offer it a
    /// `WebRTC` session now, as the path watcher does when a direct path is lost.
    /// A test uses it to attach a session at a chosen moment instead of at the
    /// next alive tick.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    OfferSession {
        /// The peer, by nickname.
        peer: String,
        /// Gets `Ok` when the request is done, or `UnknownPeer` when no member has that nickname.
        reply: oneshot::Sender<Result<(), UnknownPeer>>,
    },
    /// Tests only: close the live gossip connections to the member `peer` and nothing else. The
    /// engine then runs its own `NeighborDown` path.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    CloseLink {
        /// The peer, by nickname.
        peer: String,
        /// Gets `Ok` when the request is done, or `UnknownPeer` when no member has that nickname.
        reply: oneshot::Sender<Result<(), UnknownPeer>>,
    },
    /// Tests only: run the underlay tick now, as the alive tick does. A test that closes a link
    /// uses it to put a tick inside the time the link is down.
    #[cfg(all(
        feature = "iroh-test-utils",
        not(target_arch = "wasm32"),
        feature = "multihop"
    ))]
    UnderlayTick {
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: the endpoint id of this node. A test that needs the order of two
    /// ids (the lower id offers a session) reads them here.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    EndpointId {
        /// Gets the endpoint id.
        reply: oneshot::Sender<iroh::EndpointId>,
    },
    /// Tests only: mark the gossip topic closed without a real end of the stream, as the heal
    /// arm reads a terminal `None`. The loop stops reading the topic, the heal tick resubscribes,
    /// and the messages that arrive in between must still reach the app.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    SeverGossip {
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: the rung of the selected path on this node's pooled
    /// connection to the member `peer`: `ip`, `webrtc`, `multihop` or `relay`.
    /// It opens the connection first if there is none. This is the connection
    /// the answer is about: the gossip link is not, because the relay policy
    /// closes a gossip link that stays on the relay.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    SelectedRung {
        /// The peer, by nickname.
        peer: String,
        /// Gets the reason, or `None` when there is none.
        reply: oneshot::Sender<Option<&'static str>>,
    },
    /// Tests only: whether the multihop topology of this node has a route to the
    /// member `peer` now. A route exists from the first link-state on.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    HasRoute {
        /// The peer, by nickname.
        peer: String,
        /// Gets the answer.
        reply: oneshot::Sender<bool>,
    },
    /// Tests only: hold this node's link-vector back, or let it go. Holding withdraws the vector
    /// that this node advertised from its own routing table, so that it has no outgoing edge and
    /// no route, and no tick or link event advertises one until it is let go. Letting go
    /// advertises at once. The others keep the last vector that they heard for up to three
    /// advertisement intervals, so the hold is for seconds: a test uses it to force the order
    /// "a path is lost before any route exists", where it would otherwise wait for it.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    HoldLinkState {
        /// Whether the hold is on.
        hold: bool,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: the multihop view of this node as one line: its edges, and for each
    /// member the open paths of the writer connection toward its underlay, or that there
    /// is none. A writer toward a member exists only if this node sent cells to it: one
    /// toward the receiver of a cell that must go through a third member is a direct hop.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    RouteDiag {
        /// Gets the text of the answer.
        reply: oneshot::Sender<String>,
    },
    /// Tests only: how many multihop cells this node has passed on for other
    /// nodes. `0` when multihop is off.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    ForwardedCells {
        /// Gets the count.
        reply: oneshot::Sender<u64>,
    },
    /// Tests only: what the multihop data path of this node counted: cells passed on,
    /// dropped, refused on the relay and delivered to the local transport. All `0` when
    /// multihop is off.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    MultihopCounters {
        /// Gets the counters of the multihop transport.
        reply: oneshot::Sender<habilis_network_iroh_multihop_transport::MultihopCounters>,
    },
    /// Tests only: how many `WebRTC` sessions the multihop underlay of this node
    /// holds. `0` when multihop is off.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    UnderlaySessions {
        /// Gets the count.
        reply: oneshot::Sender<usize>,
    },
    /// Tests only: how many `WebRTC` sessions of this node go to a member that is
    /// neither a gossip neighbor nor the rendezvous. Such a session carries only what
    /// was sent over it, so it must go after it idled for 120 s.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    SessionsToNonNeighbors {
        /// Gets the count.
        reply: oneshot::Sender<usize>,
    },
    /// Tests only: the closes of direct connections, and how many of them were followed by
    /// a connection to the same peer within 300 s, as `[quic closes, quic re-dials, session
    /// closes, session re-dials, pool closes, pool re-dials]`. `quic` counts every live
    /// connection, the gossip links too; `pool` only the pooled unicast connections that a
    /// send used, which is what the idle close acts on. Each request samples the peers, so ask
    /// about once per second.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    RedialCounts {
        /// Gets the six counters.
        reply: oneshot::Sender<[u64; 6]>,
    },
    /// Tests only: the direct peers the ledger of the ceiling counts now, and by how many it is over
    /// the ceiling, as `(units, over_ceiling)`.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    DirectUnits {
        /// Gets the pair of counts.
        reply: oneshot::Sender<(usize, usize)>,
    },
}

/// A rung of the path ladder, for [`Request::BlockRung`].
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub use habilis_network_iroh_webrtc_transport::Rung;

/// The engine seam. Every inbound `msg` is queued for the consumer instead of
/// being written anywhere: a browser's `js_sys::Function` is neither `Send`
/// nor `Sync`, and [`NodeApp`] is `Send`, so the driver could not keep one even
/// if it wanted to. Consumers drain the queue on their own schedule.
#[derive(Debug)]
pub struct MembershipApp {
    inbound: mpsc::Sender<Inbound>,
    /// Messages dropped since the queue last had room. One error is surfaced
    /// per stall rather than one per drop: the event channel is unbounded,
    /// and a consumer that stopped reading must not grow it without bound.
    dropped: u64,
}

impl MembershipApp {
    /// Messages land on `inbound`, dropped when it is full.
    #[must_use]
    pub fn new(inbound: mpsc::Sender<Inbound>) -> Self {
        Self {
            inbound,
            dropped: 0,
        }
    }

    /// Count one delivery attempt; `true` on the first drop of a stall.
    fn stall_began(&mut self, queued: bool) -> bool {
        if queued {
            self.dropped = 0;
            return false;
        }
        self.dropped += 1;
        self.dropped == 1
    }
}

#[async_trait]
impl NodeApp for MembershipApp {
    fn classify(&self, _message: &Authored) -> AppClass {
        // Ephemeral text: never logged, never a task beat, always valid, no
        // per-author hash chain. `sealed: false` is load-bearing — a member
        // publishes no a2a card, so it can neither seal to a peer nor be sealed
        // to, and the addressee must pass a directed plaintext body straight
        // through instead of trying (and failing) to unseal it.
        AppClass::VALID
    }

    async fn on_app_frame(
        &mut self,
        frame: InboundApp<'_>,
        _state: &mut EventLoopState,
        ctx: &HandlerCtx<'_>,
    ) -> bool {
        let InboundApp {
            message,
            surfaceable: _,
        } = frame;
        if message.kind.app_tag().map(AppTag::as_str) != Some(MSG_TAG) {
            return false;
        }
        // The engine only dispatches frames addressed to us or broadcast, so a
        // present `to` is us.
        let inbound = Inbound {
            nick: message.author.to_string(),
            directed: matches!(message.kind, MessageKind::App { to: Some(_), .. }),
            text: message.body.as_str().to_owned(),
        };
        // Full or closed: the caller is not draining. Dropping is the only
        // option that neither blocks the event loop nor grows without bound.
        let queued = self.inbound.try_send(inbound).is_ok();
        if self.stall_began(queued) {
            ctx.sink.emit(NodeEvent::Error(
                "inbound message queue full: messages are being dropped until it is read"
                    .to_owned(),
            ));
        }
        // Never retained or indexed — the frame is fully handled here.
        false
    }
}

#[async_trait]
impl NodeDriver for MembershipApp {
    type Session = Request;
    type Http = ();
    type Ipc = ();

    #[expect(
        clippy::too_many_lines,
        reason = "the test-only requests share this one match, and the lint counts the lines that a cfg removes"
    )]
    async fn handle_session(
        &mut self,
        req: Request,
        state: &mut EventLoopState,
        ctx: &HandlerCtx<'_>,
    ) -> bool {
        match req {
            Request::Send { to, body, reply } => {
                let frame = app_frame(
                    ctx,
                    AppFrameParams::new(
                        AppTag::new(MSG_TAG).expect("a valid app tag"),
                        to,
                        None,
                        body,
                    ),
                );
                let class = self.classify(&frame.authored());
                match send_app(state, ctx, frame, class).await {
                    Ok(crate::transport::Delivered::Done) => {
                        let _ = reply.send(Ok(()));
                    }
                    Ok(crate::transport::Delivered::Pending(handle)) => {
                        // The dial runs on a task, and so does the wait for its outcome: the loop
                        // serves the next request meanwhile.
                        n0_future::task::spawn(async move {
                            let outcome = handle.await.unwrap_or_else(|_| {
                                Err(anyhow::anyhow!("the send ended without an outcome"))
                            });
                            let _ = reply.send(outcome.map_err(|error| error.to_string()));
                        });
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error.to_string()));
                    }
                }
                true
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::SendCold { to, body, reply } => {
                let frame = app_frame(
                    ctx,
                    AppFrameParams::new(
                        AppTag::new(MSG_TAG).expect("a valid app tag"),
                        to,
                        None,
                        body,
                    ),
                );
                let routed = frame
                    .serialize()
                    .map_err(|error| error.to_string())
                    .and_then(|bytes| {
                        crate::transport::resolve(&frame, bytes, state)
                            .map_err(|error| error.to_string())
                    });
                match routed {
                    Ok(crate::transport::Resend::Unicast(eid, bytes)) => {
                        let pool = state.unicast_pool.clone();
                        let registration = pool.register_dial(eid);
                        n0_future::task::spawn(async move {
                            let sent = pool
                                .send_registered(registration, eid, bytes.into_bytes())
                                .await;
                            let _ = reply.send(sent.map_err(|error| error.to_string()));
                        });
                    }
                    Ok(crate::transport::Resend::Broadcast(_)) => {
                        let _ = reply.send(Err("a cold send needs a directed message".to_owned()));
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
                true
            }
            Request::StateMerge { merge, reply } => {
                let merged = broadcast_state_merge(
                    state,
                    StateMergeParams::new(ctx.into(), Channel::State, merge),
                )
                .await;
                let _ = reply.send(merged.map(|_| ()).map_err(|error| error.to_string()));
                true
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::StallBeacon { reply } => {
                state.stall_requested = true;
                let _ = reply.send(());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::ShedBeacon { reply } => {
                state.shed_requested = true;
                let _ = reply.send(());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::HoldClaims { hold, reply } => {
                state.claims_held = hold;
                let _ = reply.send(());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::BlindRungProbes { blind, reply } => {
                crate::beacon::set_blind_rung_probes(ctx.endpoint.id(), blind);
                let _ = reply.send(());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::BlockIpTo {
                remote_ports,
                reply,
            } => {
                habilis_network_iroh_webrtc_transport::block_ip_to(ctx.endpoint.id(), remote_ports);
                // iroh re-selects only on path events: nudge every peer so the
                // new set takes effect now.
                for addr in state.peer_endpoints.values() {
                    let endpoint = ctx.endpoint.clone();
                    let peer = addr.id;
                    n0_future::task::spawn(async move {
                        webrtc::nudge(&endpoint, peer).await;
                    });
                }
                let _ = reply.send(());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::Ping { reply } => {
                crate::ops::start_ping_round(state, ctx, Some(reply)).await;
                true
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::BlockRung {
                rung,
                blocked,
                reply,
            } => {
                habilis_network_iroh_webrtc_transport::block_rung(ctx.endpoint.id(), rung, blocked);
                // iroh re-selects only on path events: nudge every peer so the
                // change takes effect now.
                for addr in state.peer_endpoints.values() {
                    let endpoint = ctx.endpoint.clone();
                    let peer = addr.id;
                    n0_future::task::spawn(async move {
                        webrtc::nudge(&endpoint, peer).await;
                    });
                }
                let _ = reply.send(());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::BlockRungTo {
                rung,
                peer,
                blocked,
                reply,
            } => {
                let result = known_peer(state, &peer).map(|addr| {
                    let remote = addr.id;
                    habilis_network_iroh_webrtc_transport::block_rung_to(
                        ctx.endpoint.id(),
                        rung,
                        remote,
                        blocked,
                    );
                    let endpoint = ctx.endpoint.clone();
                    n0_future::task::spawn(async move {
                        webrtc::nudge(&endpoint, remote).await;
                    });
                });
                let _ = reply.send(result);
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::DenyPeer {
                peer,
                denied,
                reply,
            } => {
                let member = known_peer(state, &peer).map(|addr| addr.id);
                if let Ok(member) = member {
                    state.webrtc_admission.deny(member, denied);
                    if denied
                        && let Some(handle) = state.webrtc.as_ref()
                        && handle.detach(&member)
                    {
                        tracing::debug!(
                            target: "habilis_network::transport",
                            peer = %member,
                            "session detached: a test denied the peer"
                        );
                    }
                    #[cfg(feature = "multihop")]
                    underlay_webrtc::tick_now(state);
                }
                let _ = reply.send(member.map(|_| ()));
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::OfferSession { peer, reply } => {
                let result = known_peer(state, &peer).cloned().map(|addr| {
                    state.direct.insert(addr.id, DirectState::RelayOnly);
                    webrtc::negotiate_session(state, ctx, addr.id, addr);
                });
                let _ = reply.send(result);
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::CloseLink { peer, reply } => {
                let result = known_peer(state, &peer).map(|addr| {
                    path::close_gossip_links_to(addr.id);
                });
                let _ = reply.send(result);
                false
            }
            #[cfg(all(
                feature = "iroh-test-utils",
                not(target_arch = "wasm32"),
                feature = "multihop"
            ))]
            Request::UnderlayTick { reply } => {
                underlay_webrtc::tick_now(state);
                let _ = reply.send(());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::MessageLogLen { reply } => {
                let _ = reply.send(state.message_log.len());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::ForgetUnicast { peer, reply } => {
                let id = known_peer(state, &peer).map(|addr| addr.id);
                let pool = state.unicast_pool.clone();
                let outcome = match id {
                    Ok(id) => Ok(pool.drop_connection(id).await),
                    Err(unknown) => Err(unknown),
                };
                let _ = reply.send(outcome);
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::GossipRecursionCloses { reply } => {
                let _ = reply.send(path::gossip_recursion_closes());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::EndpointId { reply } => {
                let _ = reply.send(ctx.endpoint.id());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::SeverGossip { reply } => {
                state.gossip_open = false;
                let _ = reply.send(());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::SelectedRung { peer, reply } => {
                let id = known_peer(state, &peer).ok().map(|addr| addr.id);
                let pool = state.unicast_pool.clone();
                // Off the event loop: a dial can take seconds.
                n0_future::task::spawn(async move {
                    let rung = match id {
                        Some(id) => pool.warm_or_dial(id).await.ok().and_then(|conn| {
                            let rung = path::selected_rung(&conn);
                            // The same stable id twice is one connection read twice: a test that
                            // waits for a rung can see whether the connection it reads is the one
                            // that climbed.
                            tracing::debug!(
                                target: "habilis_network::transport",
                                peer = %id,
                                conn = conn.stable_id(),
                                ?rung,
                                "the rung read for a test"
                            );
                            rung
                        }),
                        None => None,
                    };
                    let _ = reply.send(rung);
                });
                false
            }
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::HoldLinkState { hold, reply } => {
                state.linkstate_held = hold;
                state.last_advertised = None;
                if hold && let Some(handle) = state.multihop() {
                    let _ = handle.remove_origin(handle.app_id());
                }
                if !hold {
                    event_loop::linkstate_arm(state, ctx).await;
                }
                let _ = reply.send(());
                false
            }
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::HasRoute { peer, reply } => {
                let has_route = known_peer(state, &peer).is_ok_and(|addr| {
                    state.multihop().is_some_and(|handle| {
                        handle
                            .route_addr(habilis_network_iroh_multihop_transport::AppId::new(
                                addr.id,
                            ))
                            .is_some()
                    })
                });
                let _ = reply.send(has_route);
                false
            }
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::RouteDiag { reply } => {
                let _ = reply.send(route_diag(state));
                false
            }
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::UnderlaySessions { reply } => {
                let sessions = state
                    .underlay_webrtc
                    .as_ref()
                    .map_or(0, |underlay| underlay.handle.session_count());
                let _ = reply.send(sessions);
                false
            }
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::SessionsToNonNeighbors { reply } => {
                let sessions = state.webrtc.as_ref().map_or(0, |webrtc| {
                    state
                        .peer_endpoints
                        .values()
                        .filter(|addr| {
                            webrtc.has_session(&addr.id)
                                && !state.linked_endpoints.contains(&addr.id)
                                && addr.id != ctx.rendezvous_id
                        })
                        .count()
                });
                let _ = reply.send(sessions);
                false
            }
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::DirectUnits { reply } => {
                let _ = reply.send((
                    state.webrtc_admission.direct_units(),
                    state.webrtc_admission.over_ceiling(),
                ));
                false
            }
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::RedialCounts { reply } => {
                let now = clock::Instant::now();
                let ids: Vec<_> = state.peer_endpoints.values().map(|addr| addr.id).collect();
                for id in ids {
                    let quic = state.webrtc_admission.has_live_connection(id);
                    let session = state
                        .webrtc
                        .as_ref()
                        .is_some_and(|hub| hub.has_session(&id));
                    let pooled = state.unicast_pool.used_connection(id).is_some();
                    state.redials.quic.observe(now, id, quic);
                    state.redials.session.observe(now, id, session);
                    state.redials.pool.observe(now, id, pooled);
                }
                let counts = [
                    state.redials.quic.closes(),
                    state.redials.quic.redials(),
                    state.redials.session.closes(),
                    state.redials.session.redials(),
                    state.redials.pool.closes(),
                    state.redials.pool.redials(),
                ];
                let _ = reply.send(counts);
                false
            }
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::ForwardedCells { reply } => {
                let forwarded = state.multihop().map_or(
                    0,
                    habilis_network_iroh_multihop_transport::MultihopHandle::forwarded_cells,
                );
                let _ = reply.send(forwarded);
                false
            }
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::MultihopCounters { reply } => {
                let counters = state.multihop().map_or_else(
                    Default::default,
                    habilis_network_iroh_multihop_transport::MultihopHandle::counters,
                );
                let _ = reply.send(counters);
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::AddExternalAddr { addr, reply } => {
                ctx.endpoint.add_external_addr(addr).await;
                let _ = reply.send(());
                false
            }
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::BlockUdp { blocked, reply } => {
                habilis_network_iroh_webrtc_transport::block_ip_paths(blocked);
                for addr in state.peer_endpoints.values() {
                    let endpoint = ctx.endpoint.clone();
                    let peer = addr.id;
                    n0_future::task::spawn(async move {
                        webrtc::nudge(&endpoint, peer).await;
                    });
                }
                let _ = reply.send(());
                false
            }
            Request::StateJson { reply } => {
                let _ = reply.send(state.doc(Channel::State).to_json().to_string());
                false
            }
            Request::Peers { reply } => {
                let snapshot = state.roster_snapshot();
                let json = serde_json::to_string(&snapshot)
                    .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"));
                let _ = reply.send(json);
                false
            }
            Request::PeerCount { reply } => {
                // `peers.len()`, not the snapshot's `count` — that one includes
                // self, and a caller asking "is anyone else here?" wants zero
                // when it is alone.
                let _ = reply.send(state.roster_snapshot().peers.len());
                false
            }
        }
    }
}

/// Tests only: the member that a request names is not in the book of this node. A request on it
/// does nothing; the node says so, and the test waits for the `PeerInfo` that brings the member.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownPeer(pub String);

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
impl UnknownPeer {
    /// The peer that was not found.
    #[must_use]
    pub const fn new(peer: String) -> Self {
        Self(peer)
    }
}

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
impl std::fmt::Display for UnknownPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the member {:?} is not in the book of this node", self.0)
    }
}

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
impl std::error::Error for UnknownPeer {}

/// The address of the member `peer`, or [`UnknownPeer`]. The requests of the tests that name a
/// member resolve it here, so that none of them answers for a member it does not know.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
fn known_peer<'a>(
    state: &'a EventLoopState,
    peer: &str,
) -> Result<&'a iroh::EndpointAddr, UnknownPeer> {
    state
        .peer_endpoints
        .get(peer)
        .ok_or_else(|| UnknownPeer(peer.to_owned()))
}

#[cfg(all(
    feature = "iroh-test-utils",
    feature = "host",
    not(target_arch = "wasm32")
))]
fn route_diag(state: &EventLoopState) -> String {
    use std::borrow::Borrow as _;

    let Some(handle) = state.multihop() else {
        return "multihop is off".to_owned();
    };
    let view = handle.topology_view();
    let name_of = |id: &str| -> String {
        if id == view.self_id {
            return "self".to_owned();
        }
        state
            .peer_endpoints
            .iter()
            .find(|(_, addr)| addr.id.to_string() == id)
            .map_or_else(
                || id.chars().take(10).collect(),
                |(nickname, _)| {
                    let text: &str = nickname.borrow();
                    text.to_owned()
                },
            )
    };
    let edges: Vec<String> = view
        .edges
        .iter()
        .map(|edge| {
            format!(
                "{}->{}:{}",
                name_of(&edge.from),
                name_of(&edge.to),
                edge.metric
            )
        })
        .collect();
    let mut writers: Vec<String> = state
        .peer_endpoints
        .iter()
        .filter_map(|(nickname, addr)| {
            let underlay = handle
                .underlay_addr_of(habilis_network_iroh_multihop_transport::AppId::new(addr.id))?;
            let text: &str = nickname.borrow();
            let open = handle
                .underlay_paths_for_test(habilis_network_iroh_multihop_transport::UnderlayId::new(
                    underlay.id,
                ))
                .map_or_else(
                    || "none".to_owned(),
                    |paths| {
                        let shown: Vec<String> = paths
                            .into_iter()
                            .map(|(path, selected)| {
                                format!("{path:?}{}", if selected { "*" } else { "" })
                            })
                            .collect();
                        shown.join(",")
                    },
                );
            Some(format!("{text}:{open}"))
        })
        .collect();
    writers.sort();
    format!(
        "edges=[{}] writers=[{}]",
        edges.join(" "),
        writers.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Identity, Lookup, MeshConfig, MeshId, Message, RelayLadder};
    use crate::runtime::derive_topic_mesh_config;
    use habilis_network_test_tracing::test;

    /// The longest nickname there is: 32 four-byte scalars.
    fn widest_nick(seed: char) -> Nickname {
        Nickname::new(std::iter::repeat_n(seed, 32).collect::<String>()).expect("32 scalars")
    }

    /// A mesh id well past the common case: every lookup and a four-rung
    /// custom relay ladder.
    fn long_mesh() -> MeshId {
        let ladder: RelayLadder = (0..4)
            .map(|rung| format!("https://relay-{rung}.a-rather-long-relay-domain.example/"))
            .collect::<Vec<_>>()
            .join(",")
            .parse()
            .expect("ladder");
        let config = MeshConfig::resolve(
            &[Lookup::Mdns, Lookup::Dht, Lookup::Relay],
            Some(ladder),
            &[],
        )
        .expect("config");
        let mesh = derive_topic_mesh_config("standup", config).expect("mesh");
        MeshId::new(mesh.to_string()).expect("id")
    }

    fn signed_len(text: &str) -> usize {
        Message::new_app(
            &long_mesh(),
            &widest_nick('\u{1F980}'),
            AppFrameParams::new(
                AppTag::new(MSG_TAG).expect("a valid app tag"),
                Some(widest_nick('\u{1F99E}')),
                None,
                MessageBody::new(text.to_owned()).expect("body"),
            ),
        )
        .sign(&Identity::generate())
        .wire_len()
    }

    #[test]
    fn the_envelope_fits_its_reserve() {
        let envelope = signed_len("");
        assert!(envelope <= ENVELOPE_RESERVE, "envelope is {envelope} bytes");
    }

    /// `msg_fits` must never say yes to a text `send_app` would refuse, at
    /// either end of the escaping range.
    #[test]
    fn a_text_msg_fits_accepts_signs_within_one_frame() {
        for text in [
            "\"".repeat(MAX_MSG),
            "a".repeat(ESCAPED_BUDGET),
            "\u{1F980}".repeat(ESCAPED_BUDGET / 4),
        ] {
            assert!(msg_fits(&text));
            let len = signed_len(&text);
            assert!(len <= MAX_MESSAGE_SIZE, "{len} bytes");
        }
        assert!(!msg_fits(&"\"".repeat(MAX_MSG + 1)));
        assert!(!msg_fits(&"a".repeat(ESCAPED_BUDGET + 1)));
    }

    #[test]
    fn a_body_round_trips_and_refuses_what_it_cannot_carry() {
        let text = "ol\u{e1}, \"mesh\"\n\ttab";
        assert_eq!(msg_body(text).expect("body").as_str(), text);
        assert!(msg_body("bell\u{7}").is_err());
        assert!(msg_body(&"\"".repeat(MAX_MSG + ESCAPED_BUDGET)).is_err());
    }

    #[test]
    fn a_stall_surfaces_once_until_the_queue_drains() {
        let (inbound, _queue) = mpsc::channel(1);
        let mut app = MembershipApp::new(inbound);
        let surfaced: Vec<bool> = [true, false, false, false, true, false]
            .into_iter()
            .map(|queued| app.stall_began(queued))
            .collect();
        assert_eq!(surfaced, [false, true, false, false, false, true]);
    }
}
