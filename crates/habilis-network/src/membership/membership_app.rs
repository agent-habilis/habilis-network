//! The membership driver: what a `msg` frame means on the way in, and what a
//! consumer's request means on the way out.

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::daemon::state::{Standing, TestHold};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use crate::embed::{
    AppClass, EventLoopState, HandlerCtx, InboundApp, NodeApp, NodeDriver, NodeEvent,
};
use crate::ops::{StateMergeParams, app_frame, broadcast_state_merge, send_app};
use crate::protocol::messages::Authored;
use crate::protocol::{
    AppFrameParams, AppTag, AuthorKey, Channel, MessageBody, MessageKind, Nickname,
};
use crate::util::consts::MAX_MESSAGE_SIZE;

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::beacon;
#[cfg(all(
    feature = "iroh-test-utils",
    feature = "host",
    not(target_arch = "wasm32")
))]
use crate::daemon::event_loop;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::daemon::state::DirectState;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::ops;
use crate::transport;
use crate::transport::Delivered;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::transport::Resend;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use crate::transport::payload_path;
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
use n0_future::task;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use std::error;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use std::fmt;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
use std::net;
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
/// `the_envelope_fits_its_reserve` against a 32-scalar author, an addressee key
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
///
/// # Examples
///
/// A short message fits in one frame, and a megabyte does not.
///
/// ```
/// use habilis_network::membership::msg_fits;
///
/// assert!(msg_fits("hello"));
/// assert!(!msg_fits(&"x".repeat(1 << 20)));
/// ```
#[must_use]
pub fn msg_fits(text: &str) -> bool {
    escaped_len(text) <= ESCAPED_BUDGET
}

/// The body of a `msg` frame.
///
/// # Errors
/// `text` holds a control character other than tab, newline or carriage
/// return, or does not fit one frame (see [`msg_fits`]).
///
/// # Examples
///
/// A message becomes a body if it fits, and an oversize message is refused.
///
/// ```
/// use habilis_network::membership::msg_body;
///
/// let body = msg_body("hello").expect("a body");
/// assert!(!body.as_str().is_empty());
/// assert!(msg_body(&"x".repeat(1 << 20)).is_err());
/// ```
pub fn msg_body(text: &str) -> Result<MessageBody, transport::SendError> {
    if !msg_fits(text) {
        return Err(transport::SendError::Oversize(
            "message too large for one frame: send it as a stream instead".to_owned(),
        ));
    }
    MessageBody::try_new(text).map_err(|error| transport::SendError::Internal(error.into()))
}

/// Parse an optional addressee.
///
/// # Errors
/// `to` is not a valid nickname.
///
/// # Examples
///
/// No addressee means a broadcast, and a nickname names one member.
///
/// ```
/// use habilis_network::membership::parse_to;
///
/// assert!(parse_to(None).expect("no addressee").is_none());
/// assert!(parse_to(Some("bob")).expect("a nickname").is_some());
/// ```
pub fn parse_to(to: Option<&str>) -> Result<Option<Nickname>, transport::SendError> {
    to.map(Nickname::try_new)
        .transpose()
        .map_err(|error| transport::SendError::InvalidAddressee(error.to_string()))
}

/// Parse the author key of an addressee from its 64 lowercase hex digits, the form that
/// [`Inbound::key`] has in text and that the roster JSON names in `key`.
///
/// # Errors
/// `key` is not 64 lowercase hex digits.
///
/// # Examples
///
/// A key is 64 lowercase hex digits, and any other text is refused.
///
/// ```
/// use habilis_network::membership::parse_key;
///
/// assert!(parse_key(&"ab".repeat(32)).is_ok());
/// assert!(parse_key("bob").is_err());
/// ```
pub fn parse_key(key: &str) -> Result<AuthorKey, transport::SendError> {
    AuthorKey::decode_hex(key).ok_or_else(|| {
        transport::SendError::InvalidAddressee(
            "the author key of an addressee is 64 lowercase hex digits".to_owned(),
        )
    })
}

/// The key a directed send by nickname goes to ([`EventLoopState::addressee_key`]). A frame names
/// its recipient by key, so a nickname that no key uses, or that two or more keys of one rank
/// use, is refused here with the text of the cause. No `to` is a broadcast.
fn recipient_key(
    state: &EventLoopState,
    to: Option<Nickname>,
) -> Result<Option<AuthorKey>, String> {
    let Some(nickname) = to else {
        return Ok(None);
    };
    state
        .addressee_key(&nickname)
        .map(Some)
        .map_err(|error| format!("directed message to {nickname} refused: {error}"))
}

/// The length in bytes of `text` as `serde_json` writes it inside quotes: `"`, `\`, newline, tab
/// and carriage return take two bytes, and every other scalar keeps its UTF-8 length.
fn escaped_len(text: &str) -> usize {
    text.chars()
        .map(|scalar| match scalar {
            '"' | '\\' | '\n' | '\t' | '\r' => 2,
            other => other.len_utf8(),
        })
        .sum()
}

/// One surfaced `msg`, flattened for a consumer outside the engine.
///
/// # Examples
///
/// An inbound message names its author, and it says whether it was sent to this member. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::membership::Membership;
///
/// # async fn demo(mut member: Membership) {
/// while let Some(inbound) = member.inbound.recv().await {
///     if inbound.directed {
///         println!("{} wrote to us", inbound.nick);
///     }
/// }
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Inbound {
    /// The author's nickname. Two live members can use one nickname, so it names no author.
    pub nick: String,
    /// The author's key. A reply goes to this key with [`Messaging::SendToKey`].
    pub key: AuthorKey,
    /// The message was addressed to us specifically, not broadcast.
    pub directed: bool,
    /// The body of the message, as UTF-8.
    pub text: String,
}

/// A request pushed into the event loop from the consumer's side. Every arm
/// carries its own reply channel: a foreign caller needs the outcome of a send
/// as a return code, not a log line.
///
/// # Examples
///
/// A request asks the membership for something, and the reply comes back on a channel. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::membership::{Inspect, Membership, Request};
///
/// # async fn demo(member: &Membership) {
/// let peers = member.request(|reply| Request::Inspect(Inspect::Peers { reply })).await.unwrap_or_default();
/// # let _ = peers;
/// # }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum Request {
    /// Messages the member sends.
    Messaging(Messaging),
    /// Test-only sends and pings.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    MessagingTest(MessagingTest),
    /// Reads of the member's state and peers.
    Inspect(Inspect),
    /// Test-only reads of the member's identity, logs and rung.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    InspectTest(InspectTest),
    /// Test-only reads of routes, on a host build.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    InspectHost(InspectHost),
    /// Test-only link control: offer, close, drop and sever links.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    Linking(Linking),
    /// Test-only underlay tick, with multihop.
    #[cfg(all(
        feature = "iroh-test-utils",
        not(target_arch = "wasm32"),
        feature = "multihop"
    ))]
    Ticks(Ticks),
    /// Test-only reads of the underlay's sessions and counters.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    Routing(Routing),
    /// Test-only blocks and denials: a path, an address or a peer is cut off.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    Blocking(Blocking),
    /// Test-only beacon and claim controls.
    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    Beacons(Beacons),
    /// Test-only hold of a link's state, on a host build.
    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    LinkHold(LinkHold),
}

/// Messages the member sends.
#[derive(Debug)]
#[non_exhaustive]
pub enum Messaging {
    /// Send one `msg`. Build `body` with [`msg_body`].
    Send {
        /// The recipient, when the message is directed.
        to: Option<Nickname>,
        /// The body of the message (sealed for a directed frame on a passworded mesh).
        body: MessageBody,
        /// Gets `Ok` when the request is done, or the error text.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Send one `msg` to the member that holds an author key. Two live members can use one
    /// nickname, and [`Messaging::Send`] refuses such a nickname; a key names one member. Build
    /// `body` with [`msg_body`].
    SendToKey {
        /// The author key of the recipient.
        to: AuthorKey,
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
}

/// Test-only sends and pings.
#[derive(Debug)]
#[non_exhaustive]
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub enum MessagingTest {
    /// Tests only: send one directed `msg` the way [`Messaging::Send`] does, but never take the
    /// warm fast path. A pooled connection that a direct-path probe opened between a
    /// [`Linking::ForgetUnicast`] and the send would answer at once, `Sent` or `Refused`, and a
    /// test that needs the send to wait on a dial would not see the wait. This one dials, or
    /// waits for a direct path on the pooled connection, as the cold path does.
    SendCold {
        /// The recipient, when the message is directed.
        to: Option<Nickname>,
        /// The body of the message (sealed for a directed frame on a passworded mesh).
        body: MessageBody,
        /// Gets `Ok` when the request is done, or the error text.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Tests only: ping every member and answer with the round trip time in
    /// milliseconds of each one that answered within the ping window. A test uses it to
    /// show that a pair answers over the one path it has.
    Ping {
        /// Gets each member with its round-trip time.
        reply: oneshot::Sender<Vec<(Nickname, u64)>>,
    },
}

/// Reads of the member's state and peers.
#[derive(Debug)]
#[non_exhaustive]
pub enum Inspect {
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
    /// How many members are in the mesh now, this member included: the shown peers that are not
    /// quiet, and this member. A member that is alone reads 1.
    PeerCount {
        /// Gets the count.
        reply: oneshot::Sender<usize>,
    },
}

/// Test-only reads of the member's identity, logs and rung.
#[derive(Debug)]
#[non_exhaustive]
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub enum InspectTest {
    /// Tests only: the endpoint id of this node. A test that needs the order of two
    /// ids (the lower id offers a session) reads them here.
    EndpointId {
        /// Gets the endpoint id.
        reply: oneshot::Sender<iroh::EndpointId>,
    },
    /// Tests only: how many gossip connections the recursion rule has closed since the process
    /// started (the census field `gossip_recursion_closes_total`): a total, shared by every
    /// member of the process. A pair that cannot leave the gossip path closes and dials again,
    /// so a count that grows without a bound is that loop.
    GossipRecursionCloses {
        /// Gets the count.
        reply: oneshot::Sender<u64>,
    },
    /// Tests only: the rung of the selected path on this node's pooled
    /// connection to the member `peer`: `ip`, `webrtc`, `multihop` or `relay`.
    /// It opens the connection first if there is none. This is the connection
    /// the answer is about: the gossip link is not, because the relay policy
    /// closes a gossip link that stays on the relay.
    SelectedRung {
        /// The peer, by nickname.
        peer: String,
        /// Gets the reason, or `None` when there is none.
        reply: oneshot::Sender<Option<&'static str>>,
    },
}

/// Test-only reads of routes, on a host build.
#[derive(Debug)]
#[non_exhaustive]
#[cfg(all(
    feature = "iroh-test-utils",
    feature = "host",
    not(target_arch = "wasm32")
))]
pub enum InspectHost {
    /// Tests only: whether the multihop topology of this node has a route to the
    /// member `peer` now. A route exists from the first link-state on.
    HasRoute {
        /// The peer, by nickname.
        peer: String,
        /// Gets the answer.
        reply: oneshot::Sender<bool>,
    },
    /// Tests only: the multihop view of this node as one line: its edges, and for each
    /// member the open paths of the writer connection toward its underlay, or that there
    /// is none. A writer toward a member exists only if this node sent cells to it: one
    /// toward the receiver of a cell that must go through a third member is a direct hop.
    RouteDiag {
        /// Gets the text of the answer.
        reply: oneshot::Sender<String>,
    },
}

/// Test-only link control: offer, close, drop and sever links.
#[derive(Debug)]
#[non_exhaustive]
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub enum Linking {
    /// Tests only: forget that the member `peer` is proven direct, and offer it a
    /// `WebRTC` session now, as the path watcher does when a direct path is lost.
    /// A test uses it to attach a session at a chosen moment instead of at the
    /// next alive tick.
    OfferSession {
        /// The peer, by nickname.
        peer: String,
        /// Gets `Ok` when the request is done, or `UnknownPeer` when no member has that nickname.
        reply: oneshot::Sender<Result<(), UnknownPeer>>,
    },
    /// Tests only: close the live gossip connections to the member `peer` and nothing else. The
    /// engine then runs its own `NeighborDown` path.
    CloseLink {
        /// The peer, by nickname.
        peer: String,
        /// Gets `Ok` when the request is done, or `UnknownPeer` when no member has that nickname.
        reply: oneshot::Sender<Result<(), UnknownPeer>>,
    },
    /// Tests only: forget the pooled unicast connection of the member `peer`, and its dial
    /// cooldown, and keep its address, so that the next directed send to it is cold. It answers
    /// whether a connection was pooled: a test that needs a cold send asks until the answer is
    /// `false`, because a direct-path probe can pool a connection again.
    ForgetUnicast {
        /// The peer, by nickname.
        peer: String,
        /// Gets the answer, or `UnknownPeer` when no member has that nickname.
        reply: oneshot::Sender<Result<bool, UnknownPeer>>,
    },
    /// Tests only: mark the gossip topic closed without a real end of the stream, as the heal
    /// arm reads a terminal `None`. The loop stops reading the topic, the heal tick resubscribes,
    /// and the messages that arrive in between must still reach the app.
    SeverGossip {
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
}

/// Test-only underlay tick, with multihop.
#[derive(Debug)]
#[non_exhaustive]
#[cfg(all(
    feature = "iroh-test-utils",
    not(target_arch = "wasm32"),
    feature = "multihop"
))]
pub enum Ticks {
    /// Tests only: run the underlay tick now, as the alive tick does. A test that closes a link
    /// uses it to put a tick inside the time the link is down.
    UnderlayTick {
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
}

/// Test-only reads of the underlay's sessions and counters.
#[derive(Debug)]
#[non_exhaustive]
#[cfg(all(
    feature = "iroh-test-utils",
    feature = "host",
    not(target_arch = "wasm32")
))]
pub enum Routing {
    /// Tests only: how many `WebRTC` sessions the multihop underlay of this node
    /// holds. `0` when multihop is off.
    UnderlaySessions {
        /// Gets the count.
        reply: oneshot::Sender<usize>,
    },
    /// Tests only: how many `WebRTC` sessions of this node go to a member that is
    /// neither a gossip neighbor nor the rendezvous. Such a session carries only what
    /// was sent over it, so it must go after it idled for 120 s.
    SessionsToNonNeighbors {
        /// Gets the count.
        reply: oneshot::Sender<usize>,
    },
    /// Tests only: the direct peers the ledger of the ceiling counts now, and by how many it is over
    /// the ceiling, as `(units, over_ceiling)`.
    DirectUnits {
        /// Gets the pair of counts.
        reply: oneshot::Sender<(usize, usize)>,
    },
    /// Tests only: the closes of direct connections, and how many of them were followed by
    /// a connection to the same peer within 300 s, as `[quic closes, quic re-dials, session
    /// closes, session re-dials, pool closes, pool re-dials]`. `quic` counts every live
    /// connection, the gossip links too; `pool` only the pooled unicast connections that a
    /// send used, which is what the idle close acts on. Each request samples the peers, so ask
    /// about once per second.
    RedialCounts {
        /// Gets the six counters.
        reply: oneshot::Sender<[u64; 6]>,
    },
    /// Tests only: how many multihop cells this node has passed on for other
    /// nodes. `0` when multihop is off.
    ForwardedCells {
        /// Gets the count.
        reply: oneshot::Sender<u64>,
    },
    /// Tests only: what the multihop data path of this node counted: cells passed on,
    /// dropped, refused on the relay and delivered to the local transport. All `0` when
    /// multihop is off.
    MultihopCounters {
        /// Gets the counters of the multihop transport.
        reply: oneshot::Sender<habilis_network_iroh_multihop_transport::MultihopCounters>,
    },
}

/// Test-only blocks and denials: a path, an address or a peer is cut off.
#[derive(Debug)]
#[non_exhaustive]
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub enum Blocking {
    /// Tests only, and the only request that is a test hook: take UDP away
    /// from (or give it back to) every connection in the process, and nudge
    /// this node's peers so path selection runs now: iroh re-selects only on
    /// path events.
    BlockUdp {
        /// Whether the block is on.
        blocked: bool,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: add `addr` to the addresses this node advertises, as an
    /// external address. The address of the node's endpoint changes, which is
    /// what a late home relay or an interface change does.
    AddExternalAddr {
        /// The address to advertise as external.
        address: net::SocketAddr,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: take UDP away from this node alone, to the nodes bound on
    /// `remote_ports` (see `Node::bound_ports`). An empty list gives it back.
    /// Unlike [`Blocking::BlockUdp`] it leaves every other node's paths alone,
    /// so a test can cut one group of nodes from another while each group
    /// keeps its own links.
    BlockIpTo {
        /// The ports of the remote side.
        remote_ports: Vec<u16>,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: take one rung of the path ladder away from this node alone
    /// (or give it back), to every remote. With [`Blocking::BlockIpTo`] it takes
    /// the node down the ladder one rung at a time.
    BlockRung {
        /// The rung of the path.
        rung: Rung,
        /// Whether the block is on.
        blocked: bool,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: take one rung of the path ladder away from this node alone (or
    /// give it back), to the member `peer` only. [`Blocking::BlockRung`] takes it
    /// from every remote. Only the `WebRTC` rung has a remote in its address, so
    /// only that rung is cut this way.
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
    DenyPeer {
        /// The peer, by nickname.
        peer: String,
        /// Whether the peer is denied.
        denied: bool,
        /// Gets `Ok` when the request is done, or `UnknownPeer` when no member has that nickname.
        reply: oneshot::Sender<Result<(), UnknownPeer>>,
    },
}

/// Test-only beacon and claim controls.
#[derive(Debug)]
#[non_exhaustive]
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub enum Beacons {
    /// Tests only: make the beacon of this node stop answering while it keeps its rung, as a
    /// stopped process or a wedged accept loop does. Nothing happens when it holds no beacon.
    StallBeacon {
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: shed the beacon of this node at once, as a rival re-check shed does, and leave
    /// the node to re-claim or to read the holder that is there. Nothing happens when it holds no
    /// beacon.
    ShedBeacon {
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
    /// Tests only: hold this node's rendezvous claims back (`hold`), or let it claim again. A held
    /// node claims on no heal tick and in no reclaim window, and its links are untouched. A test
    /// holds the old members of a room so that a late joiner takes the free rung first.
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
    BlindRungProbes {
        /// Whether the probes are blind.
        blind: bool,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
}

/// Test-only hold of a link's state, on a host build.
#[derive(Debug)]
#[non_exhaustive]
#[cfg(all(
    feature = "iroh-test-utils",
    feature = "host",
    not(target_arch = "wasm32")
))]
pub enum LinkHold {
    /// Tests only: hold this node's link-vector back, or let it go. Holding withdraws the vector
    /// that this node advertised from its own routing table, so that it has no outgoing edge and
    /// no route, and no tick or link event advertises one until it is let go. Letting go
    /// advertises at once. The others keep the last vector that they heard for up to three
    /// advertisement intervals, so the hold is for seconds: a test uses it to force the order
    /// "a path is lost before any route exists", where it would otherwise wait for it.
    HoldLinkState {
        /// Whether the hold is on.
        hold: bool,
        /// Gets `()` when the request is done.
        reply: oneshot::Sender<()>,
    },
}

/// A rung of the path ladder, for [`Blocking::BlockRung`].
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub use habilis_network_iroh_webrtc_transport::Rung;

/// The engine seam. Every inbound `msg` is queued for the consumer instead of
/// being written anywhere: a browser's `js_sys::Function` is neither `Send`
/// nor `Sync`, and [`NodeApp`] is `Send`, so the driver could not keep one even
/// if it wanted to. Consumers drain the queue on their own schedule.
///
/// # Examples
///
/// The app of a membership node serves its requests, and depart takes that node. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::membership::{Membership, depart};
///
/// # async fn demo(member: Membership) {
/// // member.node is the node that runs a MembershipApp.
/// depart(member.node).await.expect("depart");
/// # }
/// ```
#[derive(Debug, Clone)]
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
        context: &HandlerCtx<'_>,
    ) -> bool {
        let InboundApp {
            message,
            surfaceable: _,
        } = frame;
        if message.kind.app_tag().map(AppTag::as_str) != Some(MSG_TAG) {
            return false;
        }
        // The engine hands over a directed frame for another key too: only a frame for this
        // key, or a broadcast, is a message to the member.
        if let MessageKind::App { to: Some(to), .. } = &message.kind
            && *to != context.our_pubkey
        {
            return false;
        }
        let directed = matches!(message.kind, MessageKind::App { to: Some(_), .. });
        let text = message.body.as_str().to_owned();
        let inbound = Inbound {
            nick: message.author.to_string(),
            key: message.key(),
            directed,
            text,
        };
        // Full or closed: the caller is not draining. Dropping is the only
        // option that neither blocks the event loop nor grows without bound.
        let queued = self.inbound.try_send(inbound).is_ok();
        if self.stall_began(queued) {
            context.sink.emit(NodeEvent::Error(
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

    async fn handle_session(
        &mut self,
        request: Request,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            Request::Messaging(request) => self.handle_messaging(request, state, context).await,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::MessagingTest(request) => {
                self.handle_messaging_test(request, state, context).await
            }
            Request::Inspect(request) => Self::handle_inspect(request, state),
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::InspectTest(request) => Self::handle_inspect_test(request, state, context),
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::InspectHost(request) => Self::handle_inspect_host(request, state),
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::Linking(request) => self.handle_linking(request, state, context).await,
            #[cfg(all(
                feature = "iroh-test-utils",
                not(target_arch = "wasm32"),
                feature = "multihop"
            ))]
            Request::Ticks(request) => Self::handle_ticks(request, state),
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::Routing(request) => Self::handle_routing(request, state, context),
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::Blocking(request) => self.handle_blocking(request, state, context).await,
            #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
            Request::Beacons(request) => Self::handle_beacons(request, state, context),
            #[cfg(all(
                feature = "iroh-test-utils",
                feature = "host",
                not(target_arch = "wasm32")
            ))]
            Request::LinkHold(request) => self.handle_link_hold(request, state, context).await,
        }
    }
}

impl MembershipApp {
    /// Send one `msg` frame to `to` (a broadcast for `None`) and answer `reply` with the outcome.
    /// Returns `true`: a frame that went out is a live frame.
    async fn send_msg(
        &mut self,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
        to: Option<AuthorKey>,
        body: MessageBody,
        reply: oneshot::Sender<Result<(), String>>,
    ) -> bool {
        let frame = app_frame(
            context,
            AppFrameParams::new(
                AppTag::try_new(MSG_TAG).expect("a valid app tag"),
                to,
                None,
                body,
            ),
        );
        match send_app(state, context, frame).await {
            Ok(Delivered::Done) => {
                let _ = reply.send(Ok(()));
            }
            Ok(Delivered::Pending(handle)) => {
                // The dial runs on a task, and so does the wait for its outcome: the loop
                // serves the next request meanwhile.
                task::spawn(async move {
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

    async fn handle_messaging(
        &mut self,
        request: Messaging,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            Messaging::Send { to, body, reply } => {
                let to = match recipient_key(state, to) {
                    Ok(to) => to,
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        return false;
                    }
                };
                self.send_msg(state, context, to, body, reply).await
            }
            Messaging::SendToKey { to, body, reply } => {
                self.send_msg(state, context, Some(to), body, reply).await
            }
            Messaging::StateMerge { merge, reply } => {
                let merged = broadcast_state_merge(
                    state,
                    StateMergeParams::new(context.into(), Channel::State, merge),
                )
                .await;
                let outcome = merged.map_err(|error| error.to_string());
                let _ = reply.send(outcome);
                // A durable write is not a live frame: it proves life only within one alive
                // timeout of the clock of the reader, so it must not hold back the `alive`.
                false
            }
        }
    }

    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    async fn handle_messaging_test(
        &mut self,
        request: MessagingTest,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            MessagingTest::SendCold { to, body, reply } => {
                let to = match recipient_key(state, to) {
                    Ok(to) => to,
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        return false;
                    }
                };
                let frame = app_frame(
                    context,
                    AppFrameParams::new(
                        AppTag::try_new(MSG_TAG).expect("a valid app tag"),
                        to,
                        None,
                        body,
                    ),
                );
                let routed: Result<_, String> = frame
                    .serialize()
                    .map_err(|error| error.to_string())
                    .and_then(|bytes| {
                        transport::resolve(&frame, bytes, state).map_err(|error| error.to_string())
                    });
                match routed {
                    Ok(Resend::Unicast(eid, bytes)) => {
                        let pool = state.unicast_pool.clone();
                        let registration = pool.register_dial(eid);
                        task::spawn(async move {
                            let sent = pool
                                .send_registered(registration, eid, bytes.into_bytes())
                                .await;
                            let _ = reply.send(sent.map_err(|error| error.to_string()));
                        });
                    }
                    Ok(Resend::Broadcast(_)) => {
                        let _ = reply.send(Err("a cold send needs a directed message".to_owned()));
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
                true
            }
            MessagingTest::Ping { reply } => {
                ops::start_ping_round(state, context, Some(reply)).await;
                true
            }
        }
    }

    fn handle_inspect(request: Inspect, state: &mut EventLoopState) -> bool {
        match request {
            Inspect::StateJson { reply } => {
                let state_json = state.doc(Channel::State).to_json().to_string();
                let _ = reply.send(state_json);
                false
            }
            Inspect::Peers { reply } => {
                let snapshot = state.roster_snapshot();
                let json = serde_json::to_string(&snapshot)
                    .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"));
                let _ = reply.send(json);
                false
            }
            Inspect::PeerCount { reply } => {
                // The one count of the engine: see `EventLoopState::member_count`.
                let _ = reply.send(state.member_count());
                false
            }
        }
    }

    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    fn handle_inspect_test(
        request: InspectTest,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            InspectTest::GossipRecursionCloses { reply } => {
                let _ = reply.send(payload_path::gossip_recursion_closes());
                false
            }
            InspectTest::EndpointId { reply } => {
                let _ = reply.send(context.endpoint.id());
                false
            }
            InspectTest::SelectedRung { peer, reply } => {
                let id = known_peer(state, &peer).ok().map(|address| address.id);
                let pool = state.unicast_pool.clone();
                // Off the event loop: a dial can take seconds.
                task::spawn(async move {
                    let rung = match id {
                        Some(id) => pool.warm_or_dial(id).await.ok().and_then(|connection| {
                            let rung = payload_path::selected_rung(&connection);
                            // The same stable id twice is one connection read twice: a test that
                            // waits for a rung can see whether the connection it reads is the one
                            // that climbed.
                            tracing::debug!(
                                target: "habilis_network::transport",
                                peer = %id,
                                connection = connection.stable_id(),
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
        }
    }

    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    fn handle_inspect_host(request: InspectHost, state: &mut EventLoopState) -> bool {
        match request {
            InspectHost::HasRoute { peer, reply } => {
                let has_route: bool = known_peer(state, &peer).is_ok_and(|address| {
                    state.multihop().is_some_and(|handle| {
                        handle
                            .route_addr(habilis_network_iroh_multihop_transport::AppId::new(
                                address.id,
                            ))
                            .is_some()
                    })
                });
                let _ = reply.send(has_route);
                false
            }
            InspectHost::RouteDiag { reply } => {
                let _ = reply.send(route_diag(state));
                false
            }
        }
    }

    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    async fn handle_linking(
        &mut self,
        request: Linking,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            Linking::OfferSession { peer, reply } => {
                let result = known_peer(state, &peer).cloned().map(|address| {
                    state.direct.insert(address.id, DirectState::RelayOnly);
                    webrtc::negotiate_session::negotiate_session(
                        state, context, address.id, address,
                    );
                });
                let _ = reply.send(result);
                false
            }
            Linking::CloseLink { peer, reply } => {
                let result = known_peer(state, &peer).map(|address| {
                    payload_path::close_gossip_links_to(address.id);
                });
                let _ = reply.send(result);
                false
            }
            Linking::ForgetUnicast { peer, reply } => {
                let id = known_peer(state, &peer).map(|address| address.id);
                let pool = &state.unicast_pool;
                let outcome = match id {
                    Ok(id) => Ok(pool.drop_connection(id).await),
                    Err(unknown) => Err(unknown),
                };
                let _ = reply.send(outcome);
                false
            }
            Linking::SeverGossip { reply } => {
                state.standing.remove(&Standing::GossipOpen);
                let _ = reply.send(());
                false
            }
        }
    }

    #[cfg(all(
        feature = "iroh-test-utils",
        not(target_arch = "wasm32"),
        feature = "multihop"
    ))]
    fn handle_ticks(request: Ticks, state: &mut EventLoopState) -> bool {
        match request {
            Ticks::UnderlayTick { reply } => {
                underlay_webrtc::tick_now(state);
                let _ = reply.send(());
                false
            }
        }
    }

    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    fn handle_routing(
        request: Routing,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            Routing::UnderlaySessions { reply } => {
                let sessions = state
                    .underlay_webrtc
                    .as_ref()
                    .map_or(0, |underlay| underlay.handle.session_count());
                let _ = reply.send(sessions);
                false
            }
            Routing::SessionsToNonNeighbors { reply } => {
                let sessions: usize = state.webrtc.as_ref().map_or(0, |webrtc| {
                    state
                        .member_addresses()
                        .iter()
                        .filter(|address| {
                            webrtc.has_session(&address.id)
                                && !state.linked_endpoints.contains(&address.id)
                                && address.id != context.rendezvous_id
                        })
                        .count()
                });
                let _ = reply.send(sessions);
                false
            }
            Routing::DirectUnits { reply } => {
                let _ = reply.send((
                    state.webrtc_admission.direct_units(),
                    state.webrtc_admission.over_ceiling(),
                ));
                false
            }
            Routing::RedialCounts { reply } => {
                let now = clock::Instant::now();
                let ids: Vec<_> = state
                    .member_addresses()
                    .iter()
                    .map(|address| address.id)
                    .collect();
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
                let mut counts = [0_u64; 6];
                (counts[0], counts[1]) =
                    (state.redials.quic.closes(), state.redials.quic.redials());
                (counts[2], counts[3]) = (
                    state.redials.session.closes(),
                    state.redials.session.redials(),
                );
                (counts[4], counts[5]) =
                    (state.redials.pool.closes(), state.redials.pool.redials());
                let _ = reply.send(counts);
                false
            }
            Routing::ForwardedCells { reply } => {
                let forwarded = state.multihop().map_or(
                    0,
                    habilis_network_iroh_multihop_transport::MultihopHandle::forwarded_cells,
                );
                let _ = reply.send(forwarded);
                false
            }
            Routing::MultihopCounters { reply } => {
                let counters = state.multihop().map_or_else(
                    Default::default,
                    habilis_network_iroh_multihop_transport::MultihopHandle::counters,
                );
                let _ = reply.send(counters);
                false
            }
        }
    }

    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    async fn handle_blocking(
        &mut self,
        request: Blocking,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            Blocking::BlockIpTo {
                remote_ports,
                reply,
            } => {
                habilis_network_iroh_webrtc_transport::block_ip_to(
                    context.endpoint.id(),
                    remote_ports,
                );
                // iroh re-selects only on path events: nudge every peer so the
                // new set takes effect now.
                for address in &state.member_addresses() {
                    let endpoint = context.endpoint.clone();
                    let peer = address.id;
                    task::spawn(async move {
                        webrtc::nudge_acceptor::nudge(&endpoint, peer).await;
                    });
                }
                let _ = reply.send(());
                false
            }
            Blocking::BlockRung {
                rung,
                blocked,
                reply,
            } => {
                habilis_network_iroh_webrtc_transport::block_rung(
                    context.endpoint.id(),
                    rung,
                    blocked,
                );
                // iroh re-selects only on path events: nudge every peer so the
                // change takes effect now.
                for address in &state.member_addresses() {
                    let endpoint = context.endpoint.clone();
                    let peer = address.id;
                    task::spawn(async move {
                        webrtc::nudge_acceptor::nudge(&endpoint, peer).await;
                    });
                }
                let _ = reply.send(());
                false
            }
            Blocking::BlockRungTo {
                rung,
                peer,
                blocked,
                reply,
            } => {
                let result = known_peer(state, &peer).map(|address| {
                    let remote = address.id;
                    habilis_network_iroh_webrtc_transport::block_rung_to(
                        context.endpoint.id(),
                        rung,
                        remote,
                        blocked,
                    );
                    let endpoint = context.endpoint.clone();
                    task::spawn(async move {
                        webrtc::nudge_acceptor::nudge(&endpoint, remote).await;
                    });
                });
                let _ = reply.send(result);
                false
            }
            Blocking::DenyPeer {
                peer,
                denied,
                reply,
            } => {
                let member = known_peer(state, &peer).map(|address| address.id);
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
            Blocking::AddExternalAddr { address, reply } => {
                context.endpoint.add_external_addr(address).await;
                let _ = reply.send(());
                false
            }
            Blocking::BlockUdp { blocked, reply } => {
                habilis_network_iroh_webrtc_transport::block_ip_paths(blocked);
                for address in &state.member_addresses() {
                    let endpoint = context.endpoint.clone();
                    let peer = address.id;
                    task::spawn(async move {
                        webrtc::nudge_acceptor::nudge(&endpoint, peer).await;
                    });
                }
                let _ = reply.send(());
                false
            }
        }
    }

    #[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
    fn handle_beacons(
        request: Beacons,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            Beacons::StallBeacon { reply } => {
                state.test_holds.insert(TestHold::Stall);
                let _ = reply.send(());
                false
            }
            Beacons::ShedBeacon { reply } => {
                state.test_holds.insert(TestHold::Shed);
                let _ = reply.send(());
                false
            }
            Beacons::HoldClaims { hold, reply } => {
                if hold {
                    state.test_holds.insert(TestHold::Claims);
                } else {
                    state.test_holds.remove(&TestHold::Claims);
                }
                let _ = reply.send(());
                false
            }
            Beacons::BlindRungProbes { blind, reply } => {
                beacon::set_blind_rung_probes(context.endpoint.id(), blind);
                let _ = reply.send(());
                false
            }
        }
    }

    #[cfg(all(
        feature = "iroh-test-utils",
        feature = "host",
        not(target_arch = "wasm32")
    ))]
    async fn handle_link_hold(
        &mut self,
        request: LinkHold,
        state: &mut EventLoopState,
        context: &HandlerCtx<'_>,
    ) -> bool {
        match request {
            LinkHold::HoldLinkState { hold, reply } => {
                if hold {
                    state.test_holds.insert(TestHold::LinkState);
                } else {
                    state.test_holds.remove(&TestHold::LinkState);
                }
                state.last_advertised = None;
                if hold && let Some(handle) = state.multihop() {
                    let _ = handle.remove_origin(handle.app_id());
                }
                if !hold {
                    event_loop::linkstate_arm(state, context).await;
                }
                let _ = reply.send(());
                false
            }
        }
    }
}

/// Tests only: the member that a request names is not in the book of this node. A request on it
/// does nothing; the node says so, and the test waits for the `PeerInfo` that brings the member.
///
/// # Examples
///
/// A name that is not a member of the mesh is reported with this type. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::membership::UnknownPeer;
///
/// # fn demo(peer: UnknownPeer) {
/// drop(peer);
/// # }
/// ```
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownPeer(pub String);

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
impl UnknownPeer {
    /// The peer that was not found.
    #[must_use]
    pub fn new(peer: String) -> Self {
        Self(peer)
    }
}

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
impl fmt::Display for UnknownPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the member {:?} is not in the book of this node", self.0)
    }
}

#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
impl error::Error for UnknownPeer {}

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
        let peer = state
            .peer_endpoints
            .iter()
            .find(|(_, address)| address.id.to_string() == id);
        match peer {
            Some((nickname, _)) => {
                let text: &str = nickname.borrow();
                text.to_owned()
            }
            None => id.chars().take(10).collect(),
        }
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
        .filter_map(|(nickname, address)| {
            let underlay = handle.underlay_addr_of(
                habilis_network_iroh_multihop_transport::AppId::new(address.id),
            )?;
            let text: &str = nickname.borrow();
            let open: String = handle
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
mod peer_count_tests {
    use std::sync::atomic::Ordering;

    use super::{Inspect, MembershipApp};
    use crate::daemon::setup::LiveCount;
    use crate::daemon::state::EventLoopState;
    use crate::testing::{fresh_state, test_key};
    use tokio::sync::oneshot;

    /// How many members the consumer reads for `Inspect::PeerCount`.
    fn peer_count_of(state: &mut EventLoopState) -> usize {
        let (reply, mut answer) = oneshot::channel();
        MembershipApp::handle_inspect(Inspect::PeerCount { reply }, state);
        answer.try_recv().expect("the handler answers at once")
    }

    /// `PeerCount` answers "how many members are in the mesh right now, this node included". A
    /// quiet peer is a row of the roster, but it is not in the mesh now: a member whose only peer
    /// went quiet reads 1, the same as a member that is alone.
    #[test]
    fn the_peer_count_leaves_out_quiet_peers() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        state.peer_for_test("swift-cedar");
        state.surfaced_for_test("swift-cedar");
        state.quiet_for_test("lost-heron");

        assert_eq!(
            peer_count_of(&mut state),
            2,
            "a quiet peer counts as a member that is in the mesh"
        );

        state.peers.remove(&test_key("swift-cedar"));
        state.quiet_for_test("swift-cedar");
        assert_eq!(
            peer_count_of(&mut state),
            1,
            "a member whose peers are all quiet reads as alone"
        );
    }

    /// A member that is alone counts itself.
    #[test]
    fn a_lone_member_counts_itself() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();

        assert_eq!(peer_count_of(&mut state), 1, "a lone member reads 0, not 1");
    }

    /// One algorithm for every surface that shows a count. The state has a shown peer, a peer
    /// that is surfaced and quiet, a live peer that is not shown yet, and a peer that left. Only
    /// the shown peer and this node count, so the answer is 2 everywhere: the member count, the
    /// peer count of the embed, the count of the roster snapshot, the non-quiet rows plus this
    /// node, and the live counter (which the state file and the directory advert read).
    #[test]
    fn every_surface_shows_the_same_count() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let live = LiveCount::default();
        state.live_count = Some(live.clone());
        state.peer_for_test("swift-cedar");
        state.surfaced_for_test("swift-cedar");
        state.surfaced_for_test("lost-heron");
        state.quiet_for_test("lost-heron");
        state.peer_for_test("calm-otter");
        state.write_peer_count();

        let roster = state.roster_snapshot();
        let live_rows = roster.peers.iter().filter(|entry| !entry.quiet).count();
        let quiet_rows = roster.peers.iter().filter(|entry| entry.quiet).count();
        assert_eq!(quiet_rows, 1, "the quiet peer is a row with quiet: true");
        let counts = [
            ("member_count", state.member_count()),
            ("Inspect::PeerCount", peer_count_of(&mut state)),
            ("roster count", roster.count),
            ("non-quiet rows plus this node", live_rows + 1),
            ("live counter", live.load(Ordering::Relaxed)),
        ];
        for (surface, count) in counts {
            assert_eq!(count, 2, "{surface} disagrees with the member count");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppFrameParams, AppTag, ENVELOPE_RESERVE, ESCAPED_BUDGET, MAX_MESSAGE_SIZE, MAX_MSG,
        MSG_TAG, MembershipApp, MessageBody, Messaging, Nickname, Request, mpsc, msg_body,
        msg_fits, parse_key, recipient_key, transport,
    };
    #[cfg(feature = "host")]
    use crate::daemon::state::Standing;
    #[cfg(feature = "host")]
    use crate::gossip::app::{InboundApp, NodeApp};
    use crate::protocol::{AuthorKey, Identity, Lookup, MeshConfig, MeshId, Message, RelayLadder};
    use crate::runtime;
    #[cfg(feature = "host")]
    use crate::testing::LaneNode;
    use crate::testing::{fresh_state, test_key};

    #[cfg(feature = "host")]
    use super::NodeDriver;
    use std::iter;
    #[cfg(feature = "host")]
    use tokio::sync::oneshot;
    /// The longest nickname there is: 32 four-byte scalars.
    fn widest_nick(seed: char) -> Nickname {
        let text: String = iter::repeat_n(seed, 32).collect();
        Nickname::try_new(&text).expect("32 scalars")
    }

    /// A mesh id well past the common case: every lookup and a four-rung
    /// custom relay ladder.
    fn long_mesh() -> MeshId {
        let urls: Vec<String> = (0..4)
            .map(|rung| format!("https://relay-{rung}.a-rather-long-relay-domain.example/"))
            .collect();
        let ladder: RelayLadder = urls.join(",").parse().expect("ladder");
        let config = MeshConfig::resolve(
            &[Lookup::Mdns, Lookup::Dht, Lookup::Relay],
            Some(ladder),
            &[],
        )
        .expect("config");
        let mesh = runtime::derive_topic_mesh_config("standup", config).expect("mesh");
        MeshId::try_new(&mesh.to_string()).expect("id")
    }

    fn signed_len(text: &str) -> usize {
        Message::new_app(
            &long_mesh(),
            &widest_nick('\u{1F980}'),
            AppFrameParams::new(
                AppTag::try_new(MSG_TAG).expect("a valid app tag"),
                Some(AuthorKey::from_bytes([0xab; 32])),
                None,
                MessageBody::try_new(text).expect("body"),
            ),
        )
        .sign(&Identity::generate())
        .wire_len()
    }

    /// A send by nickname names the one live key that uses it. A nickname that no live key uses,
    /// or that two or more use, is refused with the cause, and a send with no nickname is a
    /// broadcast. The frame names a key, so the engine never picks one of two.
    #[test]
    fn a_send_by_nickname_resolves_to_the_one_live_key_and_refuses_the_rest() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let alone = test_key("alone");
        state.names.insert(alone, Nickname::from("alone"));
        state.peers.insert(alone);
        for key in [test_key("twin#first"), test_key("twin#second")] {
            state.names.insert(key, Nickname::from("twin"));
            state.peers.insert(key);
        }

        assert_eq!(
            recipient_key(&state, Some(Nickname::from("alone"))),
            Ok(Some(alone)),
            "one live key uses the nickname"
        );
        assert_eq!(
            recipient_key(&state, None),
            Ok(None),
            "no nickname is a broadcast"
        );
        let clash = recipient_key(&state, Some(Nickname::from("twin")))
            .expect_err("two live keys use the nickname");
        assert!(
            clash.contains("two or more live peers use this nickname"),
            "the refusal does not name the cause: {clash}"
        );
        let stranger = recipient_key(&state, Some(Nickname::from("nobody")))
            .expect_err("no live key uses the nickname");
        assert!(
            stranger.contains("no live peer uses this nickname"),
            "the refusal does not name the cause: {stranger}"
        );
    }

    /// A peer that went quiet may return, and a send by nickname to it was sent before: it goes to
    /// the hint of the quiet key. A live key of the nickname wins over a quiet one, and two quiet
    /// keys with no live key are as ambiguous as two live keys.
    #[test]
    fn a_send_by_nickname_to_the_only_quiet_key_of_it_is_sent() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let (sleeper, live, quiet) = (
            test_key("sleeper"),
            test_key("mixed#live"),
            test_key("mixed#quiet"),
        );
        state.names.insert(sleeper, Nickname::from("sleeper"));
        state.quiet.insert(sleeper);
        state.names.insert(live, Nickname::from("mixed"));
        state.peers.insert(live);
        state.names.insert(quiet, Nickname::from("mixed"));
        state.quiet.insert(quiet);
        for key in [test_key("snooze#first"), test_key("snooze#second")] {
            state.names.insert(key, Nickname::from("snooze"));
            state.quiet.insert(key);
        }

        assert_eq!(
            recipient_key(&state, Some(Nickname::from("sleeper"))),
            Ok(Some(sleeper)),
            "the only key of the nickname is quiet, and it may return"
        );
        assert_eq!(
            recipient_key(&state, Some(Nickname::from("mixed"))),
            Ok(Some(live)),
            "a live key wins over a quiet key of the same nickname"
        );
        let clash = recipient_key(&state, Some(Nickname::from("snooze")))
            .expect_err("two quiet keys use the nickname");
        assert!(
            clash.contains("two or more"),
            "the refusal does not name the cause: {clash}"
        );
    }

    #[test]
    fn the_envelope_fits_its_reserve() {
        let _guard = ::habilis_network_test_tracing::init();
        let envelope = signed_len("");
        assert!(envelope <= ENVELOPE_RESERVE, "envelope is {envelope} bytes");
    }

    /// `msg_fits` must never say yes to a text `send_app` would refuse, at
    /// either end of the escaping range.
    #[test]
    fn a_text_msg_fits_accepts_signs_within_one_frame() {
        let _guard = ::habilis_network_test_tracing::init();
        for text in [
            "\"".repeat(MAX_MSG),
            "a".repeat(ESCAPED_BUDGET),
            "\u{1F980}".repeat(ESCAPED_BUDGET / 4),
        ] {
            assert!(
                msg_fits(&text),
                "a text message of signs fits within one frame"
            );
            let len = signed_len(&text);
            assert!(len <= MAX_MESSAGE_SIZE, "{len} bytes");
        }
        assert!(
            !msg_fits(&"\"".repeat(MAX_MSG + 1)),
            "a message of quotes past the budget does not fit"
        );
        assert!(
            !msg_fits(&"a".repeat(ESCAPED_BUDGET + 1)),
            "an escaped message past its budget does not fit"
        );
    }

    /// A caller of a binding holds the key as text. The parse reads the one form the wire
    /// carries and refuses every other form with the cause, so a bad key is an error and not a send.
    #[test]
    fn a_key_is_read_from_64_lowercase_hex_and_nothing_else() {
        let _guard = ::habilis_network_test_tracing::init();
        let key = test_key("parse#key");
        let text: String = String::from_utf8(key.hex().to_vec()).expect("hex is ASCII");

        assert_eq!(
            parse_key(&text).expect("the hex of a key"),
            key,
            "parse_key did not read back the key that the hex was made from"
        );
        for (bad, why) in [
            ("", "an empty text"),
            (&text[..63], "63 digits"),
            (&format!("{text}0"), "65 digits"),
            (&text.to_uppercase(), "uppercase digits"),
            (&format!("{}g", &text[..63]), "a character that is not hex"),
            ("alice", "a nickname"),
        ] {
            assert!(
                matches!(
                    parse_key(bad),
                    Err(transport::SendError::InvalidAddressee(_))
                ),
                "{why} was read as a key"
            );
        }
    }

    #[test]
    fn a_body_round_trips_and_refuses_what_it_cannot_carry() {
        let _guard = ::habilis_network_test_tracing::init();
        let text = "ol\u{e1}, \"mesh\"\n\ttab";
        assert_eq!(
            msg_body(text).expect("body").as_str(),
            text,
            "a body round trips to the same text"
        );
        assert!(
            msg_body("bell\u{7}").is_err(),
            "a bell character is refused in a body"
        );
        assert!(
            msg_body(&"\"".repeat(MAX_MSG + ESCAPED_BUDGET)).is_err(),
            "a body of quotes past the budget is refused"
        );
    }

    #[test]
    fn a_stall_surfaces_once_until_the_queue_drains() {
        let _guard = ::habilis_network_test_tracing::init();
        let (inbound, _queue) = mpsc::channel(1);
        let mut app = MembershipApp::new(inbound);
        let surfaced: Vec<bool> = [true, false, false, false, true, false]
            .into_iter()
            .map(|queued| app.stall_began(queued))
            .collect();
        assert_eq!(
            surfaced,
            [false, true, false, false, false, true],
            "a stall surfaces once until the queue drains"
        );
    }

    /// The loop refreshes the keepalive clock when a session request reports a broadcast. A
    /// durable write is stamped by the clock of the writer and does not prove life to a peer that
    /// is quiet, so it must not hold back the `alive` that does.
    #[cfg(feature = "host")]
    #[test]
    fn a_state_merge_does_not_report_a_live_broadcast() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = LaneNode::start().await;
            let context = node.context();
            let mut state = node.state();
            let (inbound, _queue) = mpsc::channel(1);
            let mut app = MembershipApp::new(inbound);
            let (reply, answer) = oneshot::channel();
            let request = Request::Messaging(Messaging::StateMerge {
                merge: serde_json::json!({"note": "durable"}),
                reply,
            });

            let live = app.handle_session(request, &mut state, &context).await;

            assert_eq!(
                answer.await.expect("the request is answered"),
                Ok(()),
                "the merge was made and broadcast"
            );
            assert!(
                !live,
                "a state merge is a durable write and does not refresh the keepalive clock"
            );
            node.endpoint.close().await;
        });
    }

    /// Two live keys use one nickname. A send by nickname is refused, because the engine never
    /// picks one of them. A send to a key is refused at once while unmeshed: a directed frame is
    /// not buffered, so nothing is queued for the caller's key.
    #[cfg(feature = "host")]
    #[test]
    fn a_send_to_a_key_of_two_keys_that_share_a_nickname_is_refused_while_unmeshed() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = LaneNode::start().await;
            let context = node.context();
            let mut state = node.state();
            state.standing.remove(&Standing::Meshed);
            let (first, second) = (test_key("twin#first"), test_key("twin#second"));
            for key in [first, second] {
                state.names.insert(key, Nickname::from("twin"));
                state.peers.insert(key);
            }
            let (inbound, _queue) = mpsc::channel(1);
            let mut app = MembershipApp::new(inbound);

            let (reply, by_nickname) = oneshot::channel();
            let request = Request::Messaging(Messaging::Send {
                to: Some(Nickname::from("twin")),
                body: MessageBody::from("hi"),
                reply,
            });
            app.handle_session(request, &mut state, &context).await;
            let refused = by_nickname
                .await
                .expect("the request is answered")
                .expect_err("a send to a nickname of two live keys");
            assert!(
                refused.contains("two or more live peers use this nickname"),
                "the refusal does not name the cause: {refused}"
            );
            assert!(
                state.pending_outbound.is_empty(),
                "the refused send was buffered"
            );

            let (key_reply, by_key) = oneshot::channel();
            let to_key = Request::Messaging(Messaging::SendToKey {
                to: second,
                body: MessageBody::from("hi"),
                reply: key_reply,
            });
            app.handle_session(to_key, &mut state, &context).await;
            let outcome = by_key.await.expect("the request is answered");
            assert!(
                matches!(outcome, Err(ref error) if error.contains("not meshed yet")),
                "the send to a key of the nickname was not refused while unmeshed: {outcome:?}"
            );
            assert!(
                state.pending_outbound.is_empty(),
                "the refused directed frame was buffered"
            );
            node.endpoint.close().await;
        });
    }

    /// A key that no roster, quiet set or address holds has no one to wait for. A meshed node
    /// refuses a send to it with that cause, as an unmeshed node does. The cause "no known endpoint
    /// (`PeerInfo` not yet received)" would tell a caller with a mistyped key to wait.
    #[cfg(feature = "host")]
    #[test]
    fn a_send_to_a_key_that_nobody_holds_names_that_cause_on_a_meshed_node() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = LaneNode::start().await;
            let context = node.context();
            let mut state = node.state();
            state.standing.insert(Standing::Meshed);
            let (inbound, _queue) = mpsc::channel(1);
            let mut app = MembershipApp::new(inbound);

            let (reply, answer) = oneshot::channel();
            let request = Request::Messaging(Messaging::SendToKey {
                to: test_key("nobody#holds-this"),
                body: MessageBody::from("hi"),
                reply,
            });
            app.handle_session(request, &mut state, &context).await;

            let refused = answer
                .await
                .expect("the request is answered")
                .expect_err("a send to a key that nobody holds");
            assert!(
                refused.contains("no roster, quiet set or known address holds this key"),
                "the refusal does not name the cause: {refused}"
            );
            assert!(
                state.pending_outbound.is_empty(),
                "the refused send was buffered"
            );
            node.endpoint.close().await;
        });
    }

    /// The engine hands a directed frame for another key to the app too. A member that shares a
    /// nickname with that key is another peer, so its queue holds only the frames for its own
    /// key, and the broadcasts.
    #[cfg(feature = "host")]
    #[test]
    fn the_member_app_queues_a_directed_frame_only_for_its_own_key() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = LaneNode::start().await;
            let context = node.context();
            let mut state = node.state();
            let (inbound, mut queue) = mpsc::channel(4);
            let mut app = MembershipApp::new(inbound);
            let sender = Identity::generate();
            let frame_to = |to: Option<AuthorKey>, text: &str| {
                let params = AppFrameParams::new(
                    AppTag::try_new(MSG_TAG).expect("a valid app tag"),
                    to,
                    None,
                    MessageBody::from(text),
                );
                Message::new_app(&MeshId::from("test"), &Nickname::from("alice"), params)
                    .sign(&sender)
            };
            let other = test_key("twin#other");

            for (to, text, kept) in [
                (Some(other), "for the other key", false),
                (Some(context.our_pubkey), "for this key", true),
                (None, "for everyone", true),
            ] {
                let frame = frame_to(to, text);
                let retain = app
                    .on_app_frame(
                        InboundApp {
                            message: &frame.authored(),
                            surfaceable: true,
                        },
                        &mut state,
                        &context,
                    )
                    .await;
                assert!(!retain, "the member app never asks to retain a frame");
                assert_eq!(
                    queue.try_recv().is_ok(),
                    kept,
                    "the queue of the member took, or missed, the frame {text:?}"
                );
            }
            node.endpoint.close().await;
        });
    }

    /// Two members can use one nickname, so the nickname of an inbound message names no
    /// author. The message carries the key, and a reply to that key reaches only its author.
    #[cfg(feature = "host")]
    #[test]
    fn an_inbound_message_names_the_key_of_its_author() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let node = LaneNode::start().await;
            let context = node.context();
            let mut state = node.state();
            let (inbound, mut queue) = mpsc::channel(4);
            let mut app = MembershipApp::new(inbound);
            let twins = [Identity::generate(), Identity::generate()];

            let mesh = MeshId::from("test");
            let nickname = Nickname::from("twin");
            for twin in &twins {
                let params = AppFrameParams::new(
                    AppTag::try_new(MSG_TAG).expect("a valid app tag"),
                    None,
                    None,
                    MessageBody::from("hello"),
                );
                let frame = Message::new_app(&mesh, &nickname, params).sign(twin);
                app.on_app_frame(
                    InboundApp {
                        message: &frame.authored(),
                        surfaceable: true,
                    },
                    &mut state,
                    &context,
                )
                .await;
            }

            let keys: Vec<AuthorKey> = vec![
                queue.try_recv().expect("the first message is queued").key,
                queue.try_recv().expect("the second message is queued").key,
            ];
            assert_eq!(
                keys,
                [twins[0].author_key(), twins[1].author_key()],
                "an inbound message does not name the key of its author"
            );
            node.endpoint.close().await;
        });
    }
}
