//! Gossip **outbound/send plane** (engine primitives): fire-and-forget
//! broadcast, the shared-state merge write, and presence / `PeerInfo`
//! announcements. The application payload send path (broadcast chat, task
//! legs, directed RPC) lives app-side in the application's send plane; this layer only
//! carries the generic transport primitives the app rides. Inbound dispatch
//! lives in [`super::recv`].

use crate::daemon::state::{Latch, PeerInfoFlood, RendezvousFlag, Standing};
use std::fmt;

use crate::transport::MeshSender;

use crate::daemon::handler_ctx::HandlerCtx;
use crate::daemon::state::{EventLoopState, PingRound};
use crate::doc::wire;
use crate::gossip::app::{AppFrameError, NodeApp};
use crate::gossip::event::{NodeEvent, NodeSink};
use crate::protocol::messages::{AppFrameParams, Verified, WireFrame, sole_addressee};
use crate::protocol::{Channel, MeshId, Message, MessageBody, Nickname};
use crate::util::consts::MAX_MESSAGE_SIZE;
use habilis_network_doc::{ChunkPointer, SliceError};

use crate::logging::messages;
use crate::protocol::{peer_addr_error, seal_error};
use crate::transport;
use crate::transport::{probe, proven_endpoints, webrtc};
use crate::util::{clock, tuning};
use n0_future::task;
use n0_future::time::Instant as n0future_Instant;
use tokio::sync::oneshot;
/// Build → sign → deliver one outbound `App` frame — the payload-generic
/// counterpart to the application's own (chain-stamping, sharding, sealing) chat /
/// task builders. A consumer with its own data model emits its `App`-tagged payloads through
/// this one primitive: it stamps the frame with `tag`/`to`/`corr`, signs it with
/// the loop identity, and routes it with the same single-send decision the application
/// path uses ([`crate::transport::deliver`]) — unicast to a sole addressee,
/// gossip for a broadcast (`to == None`).
///
/// Reliability: a broadcast frame sent while unmeshed is buffered into `pending_outbound` and
/// flushed on the meshed edge (see `gossip::recv::flush_pending`). A directed frame is never
/// buffered: a send that cannot reach its addressee now returns an error, and the caller decides
/// whether to retry.
///
/// This is a **single-frame** send: unlike the application's chat path it does not split a
/// large body across shards (that logic is entangled with the application's per-author hash
/// chain), so `body` must fit one wire frame. A body whose signed frame would
/// exceed [`MAX_MESSAGE_SIZE`] is refused rather than silently dropped by the
/// gossip actor; a bytes-carrying consumer chunks its stream below that bound.
/// The size is checked after the seal: `frame` comes from [`app_frame`], which seals the body
/// before it signs (a directed body of a tag that seals, and a broadcast body on a passworded
/// mesh), so the signed frame is the one that goes on the wire. This function seals nothing itself.
///
/// The app classifies the frame (`app.classify(&frame)`) on the inbound side, and the send does
/// not take a class.
///
/// A directed frame to a cold peer comes back as [`crate::transport::Delivered::Pending`]: the
/// dial runs on a task, and the caller awaits the handle off its event loop.
///
/// # Errors
/// Refuses a body too large for one frame, propagates a serialize/deliver
/// failure, and errors if the unmeshed buffer is full. A directed frame names its recipient by
/// author key, so two live peers that use one nickname are two addressees, and neither send is
/// refused. A caller that holds only a nickname asks `EventLoopState::key_of` first. A directed
/// frame does not wait for the gossip overlay: an unmeshed node sends it too. A node refuses a
/// frame to a peer whose probe proved a relay-only path, on a mesh where the relay is lookup only
/// ([`crate::transport::SendError::Held`]). A peer with no proven path yet is dialed, and the send
/// waits for a direct path on a task of its own, within the path-select budget. The caller retries
/// a refused frame, and nothing is buffered.
///
/// # Examples
///
/// It sends an application frame to its addressee or to the gossip flood, and it reports how the send went. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::{EventLoopState, HandlerCtx};
/// use habilis_network::embed::AppClass;
/// use habilis_network::ops::send_app;
/// use habilis_network::protocol::Verified;
///
/// # async fn demo(state: &mut EventLoopState, context: &HandlerCtx<'_>, frame: Verified) {
/// let _ = send_app(state, context, frame).await;
/// # }
/// ```
pub async fn send_app(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    frame: Verified,
) -> Result<transport::Delivered, transport::SendError> {
    if frame.wire_len() > MAX_MESSAGE_SIZE {
        return Err(transport::SendError::Oversize(format!(
            "app frame too large: {} bytes exceeds the {MAX_MESSAGE_SIZE}-byte single-frame limit",
            frame.wire_len()
        )));
    }
    // A key that nobody holds can never be delivered to, so the caller hears that now, meshed or
    // not: the later "no known endpoint" cause would tell it to wait for a `PeerInfo`.
    if let Some(key) = sole_addressee(&frame.kind)
        && !state.knows_key(key)
    {
        return Err(transport::SendError::Undeliverable(format!(
            "directed message to {key} undeliverable: no roster, quiet set or known address holds this key"
        )));
    }
    let bytes = frame
        .serialize()
        .map_err(|error| transport::SendError::Internal(error.into()))?;
    messages::log_out(&frame);
    // A directed frame rides the unicast connection, never the gossip overlay, so it needs no
    // link to a real peer: the pool dials the addressee, and the live path of the connection
    // decides whether the payload may go out (`payload_allowed_on`). Only a broadcast waits for
    // the overlay.
    let directed = sole_addressee(&frame.kind).is_some();
    if directed || state.standing.contains(&Standing::Meshed) {
        // Directed vs. broadcast is decided inside `deliver` from the frame's
        // `to` — the same routing the application's send path rides. A directed
        // frame with no path comes back as an error for the caller to act on.
        if let Some(peer) = probe::prove_addressee(state, &frame) {
            probe::open_lane_after_proof(state, context, peer);
        } else if transport::note_unproven(state, &frame) {
            offer_for_held(state, context, &frame);
        }
        let outcome = transport::deliver(&frame, bytes, state, context.sender).await;
        if let Err(error @ transport::SendError::Held { .. }) = &outcome {
            // The caller retries; the lane session is asked now, so the retry can find it.
            transport::note_held(state, error);
            offer_for_held(state, context, &frame);
        }
        return outcome;
    }
    // An unmeshed node buffers a broadcast frame for the meshed edge.
    if state.pending_outbound.push((frame.clone(), bytes)) {
        // Buffered until the meshed edge flushes it through the same send
        // decision (see `gossip::recv::flush_pending`). A buffered broadcast is still ours.
        Ok(transport::Delivered::Done)
    } else {
        Err(transport::SendError::internal(anyhow::anyhow!(
            "pending outbound buffer full; app frame dropped"
        )))
    }
}

/// Build, seal and sign the frame that [`send_app`] sends. A plain function, so that a caller can
/// hold no reference to the app across the `await` of [`send_app`]: the app is not `Sync`, and a
/// future that holds it is not `Send`.
///
/// The seal is inside the signature, so it is made here, before the frame is signed:
/// - A directed body of a tag that seals (`NodeApp::seals`, the rule that the receiver reads too)
///   is sealed to the seal key of the addressee (`EventLoopState::seal_key_of`). If no `PeerInfo`
///   named that key yet, the call returns [`AppFrameError::NoSealKey`], and a later call can
///   succeed.
/// - A broadcast body on a passworded mesh is sealed with the mesh key, whatever the tag: the
///   receivers drop any other body.
/// - Any other body goes as it is. That includes a directed body of a tag that does not seal, also
///   on a passworded mesh: the password covers the broadcast bodies, the state and the meta slices,
///   and a relay can read a directed body that no tag seals.
///
/// This builds one frame. A body that is cut into shards is sealed whole, then cut, because the
/// receiver joins the shards and opens the joined body once: a shard is a cut of one ciphertext, not
/// an envelope of its own. An app that shards seals the whole body with
/// [`seal_broadcast_body`], or with `protocol::seal_to_body` and `seal_key_of` for a directed body,
/// cuts the sealed text, and signs each shard. [`sealed_body_len_bound`] bounds the whole sealed
/// body. [`send_app`] checks the size of a frame after the seal.
///
/// # Errors
/// [`AppFrameError::NoSealKey`] for a sealing tag whose addressee has no known seal key, and
/// [`AppFrameError::Seal`] when the sealed body is not a valid message body.
///
/// # Examples
///
/// It builds a signed application frame from the state, the handler context and the app. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::{AppFrameError, EventLoopState, HandlerCtx, NodeApp};
/// use habilis_network::ops::app_frame;
/// use habilis_network::protocol::{AppFrameParams, Verified};
///
/// # fn demo<App: NodeApp>(state: &EventLoopState, context: &HandlerCtx<'_>, app: &App, params: AppFrameParams) -> Result<Verified, AppFrameError> {
/// app_frame(state, context, app, params)
/// # }
/// ```
pub fn app_frame<App: NodeApp + ?Sized>(
    state: &EventLoopState,
    context: &HandlerCtx<'_>,
    app: &App,
    mut params: AppFrameParams,
) -> Result<Verified, AppFrameError> {
    match params.to {
        Some(to) if app.seals(&params.tag) => {
            let seal = state
                .seal_key_of(&to)
                .ok_or(AppFrameError::NoSealKey { to })?;
            params.body = seal_error::seal_to_body(seal, params.body.as_str())
                .map_err(|error| AppFrameError::Seal(Box::new(error)))?;
        }
        None => params.body = seal_broadcast_body(state, &params.body)?,
        Some(_) => {}
    }
    Ok(Message::new_app(context.mesh, context.author, params).sign(context.identity))
}

/// Seal a whole broadcast body with the mesh key, as [`app_frame`] does for one frame. On a mesh
/// with no password the body comes back as it is. An app that cuts a broadcast body into shards
/// calls this on the whole body, then cuts the result: the receiver joins the shards and opens the
/// joined body once.
///
/// # Errors
/// [`AppFrameError::Seal`] when the sealed body is not a valid message body.
///
/// # Examples
///
/// It seals a whole broadcast body, and the body comes back as it is on a mesh with no password. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::{AppFrameError, EventLoopState};
/// use habilis_network::ops::seal_broadcast_body;
/// use habilis_network::protocol::MessageBody;
///
/// # fn demo(state: &EventLoopState, body: &MessageBody) -> Result<MessageBody, AppFrameError> {
/// seal_broadcast_body(state, body)
/// # }
/// ```
pub fn seal_broadcast_body(
    state: &EventLoopState,
    body: &MessageBody,
) -> Result<MessageBody, AppFrameError> {
    match state.broadcast_key() {
        Some(key) => {
            wire::encrypt_body(body, key).map_err(|error| AppFrameError::Seal(Box::new(error)))
        }
        None => Ok(body.clone()),
    }
}

/// The longest escaped length of a sealed body for a plain body of `plain_len` bytes, whether the
/// body is sealed to a peer or with the mesh key. It bounds a whole body: an app that cuts a sealed
/// body into shards seals the whole body first, so the bound applies to the whole body and not to a
/// shard, and each shard, with the rest of its frame, must fit [`MAX_MESSAGE_SIZE`].
///
/// # Examples
///
/// It gives the longest sealed length of a body. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::ops::sealed_body_len_bound;
///
/// # fn demo(plain_len: usize) -> usize {
/// sealed_body_len_bound(plain_len)
/// # }
/// ```
#[must_use]
pub fn sealed_body_len_bound(plain_len: usize) -> usize {
    seal_error::sealed_to_body_len_bound(plain_len).max(wire::sealed_body_len_bound(plain_len))
}

/// Fire-and-forget gossip broadcast. Serialize errors are swallowed:
/// this helper is for presence / `PeerInfo` announcements where a
/// failed serialize must not block the daemon. A failed *broadcast* is
/// logged — it means the gossip actor refused the send (the wedge the
/// roster-collapse soak hit silently), not a routine empty gossip.
///
/// # Examples
///
/// It broadcasts a signed message on the gossip, and a failure to send is only logged. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::ops::{MeshSender, broadcast_msg};
/// use habilis_network::protocol::Verified;
///
/// # async fn demo(sender: &MeshSender, message: &Verified) {
/// broadcast_msg(sender, message).await;
/// # }
/// ```
pub async fn broadcast_msg(sender: &MeshSender, message: &Verified) {
    messages::log_out(message);
    if let Ok(bytes) = message.serialize()
        && let Err(error) = sender.broadcast(bytes).await
    {
        tracing::warn!(
            target: "habilis_network::gossip",
            %error,
            "presence/plumbing broadcast failed"
        );
    }
}

/// Start an RTT round: arm it and broadcast the first probe. The event loop sends the second probe
/// at the middle of the window (`send_second_probe`); the round ends at its deadline and reports
/// the first pong of each peer. This is the one place that starts a round.
///
/// # Examples
///
/// It starts a round of pings to the peers, and an optional channel gets the round trip times. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::{EventLoopState, HandlerCtx};
/// use habilis_network::ops::start_ping_round;
///
/// # async fn demo(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
/// start_ping_round(state, context, None).await;
/// # }
/// ```
pub async fn start_ping_round(
    state: &mut EventLoopState,
    context: &HandlerCtx<'_>,
    response: Option<oneshot::Sender<Vec<(Nickname, u64)>>>,
) {
    let now = n0future_Instant::now();
    let window = tuning::ping_window();
    let probe = Message::new_ping(context.mesh, context.author).sign(context.identity);
    state.arm_ping_round(PingRound::new(&probe, now, now + window, response));
    broadcast_msg(context.sender, &probe).await;
}

/// Send the second probe of the round in flight, a fresh ping: a repeat of the first one would be
/// dropped as a duplicate by gossip and by `ingest`, and would never reach a peer's `auto_pong`.
pub(crate) async fn send_second_probe(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    let Some(round) = state.ping_round.as_mut() else {
        return;
    };
    let probe = Message::new_ping(context.mesh, context.author).sign(context.identity);
    round
        .probes
        .insert(probe.id.clone(), n0future_Instant::now());
    broadcast_msg(context.sender, &probe).await;
}

/// The four refs that a state write needs from the loop: the mesh, the author, the sender of the
/// topic, and the sink that reports the write. A [`HandlerCtx`] holds all four.
///
/// # Examples
///
/// A merge context names the mesh and the author of a write. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::ops::MergeCtx;
///
/// # fn demo(ctx: MergeCtx<'_>) {
/// let _mesh = ctx.mesh;
/// let _author = ctx.author;
/// # }
/// ```
#[non_exhaustive]
#[derive(Clone)]
pub struct MergeCtx<'mesh> {
    /// The id of the mesh that the write belongs to.
    pub mesh: &'mesh MeshId,
    /// The author of the write.
    pub author: &'mesh Nickname,
    /// The sender of the topic.
    pub sender: &'mesh MeshSender,
    /// The sink that reports the write.
    pub sink: &'mesh dyn NodeSink,
}

// Hand-written: `sink` is a `dyn NodeSink`, which has no `Debug` to print.
impl fmt::Debug for MergeCtx<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MergeCtx")
            .field("mesh", &self.mesh)
            .field("author", &self.author)
            .finish_non_exhaustive()
    }
}

impl<'mesh> MergeCtx<'mesh> {
    /// Gather the four parts of a write context. An app that holds the parts and no
    /// [`HandlerCtx`] builds the context with this.
    #[must_use]
    pub fn new<Sink: NodeSink>(
        mesh: &'mesh MeshId,
        author: &'mesh Nickname,
        sender: &'mesh MeshSender,
        sink: &'mesh Sink,
    ) -> Self {
        Self {
            mesh,
            author,
            sender,
            sink,
        }
    }
}

impl<'context> From<&HandlerCtx<'context>> for MergeCtx<'context> {
    fn from(context: &HandlerCtx<'context>) -> Self {
        Self {
            mesh: context.mesh,
            author: context.author,
            sender: context.sender,
            sink: context.sink,
        }
    }
}

/// Parameters for [`broadcast_state_merge`]. Agent-driven writes surface to the operator, so
/// `surface` is `true` unless [`StateMergeParams::surface`] says otherwise.
///
/// # Examples
///
/// The parameters of a state merge name the context of the write and its channel. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::ops::StateMergeParams;
///
/// # fn demo(params: StateMergeParams<'_>) {
/// let _channel = params.channel;
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StateMergeParams<'mesh> {
    /// The context of the write.
    pub context: MergeCtx<'mesh>,
    /// The channel of the write.
    pub channel: Channel,
    /// The RFC 7386 merge to apply.
    pub merge: serde_json::Value,
    /// Whether the write is reported to the operator as a `state` or `meta` event. Default `true`.
    pub surface: bool,
    /// Whether the merged frame also goes to each peer over the unicast plane. Default
    /// [`Farewell::GossipOnly`].
    pub farewell: Farewell,
}

impl<'mesh> StateMergeParams<'mesh> {
    /// A write on `channel` that surfaces to the operator.
    #[must_use]
    pub fn new(context: MergeCtx<'mesh>, channel: Channel, merge: serde_json::Value) -> Self {
        Self {
            context,
            channel,
            merge,
            surface: true,
            farewell: Farewell::GossipOnly,
        }
    }

    /// Whether the write is reported to the operator as a `state` or `meta` event.
    #[must_use]
    pub fn surface(
        self,
        // true reports the write to the operator as a state or meta event
        surface: bool,
    ) -> Self {
        Self { surface, ..self }
    }

    /// Whether the merged frame also goes to each peer over the unicast plane.
    #[must_use]
    pub fn farewell(
        self,
        // the frame is also sent to each peer by unicast, so it survives a linkless overlay
        farewell: Farewell,
    ) -> Self {
        Self { farewell, ..self }
    }
}

/// Whether a merged frame also goes to each peer over the unicast plane.
///
/// A frame that announces a departure must not die with the leaver. Gossip alone can lose it in
/// a silently linkless overlay, and no repair can heal a frame that no live replica holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Farewell {
    /// The frame goes over gossip only.
    #[default]
    GossipOnly,
    /// The frame also goes by unicast to each live peer whose key made its dial hint with a
    /// `PeerInfo`. A peer known only by a card has no such hint and gets the frame by gossip only.
    UnicastMirror,
}

/// The single shared-state write helper, shared by the IPC `state_merge` command
/// and the in-process `StateMerge` request. Applies the RFC 7386 merge to this
/// member's own slice, gossips the slice inside a signed frame, and keeps it locally
/// so the backfill can serve it (gossip never echoes to self).
///
/// The slice is size-gated **before** it touches the live store, so an oversize
/// merge never lands in a store it could not be gossiped from.
///
/// `surface` controls whether the local write is reported to the operator/agent
/// as a `state`/`meta` event (`you changed …`). Agent-driven merges pass
/// `true`; the daemon's own automatic card publish passes `false` — that write is
/// internal plumbing, not something the agent did, so it must not appear as a
/// "you changed shared state" event (nor race into a `fetch_messages` long-poll).
///
/// # Errors
/// Unrepresentable merge, a slice too large for one frame, a write past the rate
/// limit, or a broadcast refusal.
///
/// # Examples
///
/// It applies a state merge and broadcasts it to the mesh. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::EventLoopState;
/// use habilis_network::ops::{StateMergeParams, broadcast_state_merge};
///
/// # async fn demo(state: &mut EventLoopState, params: StateMergeParams<'_>) {
/// let _ = broadcast_state_merge(state, params).await;
/// # }
/// ```
pub async fn broadcast_state_merge(
    state: &mut EventLoopState,
    params: StateMergeParams<'_>,
) -> Result<(), transport::SendError> {
    let StateMergeParams {
        context,
        channel,
        merge,
        surface,
        farewell,
    } = params;

    // 1. The own slice with the merge patch applied (RFC 7386). A merge that changes nothing is a
    //    silent success.
    let now = clock::Instant::now();
    let Some(next) = merged_own_value(state, channel, &merge)? else {
        return Ok(());
    };

    // 2. The draft of the next version, the signed frame of its body, and the commit of the frame.
    //    The engine refuses a write past the rate limit; the caller gets the typed error.
    let draft = draft_own_write(state, channel, next, now).await?;
    commit_and_send(state, &context, channel, draft, farewell, surface).await
}

/// The own value of `channel` with the merge patch `merge` applied (RFC 7386), as a whole value. The cap
/// applies to this whole value, not to the patch. `None` when the merge changes nothing.
pub(crate) fn merged_own_value(
    state: &EventLoopState,
    channel: Channel,
    merge: &serde_json::Value,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, transport::SendError> {
    let own = state.identity.author_key();
    let held = state.docs.own_value(channel, &own);
    let mut value = serde_json::Value::Object(held.clone());
    json_merge_patch(&mut value, merge);
    let serde_json::Value::Object(next) = value else {
        return Err(transport::SendError::internal(anyhow::anyhow!(
            "the merge must be a JSON object"
        )));
    };
    Ok((next != held).then_some(next))
}

/// The draft of the next version of the own slice with `next` as its whole value. A value that fits one frame is
/// the value of the slice. A value that does not is cut into chunks, and the slice holds a pointer to them. A
/// value past the value cap is refused before any chunk is made.
pub(crate) async fn draft_own_write(
    state: &mut EventLoopState,
    channel: Channel,
    next: serde_json::Map<String, serde_json::Value>,
    now: clock::Instant,
) -> Result<habilis_network_doc::LocalDraft, transport::SendError> {
    let own = state.identity.author_key();
    match state.docs.prepare_local(channel, &own, next.clone(), now) {
        Err(SliceError::TooLarge { .. }) => {}
        other => return other.map_err(transport::SendError::State),
    }
    let bytes =
        serde_json::to_vec(&next).map_err(|error| transport::SendError::internal(error.into()))?;
    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let root = state
        .chunks
        .put_value(&bytes)
        .await
        .map_err(|error| transport::SendError::internal(error.into()))?;
    drop(bytes);
    let draft = state
        .docs
        .prepare_pointer(channel, &own, ChunkPointer::new(root, size), next, now);
    if draft.is_err() {
        keep_own_chunks(state).await;
    }
    draft.map_err(transport::SendError::State)
}

/// Drops the chunks that no own slice names. Called when the own slices change, so the chunks of an old version
/// do not stay.
async fn keep_own_chunks(state: &EventLoopState) {
    let own = state.identity.author_key();
    if let Err(error) = state.chunks.keep_only(state.docs.chunk_roots(&own)).await {
        tracing::warn!(target: "habilis_network::gossip", %error, "the chunks of an old version were not dropped");
    }
}

/// Signs the body of `draft`, and commits the frame as the own slice. Returns the frame and its wire form.
pub(crate) async fn sign_and_commit(
    state: &mut EventLoopState,
    (mesh, author): (&MeshId, &Nickname),
    channel: Channel,
    draft: habilis_network_doc::LocalDraft,
) -> Result<(Verified, WireFrame), transport::SendError> {
    let now = clock::Instant::now();
    let signed = Message::new_channel_event(mesh, author, draft.body().clone(), channel)
        .sign(&state.identity);
    // The token that prepare_local spent is not refunded if this serialize fails. The frame_overhead probe keeps
    // a draft at the cap within one frame, so the failure cannot happen for a draft the store took.
    let bytes = signed
        .serialize()
        .map_err(|error| transport::SendError::Internal(error.into()))?;
    messages::log_out(&signed);
    state
        .docs
        .commit_local(channel, draft, &signed, now)
        .map_err(transport::SendError::State)?;
    keep_own_chunks(state).await;
    Ok((signed, bytes))
}

/// Commits a local draft, then sends its signed frame. A frame that announces a departure also goes to each live
/// peer by unicast before gossip takes it. With no gossip path yet, the frame waits in the outbound buffer.
pub(crate) async fn commit_and_send(
    state: &mut EventLoopState,
    context: &MergeCtx<'_>,
    channel: Channel,
    draft: habilis_network_doc::LocalDraft,
    farewell: Farewell,
    surface: bool,
) -> Result<(), transport::SendError> {
    let (signed, bytes) =
        sign_and_commit(state, (context.mesh, context.author), channel, draft).await?;

    // A departure is mirrored before gossip takes the frame: once gossip has it, the frame is
    // no longer ours to copy, and a leaver can exit before the overlay carries it.
    if farewell == Farewell::UnicastMirror {
        unicast_farewell(state, &bytes);
    }

    // Surface our own change, and gossip it (or buffer while no gossip path exists — the change is kept in the
    // local slice, and its frame is sent once a path exists).
    if surface {
        // Surface our own change from a plaintext-bodied view so the `m` delta
        // renders even when the wire body we signed is sealed.
        let own = state.identity.author_key();
        let plain_body = state.docs.plain_body(channel, &own).ok_or_else(|| {
            transport::SendError::internal(anyhow::anyhow!("the own slice is not in the store"))
        })?;
        context.sink.emit(NodeEvent::StateChanged {
            channel,
            event: Box::new(signed.copy_with_body(plain_body)),
            document: state.docs.to_json(channel),
            is_self: true,
        });
    }
    if state.overlay_reachable() {
        context
            .sender
            .broadcast(bytes)
            .await
            .map_err(|error| transport::SendError::internal(anyhow::anyhow!("{error}")))?;
    } else {
        // No gossip path yet: buffer until we mesh. The frame is also the slice of this node, so a
        // newcomer that meets us gets it from the backfill.
        state.pending_outbound.push((signed, bytes));
    }
    Ok(())
}

/// Sends the tombstone of this node on each channel, the farewell of a leaving member. Each one goes by unicast to
/// each live peer and by gossip, so a peer that misses the `Left` still drops this node's slice. The order of the
/// sends is for time, not correctness: a receiver ends in the same state in either order.
pub(crate) async fn send_tombstones(state: &mut EventLoopState, context: &MergeCtx<'_>) {
    let own = state.identity.author_key();
    for channel in [Channel::State, Channel::Meta] {
        let draft = match state
            .docs
            .prepare_leave(channel, &own, clock::Instant::now())
        {
            Ok(draft) => draft,
            Err(error) => {
                tracing::debug!(target: "habilis_network::gossip", "a tombstone draft was refused: {error:?}");
                continue;
            }
        };
        if let Err(error) = commit_and_send(
            state,
            context,
            channel,
            draft,
            Farewell::UnicastMirror,
            false,
        )
        .await
        {
            tracing::debug!(target: "habilis_network::gossip", "a tombstone was not sent: {error}");
        }
    }
}

/// Mirror a farewell frame over the unicast plane to every live peer whose key made its dial hint
/// with a `PeerInfo` — fire-and-forget dials racing the shutdown propagation sleep. A hint from a
/// card has no verified key, and dialing it would open dials to addresses that no admitted key
/// owns, so a peer known only by its card is left to gossip. The same holds for a second key under a
/// nickname whose hint another key owns. The gossip
/// overlay can be silently linkless (a post-join flap heals in seconds, but a
/// leaver exits first), and a farewell that dies with the leaver can never be
/// repaired by no mechanism until the loss repair lands — no live replica holds it. Receiver-side dedup
/// makes the double delivery a no-op; the unicast acceptor feeds the same
/// `ingest` path as gossip. Spawned dials that outlive the shutdown window
/// die with the endpoint — still best-effort, just no longer single-path.
///
/// For channel-event farewells (the meta retraction) ONLY — never presence:
/// a mirrored `Left` from a beacon host can land while a survivor's gossip
/// still holds the dying beacon's link, and the presence-driven fast-reclaim
/// then re-stands the beacon into a stale connection and stalls
/// (iroh-gossip#10).
///
/// # Examples
///
/// It sends a farewell frame to each live peer that owns a dial hint. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::EventLoopState;
/// use habilis_network::ops::unicast_farewell;
/// use habilis_network::protocol::messages::WireFrame;
///
/// # fn demo(state: &EventLoopState, bytes: &WireFrame) {
/// unicast_farewell(state, bytes);
/// # }
/// ```
pub fn unicast_farewell(state: &EventLoopState, bytes: &WireFrame) {
    for endpoint_id in farewell_targets(state) {
        let pool = state.unicast_pool.clone();
        let bytes = bytes.clone();
        task::spawn(async move {
            if let Err(error) = pool.dial_and_send(endpoint_id, bytes.into_bytes()).await {
                tracing::debug!(target: "habilis_network::gossip", %error, "unicast farewell mirror failed");
            }
        });
    }
}

/// The endpoints that [`unicast_farewell`] dials: the dial address of each live peer, once for each
/// endpoint, whatever the keys that use it. The rendezvous pseudo-node is never a directed target,
/// and a quiet or ghost peer's stale address isn't worth a dial at shutdown.
fn farewell_targets(state: &EventLoopState) -> Vec<iroh::EndpointId> {
    let mut targets: Vec<iroh::EndpointId> = Vec::new();
    for key in &state.peers {
        let Some(address) = state.address_of(key) else {
            continue;
        };
        let new_target = !targets.contains(&address.id);
        if state.rendezvous_id != Some(address.id) && new_target {
            targets.push(address.id);
        }
    }
    targets
}

/// The body of our `PeerInfo`: our address, the proof that we own it, the x25519 key that a peer
/// seals a directed body to (`seal`, Base58), and, while we hold the rendezvous, a flag that lets
/// another holder in the same overlay order itself against us. The `seal` is required: a receiver
/// refuses a body that has none.
pub(crate) fn peer_info_json(
    address: &iroh::EndpointAddr,
    proof: String,
    holds_beacon: bool,
    seal: &x25519_dalek::PublicKey,
) -> serde_json::Value {
    let mut json = peer_addr_error::endpoint_addr_to_json(address);
    json["proof"] = serde_json::Value::String(proof);
    json["seal"] = serde_json::Value::String(bs58::encode(seal.as_bytes()).into_string());
    if holds_beacon {
        json["beacon"] = serde_json::Value::Bool(true);
    }
    json
}

/// The seal key that a `PeerInfo` body names, or `None` when the body names none or the text is
/// not the Base58 of 32 bytes.
pub(crate) fn peer_info_seal_key(json: &serde_json::Value) -> Option<x25519_dalek::PublicKey> {
    let text = json["seal"].as_str()?;
    let decoded = bs58::decode(text).into_vec().ok()?;
    let bytes: [u8; 32] = decoded.try_into().ok()?;
    Some(x25519_dalek::PublicKey::from(bytes))
}

/// Broadcast a `PeerInfo` carrying our endpoint address so peers can
/// dial us directly. Unlike `joined`, `PeerInfo` is never
/// surfaced to the app, so re-sending it is invisible to `poll`/`fetch_messages` consumers —
/// safe to repeat on every new neighbor. Stamps `peerinfo_flood`, the
/// window the `joined` re-flood gate and the periodic refresh read, and draws the spread of the
/// next refresh period.
pub(crate) async fn broadcast_peer_info(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    state.peerinfo_flood = Some(PeerInfoFlood::at(clock::Instant::now()));
    state.latches.remove(&Latch::PeerInfoDeferred);
    let our_addr = context.endpoint.addr();
    state.last_flooded_addr = Some(our_addr.clone());
    let our_ips: Vec<_> = our_addr.ip_addrs().collect();
    let local = context.endpoint.id().fmt_short();
    let relay = our_addr.relay_urls().next();
    tracing::debug!(
        target: "habilis_network::gossip",
        local = %local,
        relay = ?relay,
        addrs = our_ips.len(),
        ip_addrs = ?our_ips,
        "peerinfo flooded"
    );
    let proof = state
        .peer_info_proof
        .get_or_insert_with(|| {
            let author_key = state.identity.author_key();
            proven_endpoints::sign(context.endpoint.secret_key(), context.mesh, &author_key)
        })
        .clone();
    let seal = state.identity.seal_public();
    let addr_json = peer_info_json(
        &our_addr,
        proof,
        state
            .rendezvous_flags
            .contains(&RendezvousFlag::HostsRendezvous),
        &seal,
    );
    let addr_data = serde_json::to_string(&addr_json)
        .expect("endpoint_addr_to_json produces a Value that always serializes");
    let addr_body =
        MessageBody::try_new(&addr_data).expect("endpoint address JSON has no control characters");
    broadcast_msg(
        context.sender,
        &Message::new_peer_info(context.mesh, context.author, addr_body).sign(context.identity),
    )
    .await;
}

/// Announce our arrival: `joined` presence followed by `PeerInfo`.
/// Called once at the top of the event loop; the caller bumps
/// `last_sent_at` afterwards.
///
pub(super) async fn announce_arrival(state: &mut EventLoopState, context: &HandlerCtx<'_>) {
    let joined = state.own_joined(context.mesh, context.author);
    broadcast_msg(context.sender, &joined).await;
    broadcast_peer_info(state, context).await;
}

/// Offer the session of the peer now, if a held frame asked for it. Without this the offer waits
/// for the next tick of the retry pass, up to 30 s, and a user waits with it. The peer is a lane peer,
/// or a pair with an IP path that reads as the relay (`note_held` marks both).
fn offer_for_held(state: &mut EventLoopState, context: &HandlerCtx<'_>, frame: &Verified) {
    let Some(key) = sole_addressee(&frame.kind) else {
        return;
    };
    let Some(address) = state.address_of(key) else {
        return;
    };
    if state.lane_session_wanted(address.id, clock::Instant::now()) {
        webrtc::negotiate_session::negotiate_session(state, context, address.id, address);
    }
}

/// Applies the RFC 7386 JSON merge patch `patch` to `target`, in place.
fn json_merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    let serde_json::Value::Object(patch_map) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = serde_json::Value::Object(serde_json::Map::new());
    }
    let serde_json::Value::Object(target_map) = target else {
        return;
    };
    for (name, value) in patch_map {
        if value.is_null() {
            target_map.remove(name);
        } else {
            let entry = target_map
                .entry(name.clone())
                .or_insert(serde_json::Value::Null);
            json_merge_patch(entry, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{farewell_targets, peer_info_json, wire};
    use crate::daemon::state::EventLoopState;
    use crate::protocol::identity::Identity;
    use crate::protocol::{
        Channel, MeshId, Message, MessageBody, Nickname, SymmetricKey, seal_to_body,
    };
    use crate::testing::{endpoint_id, fresh_state, longest_mesh_id, nick, test_key};
    use crate::transport::SendError;
    use crate::util::consts::MAX_MESSAGE_SIZE;
    use habilis_network_doc::SliceError;
    use std::time::Duration;

    use crate::protocol::peer_addr_error;
    #[cfg(feature = "host")]
    use crate::testing;
    #[cfg(feature = "host")]
    use crate::util::clock;
    /// The mirror dials the hint of a live peer whose key made it. It skips a hint from a card (no
    /// verified key, even when a key is admitted under the nickname later), a hint of a quiet key,
    /// and the rendezvous.
    #[test]
    fn the_farewell_mirror_dials_only_the_hints_that_a_live_key_made() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let (owned, card, quiet, rendezvous) = (
            endpoint_id(1),
            endpoint_id(2),
            endpoint_id(3),
            endpoint_id(9),
        );
        state.rendezvous_id = Some(rendezvous);
        // A live key made its hint with a PeerInfo.
        state.peer_for_test("owned");
        state.names.insert(test_key("owned"), nick("owned"));
        state.bind_peer_endpoint(
            test_key("owned"),
            nick("owned"),
            iroh::EndpointAddr::new(owned),
        );
        // A card names a nickname that no key uses yet; a key is admitted under it afterwards.
        state.note_peer_endpoint(nick("card"), iroh::EndpointAddr::new(card));
        state.peer_for_test("card");
        // The key that made a hint went quiet.
        state.quiet_for_test("quiet");
        state.names.insert(test_key("quiet"), nick("quiet"));
        state.bind_peer_endpoint(
            test_key("quiet"),
            nick("quiet"),
            iroh::EndpointAddr::new(quiet),
        );
        // A live key advertised the rendezvous.
        state.peer_for_test("beacon");
        state.names.insert(test_key("beacon"), nick("beacon"));
        state.bind_peer_endpoint(
            test_key("beacon"),
            nick("beacon"),
            iroh::EndpointAddr::new(rendezvous),
        );

        assert_eq!(
            farewell_targets(&state),
            vec![owned],
            "the mirror dialed a hint that no live key made, or the rendezvous"
        );
    }

    /// Two nicknames can bind one endpoint (a node that restarted under a new name, both keys
    /// live). The mirror dials the endpoint once, not once per nickname.
    #[test]
    fn the_farewell_mirror_dials_an_endpoint_once_whatever_the_nicknames_that_bind_it() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut state = fresh_state();
        let shared = endpoint_id(1);
        for name in ["swift-cedar", "lost-heron"] {
            state.peer_for_test(name);
            state.names.insert(test_key(name), nick(name));
            state.bind_peer_endpoint(test_key(name), nick(name), iroh::EndpointAddr::new(shared));
        }

        assert_eq!(
            farewell_targets(&state),
            vec![shared],
            "the mirror dialed the same endpoint once for each nickname that binds it"
        );
    }

    /// A leaving member's tombstone reaches each peer by unicast, once per channel, with the null value. The overlay
    /// is not meshed, so only the unicast mirror can deliver it. The mesh is plain, with no password: a passworded
    /// mesh seals the same tombstone, and the loopback test of a sealed meta write covers that. The State channel has
    /// an earlier local write, so its tombstone is version 2; Meta has none, so its tombstone is version 1.
    #[test]
    fn a_tombstone_reaches_each_peer_by_unicast_on_each_channel() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use std::time::Duration;

                use iroh::endpoint::presets;
                use iroh::protocol::Router;
                use iroh_gossip::{net, proto};
                use tokio::sync::mpsc;
                use tokio::time;

                use crate::gossip::event::SilentSink;
                use crate::gossip::{MergeCtx, StateMergeParams, broadcast_state_merge};
                use crate::lookup;
                use crate::protocol::{Channel, Message, MessageKind};
                use crate::transport::{
                    MeshSender, PayloadPath, UNICAST_ALPN, UnicastAcceptor, UnicastPool,
                };

                let (tx, mut frames) = mpsc::channel(8);
                let server = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                let router = Router::builder(server.clone())
                    .accept(
                        UNICAST_ALPN,
                        UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
                    )
                    .spawn();

                let node = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                let gossip = net::Gossip::builder().spawn(node.clone());
                let topic = gossip
                    .subscribe(proto::TopicId::from_bytes([9u8; 32]), vec![])
                    .await
                    .expect("subscribe to a peerless topic");
                let (gossip_sender, _receiver) = topic.split();
                let sender = MeshSender::new(gossip_sender);

                let mut state = fresh_state();
                state.unicast_pool = UnicastPool::new(node.clone(), false);
                lookup::add_peer_addr(&lookup::address_book(&node), server.addr());
                state.names.insert(test_key("bob"), nick("bob"));
                state.bind_peer_endpoint(test_key("bob"), nick("bob"), server.addr());
                state.peer_for_test("bob");

                let mesh = MeshId::from("test");
                let author = nick("alice");
                let context = MergeCtx {
                    mesh: &mesh,
                    author: &author,
                    sender: &sender,
                    sink: &SilentSink,
                };
                let earlier_write = StateMergeParams::new(
                    MergeCtx {
                        mesh: &mesh,
                        author: &author,
                        sender: &sender,
                        sink: &SilentSink,
                    },
                    Channel::State,
                    serde_json::json!({"a": 1}),
                )
                .surface(false);
                broadcast_state_merge(&mut state, earlier_write)
                    .await
                    .expect("an earlier local write");
                super::send_tombstones(&mut state, &context).await;

                let own_key = state.identity.author_key();
                let mut states = 0;
                let mut metas = 0;
                for _ in 0..2 {
                    let delivered = time::timeout(Duration::from_secs(5), frames.recv()).await;
                    let Ok(Some(frame)) = delivered else {
                        panic!("a tombstone frame arrives within 5 s");
                    };
                    let message = Message::parse(&frame.bytes).expect("a tombstone frame parses");
                    let verified = message
                        .verify()
                        .expect("the signature of a tombstone verifies");
                    assert_eq!(
                        verified.key(),
                        own_key,
                        "the tombstone is signed by the leaver"
                    );
                    let body: serde_json::Value =
                        serde_json::from_str(verified.body.as_str()).expect("a slice body is JSON");
                    let expected = if matches!(verified.kind, MessageKind::State) {
                        2
                    } else {
                        1
                    };
                    assert_eq!(
                        body["version"], expected,
                        "the tombstone is the version after the last one of its channel"
                    );
                    assert!(
                        body["value"].is_null(),
                        "the tombstone carries the null value"
                    );
                    if matches!(verified.kind, MessageKind::State) {
                        states += 1;
                    } else if matches!(verified.kind, MessageKind::Meta) {
                        metas += 1;
                    }
                }
                assert_eq!((states, metas), (1, 1), "one tombstone for each channel");
                let extra = time::timeout(Duration::from_millis(500), frames.recv()).await;
                assert!(extra.is_err(), "no third tombstone frame follows");
                router.shutdown().await.expect("shutdown");
                node.close().await;
                server.close().await;
            },
        );
    }

    /// A departure written with a farewell reaches each peer by unicast at once. The overlay is
    /// not meshed, so gossip carries nothing: only the unicast mirror can deliver the frame, and
    /// no backfill round is needed.
    #[test]
    fn a_farewell_merge_reaches_each_peer_by_unicast() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                use std::time::Duration;

                use iroh::endpoint::presets;
                use iroh::protocol::Router;
                use iroh_gossip::{net, proto};
                use tokio::sync::mpsc;
                use tokio::time;

                use crate::gossip::event::SilentSink;
                use crate::gossip::{Farewell, MergeCtx, StateMergeParams, broadcast_state_merge};
                use crate::lookup;
                use crate::protocol::Channel;
                use crate::transport::{
                    MeshSender, PayloadPath, UNICAST_ALPN, UnicastAcceptor, UnicastPool,
                };

                let (tx, mut frames) = mpsc::channel(8);
                let server = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                let router = Router::builder(server.clone())
                    .accept(
                        UNICAST_ALPN,
                        UnicastAcceptor::new(tx, PayloadPath::RelayAllowed),
                    )
                    .spawn();

                let node = iroh::Endpoint::builder(presets::Minimal)
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind()
                    .await
                    .expect("bind a loopback endpoint");
                let gossip = net::Gossip::builder().spawn(node.clone());
                let topic = gossip
                    .subscribe(proto::TopicId::from_bytes([7u8; 32]), vec![])
                    .await
                    .expect("subscribe to a peerless topic");
                let (gossip_sender, _receiver) = topic.split();
                let sender = MeshSender::new(gossip_sender);

                let mut state = fresh_state();
                state.unicast_pool = UnicastPool::new(node.clone(), false);
                lookup::add_peer_addr(&lookup::address_book(&node), server.addr());
                state.names.insert(test_key("bob"), nick("bob"));
                state.bind_peer_endpoint(test_key("bob"), nick("bob"), server.addr());
                state.peer_for_test("bob");

                let mesh = MeshId::from("test");
                let author = nick("alice");
                let context = MergeCtx {
                    mesh: &mesh,
                    author: &author,
                    sender: &sender,
                    sink: &SilentSink,
                };
                let params = StateMergeParams::new(
                    context,
                    Channel::Meta,
                    serde_json::json!({"peers": {"alice": null}}),
                )
                .surface(false)
                .farewell(Farewell::UnicastMirror);
                broadcast_state_merge(&mut state, params)
                    .await
                    .expect("the farewell is accepted");

                let delivered = time::timeout(Duration::from_secs(5), frames.recv()).await;
                assert!(
                    matches!(delivered, Ok(Some(ref frame)) if !frame.bytes.is_empty()),
                    "a farewell reaches the peer by unicast, without waiting for a backfill"
                );
                router.shutdown().await.expect("shutdown");
                node.close().await;
            },
        );
    }

    #[test]
    fn our_peer_info_says_so_while_we_hold_the_rendezvous() {
        let _guard = ::habilis_network_test_tracing::init();
        let address = iroh::EndpointAddr::new(iroh::SecretKey::generate().public());

        let seal = x25519_dalek::PublicKey::from([7u8; 32]);
        let holding = peer_info_json(&address, "proof".to_owned(), true, &seal);
        let idle = peer_info_json(&address, "proof".to_owned(), false, &seal);

        assert_eq!(
            holding["beacon"],
            serde_json::Value::Bool(true),
            "our peer info says the beacon is held while we hold the rendezvous"
        );
        assert_eq!(
            holding["proof"], "proof",
            "our peer info carries the proof while we hold the rendezvous"
        );
        assert!(
            idle.get("beacon").is_none(),
            "no key while we do not hold it"
        );
    }

    /// **Wire pin of the seal key of a `PeerInfo`.** The body names the x25519 key as Base58 under
    /// `seal`, and the key is required: a body with no `seal` names no key, and a receiver refuses
    /// it (`a_peer_info_with_no_seal_key_binds_nothing`).
    #[test]
    fn a_peer_info_body_pins_the_seal_text_and_a_body_with_no_seal_names_no_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = iroh::SecretKey::generate().public();
        let address = iroh::EndpointAddr::new(id);
        let seal = x25519_dalek::PublicKey::from([7u8; 32]);

        let json = peer_info_json(&address, "proof".to_owned(), false, &seal);

        assert_eq!(
            json["seal"], "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx",
            "the golden text of the seal key moved: this is a wire change"
        );
        assert_eq!(
            super::peer_info_seal_key(&json),
            Some(seal),
            "the key reads back from the body"
        );

        let mut without = json;
        without
            .as_object_mut()
            .expect("the body is an object")
            .remove("seal");
        assert_eq!(
            super::peer_info_seal_key(&without),
            None,
            "a body with no seal names no key"
        );
    }

    /// **A `PeerInfo` frame fits the frame limit at every longest field.** The longest real mesh id
    /// (about 511 bytes), a nickname of 32 characters of 4 bytes, an address with 16 `IPv6` addresses
    /// and a relay `URL`, the proof, the beacon flag and the seal key go in one signed frame under
    /// `MAX_MESSAGE_SIZE`. The seal key adds 58 bytes, so the room that is left says how many
    /// addresses fit.
    #[test]
    fn a_peer_info_frame_with_every_longest_field_fits_the_frame_limit() {
        let _guard = ::habilis_network_test_tracing::init();
        let mesh = longest_mesh_id();
        assert!(
            mesh.as_str().len() >= 500,
            "the mesh id of {} bytes is not a longest real id",
            mesh.as_str().len()
        );
        let nickname = Nickname::from("\u{1F600}".repeat(32).as_str());
        let relay: iroh::RelayUrl = "https://relay.example.com./".parse().expect("a relay url");
        let id = iroh::SecretKey::generate().public();
        let mut address = iroh::EndpointAddr::new(id).with_relay_url(relay);
        for index in 0..16u16 {
            let ip = format!("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:{index:x}]:65535");
            address = address.with_ip_addr(ip.parse().expect("an IPv6 socket address"));
        }
        let proof = "1".repeat(100);
        let seal = x25519_dalek::PublicKey::from([255u8; 32]);
        let json = peer_info_json(&address, proof, true, &seal);
        let body = MessageBody::try_new(&json.to_string()).expect("a body");

        let frame = Message::new_peer_info(&mesh, &nickname, body).sign(&Identity::generate());
        let size = frame.wire_len();

        assert!(
            size <= MAX_MESSAGE_SIZE,
            "a PeerInfo frame of {size} bytes passes the {MAX_MESSAGE_SIZE}-byte limit"
        );
    }

    /// The sealed length bound covers a real sealed body, for a seal to a peer and for a seal with the
    /// mesh key, at every length that an app can cut a shard to.
    #[test]
    fn the_sealed_length_bound_covers_every_sealed_body() {
        let _guard = ::habilis_network_test_tracing::init();
        let recipient = Identity::generate();
        let key = SymmetricKey::from([3u8; 32]);
        for plain_len in [0usize, 1, 2, 31, 32, 33, 100, 500, 1000, 2000, 3000] {
            let text = "x".repeat(plain_len);
            let body = MessageBody::try_new(&text).expect("a body");
            let to_peer =
                seal_to_body(&recipient.seal_public(), &text).expect("a body sealed to a peer");
            let with_key = wire::encrypt_body(&body, &key).expect("a sealed body");
            let bound = super::sealed_body_len_bound(plain_len);
            for sealed in [&to_peer, &with_key] {
                let escaped = serde_json::to_string(sealed.as_str())
                    .expect("a string")
                    .len();
                assert!(
                    escaped <= bound,
                    "a sealed body of {escaped} bytes passes the bound {bound} for {plain_len} plain bytes"
                );
            }
        }
    }

    /// A `seal` that is not the Base58 of 32 bytes names no key: a wrong length, a character out of
    /// the alphabet, and a text that is not a string.
    #[test]
    fn a_seal_text_that_is_not_32_bytes_of_base58_names_no_key() {
        let _guard = ::habilis_network_test_tracing::init();
        let short = bs58::encode([7u8; 31]).into_string();
        let long = bs58::encode([7u8; 33]).into_string();
        for (bad, why) in [
            (serde_json::json!({ "seal": short }), "31 bytes"),
            (serde_json::json!({ "seal": long }), "33 bytes"),
            (
                serde_json::json!({ "seal": "0OIl" }),
                "characters out of the alphabet",
            ),
            (serde_json::json!({ "seal": 7 }), "a number"),
            (serde_json::json!({}), "no field"),
        ] {
            assert_eq!(
                super::peer_info_seal_key(&bad),
                None,
                "a seal of {why} named a key"
            );
        }
    }

    /// Members built before the flag read the body by key. The new key must not stop them from
    /// reading the address.
    #[test]
    fn a_reader_that_predates_the_flag_still_reads_the_address() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = iroh::SecretKey::generate().public();
        let seal = x25519_dalek::PublicKey::from([7u8; 32]);
        let json = peer_info_json(
            &iroh::EndpointAddr::new(id),
            "proof".to_owned(),
            true,
            &seal,
        );

        let (read, _) = peer_addr_error::endpoint_addr_from_json(&json).expect("the address reads");

        assert_eq!(
            read, id,
            "a reader that predates the flag still reads the address"
        );
    }

    /// The offer goes out at once for a peer that is wanted, and a second call does not start a
    /// second one: the admission table keeps one round per peer.
    #[cfg(feature = "host")]
    #[test]
    fn offering_for_a_parked_frame_starts_one_round_and_no_more() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let node = testing::LaneNode::start().await;
                let context = node.context();
                let mut state = node.state();
                let frame = node.frame_to_bob();
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    0,
                    "no admission slot is in flight after the offer for a parked frame"
                );

                state.want_lane_session(node.bob, clock::Instant::now());
                super::offer_for_held(&mut state, &context, &frame);
                assert_eq!(state.webrtc_admission.in_flight(), 1, "the offer is out");
                super::offer_for_held(&mut state, &context, &frame);
                assert_eq!(state.webrtc_admission.in_flight(), 1, "not a second round");

                state.webrtc_admission.close();
                node.endpoint.close().await;
            },
        );
    }

    /// A peer that nobody asked for is not offered a session.
    #[cfg(feature = "host")]
    #[test]
    fn nothing_is_offered_for_a_peer_that_is_not_wanted() {
        ::habilis_network_test_tracing::run_multi_thread(
            ::habilis_network_test_tracing::init(),
            2,
            async {
                let node = testing::LaneNode::start().await;
                let context = node.context();
                let mut state = node.state();
                super::offer_for_held(&mut state, &context, &node.frame_to_bob());
                assert_eq!(
                    state.webrtc_admission.in_flight(),
                    0,
                    "no admission slot is in flight when nothing is offered"
                );
                node.endpoint.close().await;
            },
        );
    }

    /// A value of one key, `len` characters long, so the encoded value has `len + 8` bytes. The text varies, so
    /// no two chunks of it are equal, and the store cannot keep fewer chunks than the value has.
    fn big_value(fill: char, len: usize) -> serde_json::Map<String, serde_json::Value> {
        let mut value = serde_json::Map::new();
        let letters = "abcdefghijklmnopqrstuvwxyz";
        let mut seed = u32::from(fill);
        let mut text = String::with_capacity(len);
        for _ in 0..len {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let index = usize::try_from(seed >> 16).expect("a small index") % letters.len();
            text.push_str(&letters[index..=index]);
        }
        value.insert("k".to_owned(), text.into());
        value
    }

    /// Drafts and commits an own write of `value` on `channel`, without a network.
    async fn write_own(
        state: &mut EventLoopState,
        channel: Channel,
        value: serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), SendError> {
        write_own_at(state, channel, value, clock::Instant::now()).await
    }

    /// The same as `write_own`, with the time of the write given, so a test can pass the rate limit.
    async fn write_own_at(
        state: &mut EventLoopState,
        channel: Channel,
        value: serde_json::Map<String, serde_json::Value>,
        now: clock::Instant,
    ) -> Result<(), SendError> {
        let draft = super::draft_own_write(state, channel, value, now).await?;
        let mesh = MeshId::from("test");
        let author = nick("test");
        super::sign_and_commit(state, (&mesh, &author), channel, draft).await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_value_too_large_for_one_frame_is_chunked_and_reads_whole() {
        let mut state = fresh_state();
        let value = big_value('x', 70_000);
        write_own(&mut state, Channel::State, value.clone())
            .await
            .expect("a chunked write");
        let own = state.identity.author_key();
        assert_eq!(
            state.docs.own_value(Channel::State, &own),
            value,
            "the own value of a chunked slice must be the whole value and not the pointer"
        );
        assert_eq!(
            state.chunks.stored_chunks(),
            2,
            "a value of 70000 bytes must be kept as 2 chunks of 64 KiB"
        );
        assert_eq!(
            state.docs.chunk_roots(&own).count(),
            1,
            "the slice must name one root"
        );
    }

    #[tokio::test]
    async fn a_value_past_the_cap_is_refused_before_a_chunk_is_made() {
        let mut state = fresh_state();
        let error = write_own(&mut state, Channel::State, big_value('x', 2 * 1024 * 1024))
            .await
            .expect_err("a value past the cap must be refused");
        assert!(
            matches!(
                error,
                SendError::State(SliceError::ValueTooLarge {
                    limit: 1_048_576,
                    ..
                })
            ),
            "the refusal must be the typed value cap error, not {error:?}"
        );
        assert_eq!(
            state.chunks.stored_chunks(),
            0,
            "a refused value must leave no chunk"
        );
    }

    #[tokio::test]
    async fn a_smaller_inline_version_drops_the_chunks_of_the_old_value() {
        let mut state = fresh_state();
        let channel = Channel::State;
        write_own(&mut state, channel, big_value('x', 70_000))
            .await
            .expect("a chunked write");
        write_own(&mut state, channel, big_value('y', 10))
            .await
            .expect("an inline write");
        let own = state.identity.author_key();
        assert_eq!(
            state.chunks.stored_chunks(),
            0,
            "an inline version must drop the chunks of the old value"
        );
        assert_eq!(
            state.docs.chunk_roots(&own).count(),
            0,
            "an inline version must name no root"
        );
    }

    #[tokio::test]
    async fn a_chunked_rewrite_drops_the_chunks_of_the_old_version() {
        let mut state = fresh_state();
        let channel = Channel::State;
        write_own(&mut state, channel, big_value('x', 70_000))
            .await
            .expect("the first chunked write");
        write_own(&mut state, channel, big_value('y', 70_000))
            .await
            .expect("the second chunked write");
        assert_eq!(
            state.chunks.stored_chunks(),
            2,
            "a rewrite must keep the chunks of the new version only"
        );
    }

    #[tokio::test]
    async fn a_chunked_write_that_the_rate_limit_refuses_leaves_no_chunk() {
        let mut state = fresh_state();
        let channel = Channel::State;
        let mut refused = None;
        for count in 0..16 {
            if let Err(error) = write_own(&mut state, channel, big_value('x', 70_000 + count)).await
            {
                refused = Some(error);
                break;
            }
        }
        assert!(
            matches!(refused, Some(SendError::State(SliceError::RateLimited))),
            "a burst of chunked writes must reach the rate limit, got {refused:?}"
        );
        assert_eq!(
            state.chunks.stored_chunks(),
            2,
            "a refused write must leave only the chunks of the held version"
        );
    }
    /// Applies the merge patch `merge` to the own value and writes the result, as a state merge does.
    async fn merge_own(
        state: &mut EventLoopState,
        channel: Channel,
        merge: &serde_json::Value,
        now: clock::Instant,
    ) -> Result<(), SendError> {
        if let Some(next) = super::merged_own_value(state, channel, merge)? {
            write_own_at(state, channel, next, now).await?;
        }
        Ok(())
    }

    /// A time `hours` hours after `start`, so each write of a test is past the rate limit.
    fn hours_after(start: clock::Instant, hours: u64) -> clock::Instant {
        start + Duration::from_hours(hours)
    }

    #[tokio::test]
    async fn a_patch_whose_result_is_past_the_cap_is_refused_and_the_held_value_stays() {
        let mut state = fresh_state();
        let channel = Channel::State;
        let start = clock::Instant::now();
        let held = big_value('x', 600_000);
        write_own_at(&mut state, channel, held.clone(), start)
            .await
            .expect("a chunked write under the cap");
        let patch = serde_json::json!({ "j": "y".repeat(600_000) });
        let error = merge_own(&mut state, channel, &patch, hours_after(start, 1))
            .await
            .expect_err("a patch with a whole value past the cap must be refused");
        assert!(
            matches!(
                error,
                SendError::State(SliceError::ValueTooLarge {
                    limit: 1_048_576,
                    ..
                })
            ),
            "the cap applies to the value after the patch, got {error:?}"
        );
        let own = state.identity.author_key();
        assert_eq!(
            state.docs.own_value(channel, &own),
            held,
            "a refused patch must keep the held value"
        );
        assert_eq!(
            state.chunks.stored_chunks(),
            10,
            "a refused patch must keep the chunks of the held value and make none"
        );
    }

    #[tokio::test]
    async fn a_value_at_the_cap_is_taken_and_one_byte_more_is_refused() {
        let mut state = fresh_state();
        let channel = Channel::State;
        let start = clock::Instant::now();
        let cap = 1_048_576;
        // The encoded value of `big_value(_, len)` has `len + 8` bytes.
        write_own_at(&mut state, channel, big_value('x', cap - 9), start)
            .await
            .expect("a value one byte under the cap");
        let at_cap = big_value('y', cap - 8);
        write_own_at(&mut state, channel, at_cap.clone(), hours_after(start, 1))
            .await
            .expect("a value at the cap");
        let error = write_own_at(
            &mut state,
            channel,
            big_value('z', cap - 7),
            hours_after(start, 2),
        )
        .await
        .expect_err("a value one byte over the cap must be refused");
        assert!(
            matches!(
                error,
                SendError::State(SliceError::ValueTooLarge { bytes, limit })
                    if bytes == cap + 1 && limit == cap
            ),
            "the refusal must name the size and the cap, got {error:?}"
        );
        let own = state.identity.author_key();
        assert_eq!(
            state.docs.own_value(channel, &own),
            at_cap,
            "a refused write must keep the last complete version"
        );
        assert_eq!(
            state.chunks.stored_chunks(),
            16,
            "the held version of 1 MiB must keep its 16 chunks and the refusal makes none"
        );
        write_own_at(
            &mut state,
            channel,
            big_value('s', 10),
            hours_after(start, 3),
        )
        .await
        .expect("a shrink after a refusal");
        assert_eq!(
            state.chunks.stored_chunks(),
            0,
            "a shrink to an inline value must drop every chunk"
        );
    }

    #[tokio::test]
    async fn a_delete_patch_shrinks_a_chunked_value_to_inline_and_a_later_patch_grows_it_again() {
        let mut state = fresh_state();
        let channel = Channel::State;
        let start = clock::Instant::now();
        let own = state.identity.author_key();
        let big = serde_json::json!({ "big": "x".repeat(70_000), "small": 1 });
        merge_own(&mut state, channel, &big, start)
            .await
            .expect("a chunked write");
        assert_eq!(
            state.chunks.stored_chunks(),
            2,
            "the big value must be chunked"
        );
        merge_own(
            &mut state,
            channel,
            &serde_json::json!({ "big": null }),
            hours_after(start, 1),
        )
        .await
        .expect("a delete patch");
        assert_eq!(
            serde_json::Value::Object(state.docs.own_value(channel, &own)),
            serde_json::json!({ "small": 1 }),
            "a delete patch must leave the other keys"
        );
        assert_eq!(
            state.chunks.stored_chunks(),
            0,
            "a value that fits one frame again must drop every chunk"
        );
        merge_own(&mut state, channel, &big, hours_after(start, 2))
            .await
            .expect("a patch that grows the value again");
        assert_eq!(
            state.chunks.stored_chunks(),
            2,
            "a value past one frame again must be chunked again"
        );
        let replace = serde_json::json!({ "other": 2, "big": null, "small": null });
        merge_own(&mut state, channel, &replace, hours_after(start, 3))
            .await
            .expect("a patch that replaces the keys");
        assert_eq!(
            serde_json::Value::Object(state.docs.own_value(channel, &own)),
            serde_json::json!({ "other": 2 }),
            "a replace patch must leave only the new key"
        );
        assert_eq!(
            state.chunks.stored_chunks(),
            0,
            "a replace must drop every chunk"
        );
    }

    #[tokio::test]
    async fn fifty_rewrites_leave_the_chunks_of_the_held_version_only() {
        let mut state = fresh_state();
        let channel = Channel::State;
        let start = clock::Instant::now();
        for round in 0..50_u64 {
            let (len, expected) = match round % 3 {
                0 => (70_000 + usize::try_from(round).expect("a small round"), 2),
                1 => (200_000, 4),
                _ => (10, 0),
            };
            write_own_at(
                &mut state,
                channel,
                big_value('x', len),
                hours_after(start, round),
            )
            .await
            .expect("a rewrite");
            assert_eq!(
                state.chunks.stored_chunks(),
                expected,
                "round {round} must keep only the chunks of its own version"
            );
        }
    }

    /// The most characters of `big_value` that one frame takes, found by trial on fresh stores.
    async fn longest_inline_len() -> usize {
        let (mut inline, mut chunked) = (1_000_usize, 3_500_usize);
        while chunked - inline > 1 {
            let middle = inline + (chunked - inline) / 2;
            let mut state = fresh_state();
            write_own(&mut state, Channel::State, big_value('x', middle))
                .await
                .expect("a write at the boundary");
            if state.chunks.stored_chunks() == 0 {
                inline = middle;
            } else {
                chunked = middle;
            }
        }
        inline
    }

    #[tokio::test]
    async fn the_boundary_of_one_frame_flips_between_inline_and_chunked_under_the_rate_limit() {
        let inline_len = longest_inline_len().await;
        let mut state = fresh_state();
        let channel = Channel::State;
        let mut now = clock::Instant::now();
        let mut refused = false;
        for round in 0..16_usize {
            let chunked = round % 2 == 1;
            // The version number is in the body, so the 10th version has one byte more than the 1st: the inline
            // side stays 2 bytes under the edge that the first version found.
            let len = if chunked {
                inline_len + 1
            } else {
                inline_len - 2
            };
            let held_chunks = state.chunks.stored_chunks();
            match write_own_at(&mut state, channel, big_value('x', len), now).await {
                Ok(()) => assert_eq!(
                    state.chunks.stored_chunks(),
                    usize::from(chunked),
                    "round {round}: a value of {len} characters must be {}",
                    if chunked { "chunked" } else { "inline" }
                ),
                Err(SendError::State(SliceError::RateLimited)) => {
                    refused = true;
                    assert_eq!(
                        state.chunks.stored_chunks(),
                        held_chunks,
                        "round {round}: a refused write must leave the chunks of the held version"
                    );
                    now = hours_after(now, 1);
                }
                Err(other) => panic!("round {round}: an unexpected refusal {other:?}"),
            }
        }
        assert!(
            refused,
            "the burst must reach the rate limit at the boundary"
        );
    }
    #[tokio::test]
    async fn the_surfaced_body_of_a_chunked_own_write_is_the_pointer_and_not_the_value() {
        let mut state = fresh_state();
        let channel = Channel::State;
        write_own(&mut state, channel, big_value('x', 700_000))
            .await
            .expect("a chunked write");
        let own = state.identity.author_key();
        let body = state
            .docs
            .plain_body(channel, &own)
            .expect("a body for a held slice");
        let text: &[u8] = body.as_ref();
        assert!(
            text.len() < 400,
            "the surfaced body must stay small for a value of 700000 bytes, got {} bytes",
            text.len()
        );
        let parsed: serde_json::Value = serde_json::from_slice(text).expect("a JSON body");
        assert!(
            parsed["value"].get("$chunks").is_some(),
            "the surfaced body must name the chunks, got {parsed}"
        );
    }

    #[tokio::test]
    async fn the_surfaced_body_of_an_inline_own_write_is_the_value() {
        let mut state = fresh_state();
        let channel = Channel::State;
        let value = big_value('x', 100);
        write_own(&mut state, channel, value.clone())
            .await
            .expect("an inline write");
        let own = state.identity.author_key();
        let body = state
            .docs
            .plain_body(channel, &own)
            .expect("a body for a held slice");
        let text: &[u8] = body.as_ref();
        let parsed: serde_json::Value = serde_json::from_slice(text).expect("a JSON body");
        assert_eq!(
            parsed["value"],
            serde_json::Value::Object(value),
            "the surfaced body of an inline write must carry the value"
        );
    }
}
