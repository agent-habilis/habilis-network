//! An iroh endpoint in a browser tab, talking QUIC over a `WebRTC` data
//! channel.
//!
//! # The two-endpoint dance
//!
//! A tab binds **two endpoints on one secret key**, and that is the single
//! least obvious thing in this example:
//!
//! - a *signalling* endpoint, which holds the relay and is used once, to swap
//!   one JSEP envelope each way with the room;
//! - a *chat* endpoint, with `RelayMode::Disabled` and nothing registered but
//!   the `WebRTC` transport, which carries the conversation.
//!
//! Why not one. iroh only fans a connect's Initial out to candidate paths
//! *while the remote has no selected path*, so a live connection cannot be
//! upgraded onto a transport attached after it. The signalling connection has
//! already settled on the relay; a chat dial from that same endpoint would
//! settle there too and stay for the life of the connection. Giving the chat an
//! endpoint with no other path to lose to is what makes `webrtc` the answer
//! rather than a coin flip.
//!
//! Why one key. The room keys its roster, its session registry and its TLS by
//! endpoint id. Two keys would arrive as two strangers, and the session
//! negotiated by the first would not route the second's traffic.
//!
//! Why only the signalling endpoint may hold the relay: two same-key endpoints
//! registering with one relay server fight over the registration, and ICE never
//! completes.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use chat_proto::{
    CHAT_ALPN, ClientMsg, FRAME_HEADER_LEN, SIGNAL_ALPN, ServerMsg, Ticket, decode_body,
    decode_frame_len, encode_frame,
};
use habilis_network_iroh_webrtc_transport::iroh::endpoint::{Connection, Path, RecvStream, presets};
use habilis_network_iroh_webrtc_transport::iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr,
};
use habilis_network_iroh_webrtc_transport::{
    BrowserHubTransport, IceServers, MAX_ENVELOPE_BYTES, SignalEnvelope, WEBRTC_TRANSPORT_ID,
    WebRtcHandle, browser_offer, custom_addr,
};
use futures::StreamExt as _;
use futures::channel::mpsc;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// What the tab is told, as it happens.
///
/// JSON over the wasm boundary rather than `serde-wasm-bindgen`: the shapes are
/// small, the cost is irrelevant at chat rates, and a plain object is what the
/// JS side wants to switch on anyway.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Event {
    /// Progress during the join, so a tab is never silently busy for the ten
    /// seconds ICE gathering can take.
    Status { text: String },
    Welcome { you: String, roster: Vec<String> },
    Joined { nick: String },
    Left { nick: String },
    Said { nick: String, text: String },
    /// The link is gone. Terminal — nothing follows it.
    Closed { reason: String },
}

/// A joined tab.
#[wasm_bindgen]
#[derive(Debug)]
pub struct ChatPeer {
    /// Typed lines, drained by a writer task. A channel rather than a
    /// `RefCell<SendStream>` because writing is async and `say` is not: a
    /// borrow held across the await would panic the moment someone typed
    /// quickly.
    outbox: mpsc::UnboundedSender<String>,
    nick: String,
    remote: EndpointId,
    connection: Connection,
    hub: Arc<BrowserHubTransport>,
    /// Held only to keep them bound. Dropping either tears its endpoint down,
    /// and the chat endpoint's is the data channel.
    _signalling: Endpoint,
    _chat: Endpoint,
}

#[wasm_bindgen]
impl ChatPeer {
    /// Join the room named by `ticket`.
    ///
    /// `on_event` is called with one [`Event`] object per thing that happens,
    /// starting during the join itself.
    ///
    /// # Errors
    /// The ticket does not decode, an endpoint will not bind, the JSEP round
    /// fails, or the room refuses the join.
    pub async fn join(
        ticket: String,
        nick: String,
        on_event: js_sys::Function,
    ) -> Result<ChatPeer, JsValue> {
        // First thing in every entry point: without it a panic surfaces as
        // `unreachable executed` with no Rust frames at all.
        console_error_panic_hook::set_once();

        let emit = Emitter::new(on_event);
        let ticket = Ticket::decode(&ticket).map_err(|error| err("decode the ticket", &error))?;

        // One key, two endpoints — see the module docs.
        let key = SecretKey::generate();
        let local = key.public();

        emit.status("binding the signalling endpoint");
        let relay_mode = match ticket.relay.clone() {
            Some(url) => RelayMode::custom([url]),
            None => RelayMode::Default,
        };
        let signalling = Endpoint::builder(presets::Minimal)
            .secret_key(key.clone())
            .relay_mode(relay_mode)
            .bind()
            .await
            .map_err(|error| err("bind the signalling endpoint", &error))?;

        emit.status("reaching a relay");
        signalling.online().await;

        // The hub belongs to the chat endpoint, but the session is negotiated
        // over the signalling one — which is the whole point of the split.
        let hub = BrowserHubTransport::new(local);
        let handle = WebRtcHandle::new(Arc::clone(&hub));

        emit.status("negotiating a data channel over the relay");
        let remote = negotiate(&signalling, &ticket, local, &hub).await?;
        emit.status("data channel up");

        let chat = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            // Deliberate: no relay on this one. Its whole purpose is to have no
            // other path the chat dial could settle on.
            .relay_mode(RelayMode::Disabled)
            .add_custom_transport(handle.transport())
            // Registering the transport is not enough. iroh's default selector
            // skips paths it has no RTT sample for, which a freshly attached
            // WebRTC path always is.
            .path_selector(handle.path_selector())
            .bind()
            .await
            .map_err(|error| err("bind the chat endpoint", &error))?;

        // Addressed by identity alone: the WebRTC address convention derives
        // from the endpoint id, so both ends already know it.
        let target = EndpointAddr::from_parts(remote, [TransportAddr::Custom(custom_addr(remote))]);
        let connection = chat
            .connect(target, CHAT_ALPN)
            .await
            .map_err(|error| err("dial the room", &error))?;

        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| err("open the chat stream", &error))?;

        let hello = ClientMsg::Join { nick: nick.clone() };
        hello.validate().map_err(|error| err("the nick", &error))?;
        write_msg(&mut send, &hello).await?;

        let welcome: ServerMsg = read_msg(&mut recv).await?;
        let you = match &welcome {
            ServerMsg::Welcome { you, roster } => {
                emit.send(&Event::Welcome {
                    you: you.clone(),
                    roster: roster.clone(),
                });
                you.clone()
            }
            ServerMsg::Joined { .. } | ServerMsg::Left { .. } | ServerMsg::Said { .. } => {
                return Err(JsValue::from_str("the room answered the join with something else"));
            }
        };

        spawn_reader(recv, emit.clone());
        let outbox = spawn_writer(send, emit);

        Ok(Self {
            outbox,
            nick: you,
            remote,
            connection,
            hub,
            _signalling: signalling,
            _chat: chat,
        })
    }

    /// Queue a line. Returns immediately; the writer task sends it.
    ///
    /// Silently drops the line if the link is already gone — the tab will have
    /// had a `closed` event, and a second complaint per keystroke helps nobody.
    pub fn say(&self, text: String) {
        let _ = self.outbox.unbounded_send(text);
    }

    /// The nick the room assigned, which may differ from the one asked for.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn nick(&self) -> String {
        self.nick.clone()
    }

    /// Which transport is carrying the chat right now: `webrtc`, `relay`, `ip`
    /// or `none`.
    ///
    /// The demo is this string. "It connected" proves nothing — a peer that
    /// quietly fell back to the relay connects perfectly well and looks
    /// identical from the chat's point of view.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn path(&self) -> String {
        let paths = self.connection.paths();
        let Some(selected) = paths.iter().find(Path::is_selected) else {
            return "none".to_owned();
        };
        label_of(selected.remote_addr())
    }

    /// The ICE candidate pair the data channel settled on, as
    /// `"<local> ⇢ <remote>"`.
    ///
    /// Read from `RTCPeerConnection.getStats()`, so it is the browser's own
    /// account rather than ours — which is what makes it evidence rather than a
    /// claim.
    ///
    /// The candidate *type* is the part to read, and it is the part always
    /// present: `host` means the two peers found each other directly on a LAN,
    /// `srflx` means STUN gave them each other's public address and the hole
    /// punch worked, `prflx` means the pair was learned from an incoming check
    /// rather than from gathering. (`relay` would mean TURN, which this
    /// transport refuses, so it cannot appear here at all.) The address is
    /// appended only when the browser names one — Safari withholds it for
    /// `host` and `prflx`, Chrome for `prflx`.
    ///
    /// `None` before the pair is nominated, or when the chat is not on `WebRTC`.
    #[wasm_bindgen(js_name = "icePair")]
    #[must_use]
    pub async fn ice_pair(&self) -> Option<String> {
        let remote = self.hub.selected_remote_candidate(&self.remote).await?;
        let local = self.hub.selected_local_candidate(&self.remote).await;
        let local = local.map_or_else(|| "?".to_owned(), |(addr, kind)| candidate(&addr, &kind));
        Some(format!("{local} ⇢ {}", candidate(&remote.0, &remote.1)))
    }

    /// Leave. Idempotent.
    pub fn close(&self) {
        // `&self`, never `self` by value: a by-value method is a trap through
        // wasm-bindgen, since it invalidates the JS handle and every later call
        // on it throws `null pointer passed to rust`.
        self.outbox.close_channel();
        self.connection.close(0u32.into(), b"bye");
        let _ = self.hub.detach(&self.remote);
    }
}

/// Swap one envelope each way over the relay, and attach the session.
///
/// Vanilla ICE: candidates ride inside the SDP, so gathering must finish before
/// the offer goes out. There is no trickle message to add them later, which is
/// why this can take seconds and why the tab is told it is happening.
async fn negotiate(
    signalling: &Endpoint,
    ticket: &Ticket,
    local: EndpointId,
    hub: &BrowserHubTransport,
) -> Result<EndpointId, JsValue> {
    let mut room = EndpointAddr::new(ticket.id);
    if let Some(url) = ticket.relay.clone() {
        room = room.with_relay_url(url);
    }

    let connection = signalling
        .connect(room, SIGNAL_ALPN)
        .await
        .map_err(|error| err("dial the signalling lane", &error))?;
    // The TLS-proven id, not the envelope's claim.
    let remote = connection.remote_id();

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| err("open the signal stream", &error))?;

    // STUN only. TURN is refused by the transport at the enforcement point: a
    // pair that cannot ICE falls back to the iroh relay rather than to a second
    // relay at the ICE layer.
    let (pending, offer) = browser_offer(local, &IceServers::default()).await?;
    let encoded = serde_json::to_vec(&offer).map_err(|error| err("encode the offer", &error))?;
    send.write_all(&encoded)
        .await
        .map_err(|error| err("write the offer", &error))?;
    // `finish` is the frame boundary: one envelope per direction, delimited by
    // the end of the stream. No length prefix, unlike the chat.
    send.finish().map_err(|error| err("finish the offer", &error))?;

    let raw = recv
        .read_to_end(MAX_ENVELOPE_BYTES)
        .await
        .map_err(|error| err("read the answer", &error))?;
    let answer: SignalEnvelope =
        serde_json::from_slice(&raw).map_err(|error| err("decode the answer", &error))?;
    match &answer {
        SignalEnvelope::Answer { .. } => {}
        SignalEnvelope::Offer { .. } => {
            return Err(JsValue::from_str("the room sent an offer where an answer belongs"));
        }
        SignalEnvelope::Error { reason, .. } => {
            return Err(JsValue::from_str(&format!("the room refused: {reason}")));
        }
    }

    let session = pending.complete(hub, &answer).await?;
    if session.remote != remote {
        return Err(JsValue::from_str(
            "the answer was signed by a different endpoint than the connection",
        ));
    }

    connection.close(0u32.into(), b"jsep done");
    Ok(remote)
}

/// Drain the room's messages into the tab's callback.
fn spawn_reader(mut recv: RecvStream, emit: Emitter) {
    wasm_bindgen_futures::spawn_local(async move {
        loop {
            match read_msg::<ServerMsg>(&mut recv).await {
                Ok(msg) => emit.send(&event_of(&msg)),
                Err(error) => {
                    emit.send(&Event::Closed {
                        reason: describe(&error),
                    });
                    return;
                }
            }
        }
    });
}

/// Drain the outbox onto the stream.
fn spawn_writer(
    mut send: habilis_network_iroh_webrtc_transport::iroh::endpoint::SendStream,
    emit: Emitter,
) -> mpsc::UnboundedSender<String> {
    let (tx, mut rx) = mpsc::unbounded::<String>();
    wasm_bindgen_futures::spawn_local(async move {
        while let Some(text) = rx.next().await {
            let msg = ClientMsg::Say { text };
            if let Err(error) = write_msg(&mut send, &msg).await {
                emit.send(&Event::Closed {
                    reason: describe(&error),
                });
                return;
            }
        }
    });
    tx
}

fn event_of(msg: &ServerMsg) -> Event {
    match msg {
        ServerMsg::Welcome { you, roster } => Event::Welcome {
            you: you.clone(),
            roster: roster.clone(),
        },
        ServerMsg::Joined { nick } => Event::Joined { nick: nick.clone() },
        ServerMsg::Left { nick } => Event::Left { nick: nick.clone() },
        ServerMsg::Said { nick, text } => Event::Said {
            nick: nick.clone(),
            text: text.clone(),
        },
    }
}

/// `host (192.168.1.4)`, or just `host` when the browser withholds the address.
fn candidate(address: &str, kind: &str) -> String {
    if address.is_empty() {
        kind.to_owned()
    } else {
        format!("{kind} ({address})")
    }
}

fn label_of(addr: &TransportAddr) -> String {
    match addr {
        TransportAddr::Custom(custom) if custom.id() == WEBRTC_TRANSPORT_ID => "webrtc".to_owned(),
        TransportAddr::Custom(custom) => format!("custom({})", custom.id()),
        TransportAddr::Ip(_) => "ip".to_owned(),
        TransportAddr::Relay(_) => "relay".to_owned(),
        other => format!("{other:?}"),
    }
}

// ── framing ──────────────────────────────────────────────────────────────────
//
// The same two reads the CLI does, against the same `chat_proto` helpers. Not
// shared code only because the stream types cannot be: there is no tokio here.

async fn write_msg<T: Serialize>(
    send: &mut habilis_network_iroh_webrtc_transport::iroh::endpoint::SendStream,
    msg: &T,
) -> Result<(), JsValue> {
    let frame = encode_frame(msg).map_err(|error| err("encode a frame", &error))?;
    send.write_all(&frame)
        .await
        .map_err(|error| err("write a frame", &error))?;
    Ok(())
}

async fn read_msg<T: serde::de::DeserializeOwned>(recv: &mut RecvStream) -> Result<T, JsValue> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    recv.read_exact(&mut header)
        .await
        .map_err(|error| err("read a frame header", &error))?;
    let len = decode_frame_len(header).map_err(|error| err("frame length", &error))?;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|error| err("read a frame body", &error))?;
    decode_body(&body).map_err(|error| err("decode a frame", &error))
}

// ── talking to JS ────────────────────────────────────────────────────────────

/// The tab's callback, callable from several tasks.
#[derive(Debug, Clone)]
struct Emitter {
    callback: Rc<js_sys::Function>,
    /// Set once a terminal [`Event::Closed`] has gone out, so a reader and a
    /// writer failing together do not report the link dying twice.
    closed: Rc<RefCell<bool>>,
}

impl Emitter {
    fn new(callback: js_sys::Function) -> Self {
        Self {
            callback: Rc::new(callback),
            closed: Rc::new(RefCell::new(false)),
        }
    }

    fn status(&self, text: &str) {
        self.send(&Event::Status {
            text: text.to_owned(),
        });
    }

    fn send(&self, event: &Event) {
        if matches!(event, Event::Closed { .. }) {
            let mut closed = self.closed.borrow_mut();
            if *closed {
                return;
            }
            *closed = true;
        }
        let Ok(json) = serde_json::to_string(event) else {
            return;
        };
        let Ok(value) = js_sys::JSON::parse(&json) else {
            return;
        };
        if let Err(error) = self.callback.call1(&JsValue::NULL, &value) {
            web_sys::console::warn_1(&error);
        }
    }
}

fn err(context: &str, error: &impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&format!("failed to {context}: {error}"))
}

fn describe(error: &JsValue) -> String {
    error
        .as_string()
        .unwrap_or_else(|| format!("{:?}", error.clone()))
}
