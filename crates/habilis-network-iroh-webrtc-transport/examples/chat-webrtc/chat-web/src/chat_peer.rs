use crate::{
    Emitter, Event, candidate, err, label_of, negotiate, read_msg, spawn_reader, spawn_writer,
    write_msg,
};
use chat_proto::{CHAT_ALPN, ClientMsg, ServerMsg, Ticket};
use futures::channel::mpsc;
use habilis_network_iroh_webrtc_transport::iroh::endpoint::{Connection, Path, presets};
use habilis_network_iroh_webrtc_transport::iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr,
};
use habilis_network_iroh_webrtc_transport::{BrowserHubTransport, WebRtcHandle, custom_addr};
use std::sync::Arc;
use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

/// A joined tab.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct ChatPeer {
    /// Typed lines, drained by a writer task. A channel rather than a
    /// `RefCell<SendStream>` because writing is async and `say` is not: a
    /// borrow held across the await would panic the moment someone typed
    /// quickly.
    outbox: mpsc::UnboundedSender<String>,
    nick: String,
    remote: EndpointId,
    connection: Connection,
    // the hub is shared with the endpoint and the page session tasks
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
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(key.clone())
            .relay_mode(relay_mode);
        let signalling = builder
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

        let transport = handle.transport();
        let selector = handle.path_selector();
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(key)
            // Deliberate: no relay on this one. Its whole purpose is to have no
            // other path the chat dial could settle on.
            .relay_mode(RelayMode::Disabled)
            .add_custom_transport(transport);
        // Registering the transport is not enough. iroh's default selector
        // skips paths it has no RTT sample for, which a freshly attached
        // WebRTC path always is.
        let builder = builder.path_selector(selector);
        let chat = builder
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
                return Err(JsValue::from_str(
                    "the room answered the join with something else",
                ));
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
        let local = local.map_or_else(
            || "?".to_owned(),
            |(address, kind)| candidate(&address, &kind),
        );
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
