//! An in-process Nostr relay on `ws://127.0.0.1:<port>`, for tests.
//!
//! It checks every event's id and signature and filters by kinds, `#x` and
//! `since`, as a real relay does, so a client bug shows up here rather than on
//! a public relay. It can be told to refuse (with a NIP-01 reason prefix), to
//! swallow events, or to drop every connection.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result};
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_websockets::{Message, ServerBuilder};
use url::Url;

use crate::event::{Event, TAG};

/// A running test relay. Dropping it stops the listener and every connection.
#[derive(Debug)]
pub struct TestRelay {
    url: Url,
    shared: Arc<Mutex<State>>,
    _accept: n0_future::task::AbortOnDropHandle<()>,
}

#[derive(Debug, Default)]
struct State {
    refuse_events: Option<String>,
    refuse_subs: Option<String>,
    swallow_events: bool,
    tamper_events: bool,
    hang_up_on_accept: bool,
    reqs: usize,
    next_conn: u64,
    accepted: usize,
    conns: HashMap<u64, Conn>,
}

#[derive(Debug)]
struct Conn {
    outbound: mpsc::UnboundedSender<String>,
    subs: HashMap<String, Sub>,
    task: Option<tokio::task::AbortHandle>,
}

#[derive(Debug)]
struct Sub {
    kinds: Vec<u64>,
    tags: Vec<String>,
    since: u64,
}

impl Sub {
    fn matches(&self, event: &Event) -> bool {
        self.kinds.contains(&u64::from(event.kind))
            && event
                .tag()
                .is_some_and(|tag| self.tags.iter().any(|want| want == tag))
            && event.created_at >= self.since
    }
}

impl TestRelay {
    /// # Errors
    /// The loopback listener cannot bind.
    pub async fn spawn() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind test relay")?;
        let url: Url = format!("ws://{}", listener.local_addr()?)
            .parse()
            .context("a socket address makes a valid URL")?;
        let shared = Arc::new(Mutex::new(State::default()));
        let accept = tokio::spawn(accept_loop(listener, shared.clone()));
        Ok(Self {
            url,
            shared,
            _accept: n0_future::task::AbortOnDropHandle::new(accept),
        })
    }

    #[must_use]
    pub fn url(&self) -> Url {
        self.url.clone()
    }

    /// Answer every EVENT with `OK false <reason>`, or accept again with `None`.
    pub fn refuse_events(&self, reason: Option<&str>) {
        self.state().refuse_events = reason.map(str::to_owned);
    }

    /// Answer every REQ with `CLOSED <reason>`, or accept again with `None`.
    pub fn refuse_subs(&self, reason: Option<&str>) {
        self.state().refuse_subs = reason.map(str::to_owned);
    }

    /// Accept events with `OK true` but forward none, as a relay that drops
    /// ephemeral kinds does.
    pub fn swallow_events(&self, swallow: bool) {
        self.state().swallow_events = swallow;
    }

    /// Forward every event with its `content` changed and its id kept, as a
    /// buggy or hostile relay might.
    pub fn tamper_events(&self, tamper: bool) {
        self.state().tamper_events = tamper;
    }

    /// Finish each `WebSocket` handshake, then hang up at once, as an overloaded
    /// relay at its connection cap does.
    pub fn hang_up_on_accept(&self, hang_up: bool) {
        self.state().hang_up_on_accept = hang_up;
    }

    /// Deliver `event` to every matching subscription, as if another client
    /// had published it. The event is not checked, so a test can pick any
    /// `created_at`.
    pub fn inject(&self, event: &Event) {
        fan_out(&self.state(), event);
    }

    /// Send a raw text frame to every connection.
    pub fn send_raw(&self, text: &str) {
        for conn in self.state().conns.values() {
            let _ = conn.outbound.send(text.to_owned());
        }
    }

    /// REQ frames received since the relay started.
    #[must_use]
    pub fn reqs(&self) -> usize {
        self.state().reqs
    }

    /// Connections open now.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.state().conns.len()
    }

    /// Connections accepted since the relay started.
    #[must_use]
    pub fn accepted(&self) -> usize {
        self.state().accepted
    }

    /// Close every connection without a close frame, as a crash or a network
    /// drop does. The listener keeps accepting.
    pub fn drop_connections(&self) {
        let conns = std::mem::take(&mut self.state().conns);
        for conn in conns.into_values() {
            if let Some(task) = conn.task {
                task.abort();
            }
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.shared.lock().expect("test relay mutex poisoned")
    }
}

async fn accept_loop(listener: TcpListener, shared: Arc<Mutex<State>>) {
    while let Ok((stream, _)) = listener.accept().await {
        let (outbound, outbound_rx) = mpsc::unbounded_channel();
        let id = {
            let mut state = shared.lock().expect("test relay mutex poisoned");
            state.next_conn += 1;
            state.accepted += 1;
            let id = state.next_conn;
            state.conns.insert(
                id,
                Conn {
                    outbound,
                    subs: HashMap::new(),
                    task: None,
                },
            );
            id
        };
        let task = tokio::spawn(serve(stream, id, shared.clone(), outbound_rx));
        if let Some(conn) = shared
            .lock()
            .expect("test relay mutex poisoned")
            .conns
            .get_mut(&id)
        {
            conn.task = Some(task.abort_handle());
        }
    }
}

async fn serve(
    stream: tokio::net::TcpStream,
    id: u64,
    shared: Arc<Mutex<State>>,
    mut outbound: mpsc::UnboundedReceiver<String>,
) {
    let Ok((_request, socket)) = ServerBuilder::new().accept(stream).await else {
        shared
            .lock()
            .expect("test relay mutex poisoned")
            .conns
            .remove(&id);
        return;
    };
    let hang_up = shared
        .lock()
        .expect("test relay mutex poisoned")
        .hang_up_on_accept;
    let (mut sink, mut frames) = socket.split();
    loop {
        if hang_up {
            break;
        }
        tokio::select! {
            frame = outbound.recv() => {
                let Some(frame) = frame else { break };
                if sink.send(Message::text(frame)).await.is_err() {
                    break;
                }
            }
            message = frames.next() => {
                let Some(Ok(message)) = message else { break };
                let Some(text) = message.as_text() else { continue };
                handle(text, id, &shared);
            }
        }
    }
    shared
        .lock()
        .expect("test relay mutex poisoned")
        .conns
        .remove(&id);
}

fn handle(text: &str, id: u64, shared: &Mutex<State>) {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let mut state = shared.lock().expect("test relay mutex poisoned");
    let reply = |current: &State, frame: Value| {
        if let Some(conn) = current.conns.get(&id) {
            let _ = conn.outbound.send(frame.to_string());
        }
    };
    match items.first().and_then(Value::as_str) {
        Some("EVENT") => {
            let Some(Ok(event)) = items
                .get(1)
                .map(|raw| serde_json::from_value::<Event>(raw.clone()))
            else {
                return;
            };
            if let Err(error) = event.verify() {
                reply(
                    &state,
                    serde_json::json!(["OK", event.id, false, format!("invalid: {error}")]),
                );
                return;
            }
            if let Some(reason) = state.refuse_events.clone() {
                reply(&state, serde_json::json!(["OK", event.id, false, reason]));
                return;
            }
            reply(&state, serde_json::json!(["OK", event.id, true, ""]));
            if state.swallow_events {
                return;
            }
            if state.tamper_events {
                let mut forged = event;
                forged.content.push_str(" (tampered)");
                fan_out(&state, &forged);
            } else {
                fan_out(&state, &event);
            }
        }
        Some("REQ") => {
            state.reqs += 1;
            let (Some(sub_id), Some(filter)) = (items.get(1).and_then(Value::as_str), items.get(2))
            else {
                return;
            };
            if let Some(reason) = state.refuse_subs.clone() {
                reply(&state, serde_json::json!(["CLOSED", sub_id, reason]));
                return;
            }
            let numbers = |key: &str| -> Vec<u64> {
                filter
                    .get(key)
                    .and_then(Value::as_array)
                    .map(|values| values.iter().filter_map(Value::as_u64).collect())
                    .unwrap_or_default()
            };
            let sub = Sub {
                kinds: numbers("kinds"),
                tags: filter
                    .get(format!("#{TAG}"))
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                since: filter.get("since").and_then(Value::as_u64).unwrap_or(0),
            };
            if let Some(conn) = state.conns.get_mut(&id) {
                conn.subs.insert(sub_id.to_owned(), sub);
            }
            reply(&state, serde_json::json!(["EOSE", sub_id]));
        }
        Some("CLOSE") => {
            if let (Some(sub_id), Some(conn)) = (
                items.get(1).and_then(Value::as_str),
                state.conns.get_mut(&id),
            ) {
                conn.subs.remove(sub_id);
            }
        }
        _ => {}
    }
}

fn fan_out(state: &State, event: &Event) {
    for conn in state.conns.values() {
        for (sub_id, sub) in &conn.subs {
            if sub.matches(event) {
                let _ = conn
                    .outbound
                    .send(serde_json::json!(["EVENT", sub_id, event]).to_string());
            }
        }
    }
}
