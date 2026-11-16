//! An in-process Nostr relay on `ws://127.0.0.1:<port>`, for tests.
//!
//! It checks every event's id and signature and filters by kinds, `#x` and
//! `since`, as a real relay does, so a client bug shows up here rather than on
//! a public relay. It can be told to refuse (with a NIP-01 reason prefix), to
//! swallow events, or to drop every connection.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt as _, StreamExt as _};
use n0_future::task::AbortOnDropHandle;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio_websockets::{Message, ServerBuilder};
use url::Url;

use crate::event::{Event, TAG};

use std::{mem, sync};
use tokio::net;
/// A running test relay. Dropping it stops the listener and every connection.
#[must_use]
#[derive(Debug)]
pub struct TestRelay {
    url: Url,
    // The accept loop and every connection task read the same state.
    shared: Arc<Mutex<State>>,
    _accept: AbortOnDropHandle<()>,
}

#[derive(Debug, Default)]
struct State {
    refuse_events: Option<String>,
    refuse_subs: Option<String>,
    swallow_events: bool,
    tamper_events: bool,
    hang_up_on_accept: bool,
    reqs: usize,
    next_client: u64,
    accepted: usize,
    clients: HashMap<u64, Client>,
}

#[derive(Debug)]
struct Client {
    outbound: mpsc::UnboundedSender<String>,
    subs: HashMap<String, Sub>,
    task: Option<AbortHandle>,
}

#[derive(Debug)]
struct Sub {
    kinds: Vec<u64>,
    tags: Vec<String>,
    since: u64,
}

impl Sub {
    fn matches(&self, event: &Event) -> bool {
        let wanted = |tag: &str| self.tags.iter().any(|want| want == tag);
        let tagged = event.tag().is_some_and(wanted);
        self.kinds.contains(&u64::from(event.kind)) && tagged && event.created_at >= self.since
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        let clients = mem::take(&mut self.state().clients);
        for client in clients.into_values() {
            if let Some(task) = client.task {
                task.abort();
            }
        }
    }
}

impl TestRelay {
    /// # Errors
    /// The loopback listener cannot bind.
    ///
    /// # Panics
    /// Never in practice: a socket address always makes a valid URL.
    pub async fn spawn() -> Result<Self, io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = format!("ws://{}", listener.local_addr()?);
        let url: Url = address.parse().expect("a socket address makes a valid URL");
        // The accept loop and the handle read the same state.
        let shared = Arc::new(Mutex::new(State::default()));
        let for_accept = Arc::clone(&shared);
        let accept = tokio::spawn(accept_loop(listener, for_accept));
        Ok(Self {
            url,
            shared,
            _accept: AbortOnDropHandle::new(accept),
        })
    }

    #[must_use]
    /// The `ws://` address the relay listens on.
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
    pub fn swallow_events(
        &self,
        // true to swallow, false to forward again
        swallow: bool,
    ) {
        self.state().swallow_events = swallow;
    }

    /// Forward every event with its `content` changed and its id kept, as a
    /// buggy or hostile relay might.
    pub fn tamper_events(
        &self,
        // true to change the content, false to forward it as sent
        tamper: bool,
    ) {
        self.state().tamper_events = tamper;
    }

    /// Finish each `WebSocket` handshake, then hang up at once, as an overloaded
    /// relay at its connection cap does.
    pub fn hang_up_on_accept(
        &self,
        // true to hang up on each new connection, false to serve it
        hang_up: bool,
    ) {
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
        for client in self.state().clients.values() {
            let _ = client.outbound.send(text.to_owned());
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
        self.state().clients.len()
    }

    /// Connections accepted since the relay started.
    #[must_use]
    pub fn accepted(&self) -> usize {
        self.state().accepted
    }

    /// Close every connection without a close frame, as a crash or a network
    /// drop does. The listener keeps accepting.
    pub fn drop_connections(&self) {
        let clients = mem::take(&mut self.state().clients);
        for client in clients.into_values() {
            if let Some(task) = client.task {
                task.abort();
            }
        }
    }

    fn state(&self) -> sync::MutexGuard<'_, State> {
        self.shared.lock().expect("test relay mutex poisoned")
    }
}

// Shared with the handle of the relay, which reads and sets the same state.
async fn accept_loop(listener: TcpListener, shared: Arc<Mutex<State>>) {
    while let Ok((stream, _)) = listener.accept().await {
        let (outbound, outbound_rx) = mpsc::unbounded_channel();
        let id = {
            let mut state = shared.lock().expect("test relay mutex poisoned");
            state.next_client += 1;
            state.accepted += 1;
            let id = state.next_client;
            state.clients.insert(
                id,
                Client {
                    outbound,
                    subs: HashMap::new(),
                    task: None,
                },
            );
            id
        };
        // The task reads the same state as the accept loop.
        let for_task = Arc::clone(&shared);
        let task = tokio::spawn(serve(stream, id, for_task, outbound_rx));
        if let Some(client) = shared
            .lock()
            .expect("test relay mutex poisoned")
            .clients
            .get_mut(&id)
        {
            client.task = Some(task.abort_handle());
        }
    }
}

async fn serve(
    stream: net::TcpStream,
    id: u64,
    // The same state as the accept loop and the handle of the relay.
    shared: Arc<Mutex<State>>,
    mut outbound: mpsc::UnboundedReceiver<String>,
) {
    let Ok((_request, socket)) = ServerBuilder::new().accept(stream).await else {
        shared
            .lock()
            .expect("test relay mutex poisoned")
            .clients
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
        .clients
        .remove(&id);
}

fn handle(text: &str, id: u64, shared: &Mutex<State>) {
    let parsed: Result<Value, _> = serde_json::from_str(text);
    let Ok(Value::Array(items)) = parsed else {
        return;
    };
    let mut state = shared.lock().expect("test relay mutex poisoned");
    let reply = |current: &State, frame: Value| {
        if let Some(client) = current.clients.get(&id) {
            let _ = client.outbound.send(frame.to_string());
        }
    };
    match items.first().and_then(Value::as_str) {
        Some("EVENT") => {
            let Some(raw) = items.get(1) else {
                return;
            };
            let decoded: Result<Event, _> = serde_json::from_value(raw.clone());
            let Ok(event) = decoded else {
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
            let listed = |key: &str| -> Vec<Value> {
                let values = filter.get(key).and_then(Value::as_array);
                values.cloned().unwrap_or_default()
            };
            let kinds: Vec<u64> = listed("kinds").iter().filter_map(Value::as_u64).collect();
            let tags: Vec<String> = listed(&format!("#{TAG}"))
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            let sub = Sub {
                kinds,
                tags,
                since: filter.get("since").and_then(Value::as_u64).unwrap_or(0),
            };
            if let Some(client) = state.clients.get_mut(&id) {
                client.subs.insert(sub_id.to_owned(), sub);
            }
            reply(&state, serde_json::json!(["EOSE", sub_id]));
        }
        Some("CLOSE") => {
            if let (Some(sub_id), Some(client)) = (
                items.get(1).and_then(Value::as_str),
                state.clients.get_mut(&id),
            ) {
                client.subs.remove(sub_id);
            }
        }
        _ => {}
    }
}

fn fan_out(state: &State, event: &Event) {
    for client in state.clients.values() {
        for (sub_id, sub) in &client.subs {
            if sub.matches(event) {
                let _ = client
                    .outbound
                    .send(serde_json::json!(["EVENT", sub_id, event]).to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpStream;
    use tokio::time;

    use super::TestRelay;

    /// Dropping the relay stops every connection, not only the listener: a
    /// client that was connected sees its socket close.
    #[tokio::test]
    async fn dropping_the_relay_closes_its_connections() {
        let relay = TestRelay::spawn().await.expect("spawn test relay");
        let address = relay.url();
        let host = address.host_str().expect("a host");
        let port = address.port().expect("a port");
        let mut client = TcpStream::connect((host, port)).await.expect("connect");
        for _ in 0..100 {
            if relay.connections() == 1 {
                break;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(relay.connections(), 1, "the relay took the connection");

        drop(relay);
        let mut buffer = [0u8; 16];
        let read = time::timeout(Duration::from_secs(2), client.read(&mut buffer)).await;
        assert!(
            matches!(read, Ok(Ok(0))),
            "the client sees the socket close, but got {read:?}"
        );
    }
}
