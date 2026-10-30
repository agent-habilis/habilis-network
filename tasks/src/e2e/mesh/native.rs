use habilis_network::membership;

use crate::e2e::Skip;

use tokio::sync::{mpsc, oneshot};

/// The in-process side of a cell: a live membership plus everything a check
/// reads — inbound messages, surfaced events, the roster on demand.
pub(in crate::e2e) struct Native {
    pub(in crate::e2e) membership: membership::Membership,
    events: mpsc::UnboundedReceiver<String>,
    seen_events: Vec<serde_json::Value>,
    seen_msgs: Vec<membership::Inbound>,
}

impl Native {
    pub(in crate::e2e) async fn open(opts: &membership::JoinOptions) -> Result<Self, Skip> {
        let (sink, events) = membership::json_sink();
        let membership = membership::join(opts, sink)
            .await
            .map_err(|error| Skip(format!("native peer failed to open: {error:#}")))?;
        Ok(Self {
            membership,
            events,
            seen_events: Vec::new(),
            seen_msgs: Vec::new(),
        })
    }

    pub(super) fn pump(&mut self) {
        while let Ok(json) = self.events.try_recv() {
            if let Ok(event) = serde_json::from_str(&json) {
                self.seen_events.push(event);
            }
        }
        while let Ok(msg) = self.membership.inbound.try_recv() {
            self.seen_msgs.push(msg);
        }
    }

    pub(in crate::e2e) fn saw_event(&mut self, kind: &str, nick: &str) -> bool {
        self.pump();
        self.seen_events.iter().any(|event| {
            event.get("kind").and_then(serde_json::Value::as_str) == Some(kind)
                && event.get("nick").and_then(serde_json::Value::as_str) == Some(nick)
        })
    }

    pub(in crate::e2e) fn saw_msg(&mut self, text: &str, directed: bool) -> bool {
        self.pump();
        self.seen_msgs
            .iter()
            .any(|msg| msg.directed == directed && msg.text == text)
    }

    pub(in crate::e2e) async fn request<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<T>) -> membership::Request,
    ) -> Result<T, String> {
        self.membership.request(build).await
    }

    pub(in crate::e2e) async fn roster_json(&self) -> String {
        self.request(|reply| membership::Request::Inspect(membership::Inspect::Peers { reply }))
            .await
            .unwrap_or_default()
    }

    pub(in crate::e2e) async fn send(&self, to: Option<&str>, text: &str) -> Result<(), String> {
        let to = membership::parse_to(to).map_err(|error| error.to_string())?;
        let body = membership::msg_body(text).map_err(|error| error.to_string())?;
        self.request(|reply| {
            membership::Request::Messaging(membership::Messaging::Send { to, body, reply })
        })
        .await?
    }

    pub(super) async fn state_merge(&self, merge: serde_json::Value) -> Result<(), String> {
        self.request(|reply| {
            membership::Request::Messaging(membership::Messaging::StateMerge { merge, reply })
        })
        .await?
    }

    pub(super) async fn state_json(&self) -> String {
        self.request(|reply| membership::Request::Inspect(membership::Inspect::StateJson { reply }))
            .await
            .unwrap_or_default()
    }
}
