use chat_proto::ServerMsg;
use serde::Serialize;

/// What the tab is told, as it happens.
///
/// JSON over the wasm boundary rather than `serde-wasm-bindgen`: the shapes are
/// small, the cost is irrelevant at chat rates, and a plain object is what the
/// JS side wants to switch on anyway.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Event {
    /// Progress during the join, so a tab is never silently busy for the ten
    /// seconds ICE gathering can take.
    Status {
        text: String,
    },
    Welcome {
        you: String,
        roster: Vec<String>,
    },
    Joined {
        nick: String,
    },
    Left {
        nick: String,
    },
    Said {
        nick: String,
        text: String,
    },
    /// The link is gone. Terminal — nothing follows it.
    Closed {
        reason: String,
    },
}

pub(crate) fn event_of(message: &ServerMsg) -> Event {
    match message {
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
