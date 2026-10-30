use serde::{Deserialize, Serialize};

use crate::{MAX_NICK_CHARS, MAX_TEXT_CHARS, ProtoError};

/// Peer to room.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// First frame on the stream, always. The room answers with
    /// [`ServerMsg::Welcome`].
    Join {
        nick: String,
    },
    Say {
        text: String,
    },
}

/// Room to peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Answer to [`ClientMsg::Join`].
    ///
    /// `you` is the nick the room actually assigned, which is not necessarily
    /// the one asked for: the room uniquifies collisions (`bob`, `bob#2`). A
    /// client that echoes its *requested* nick in its own UI would disagree
    /// with everyone else about who it is.
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
}

impl ClientMsg {
    /// Reject what the room would have to reject anyway, at the edge.
    ///
    /// # Errors
    /// The nick or text is empty, or longer than the cap.
    pub fn validate(&self) -> Result<(), ProtoError> {
        match self {
            Self::Join { nick } => check_len("nick", nick, MAX_NICK_CHARS),
            Self::Say { text } => check_len("message", text, MAX_TEXT_CHARS),
        }
    }
}

fn check_len(what: &'static str, value: &str, max_chars: usize) -> Result<(), ProtoError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ProtoError::Empty { what });
    }
    // `chars`, not `len`: a cap in bytes would reject a shorter message in a
    // non-Latin script than in English, which is a bug rather than a policy.
    let chars = trimmed.chars().count();
    if chars > max_chars {
        return Err(ProtoError::TooLong {
            what,
            chars,
            max: max_chars,
        });
    }
    Ok(())
}
