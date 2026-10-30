/// What a chat message, frame or ticket can get wrong. The chat binaries show it to the user.
#[derive(Debug)]
pub enum ProtoError {
    /// A nick or a message is empty once trimmed.
    Empty { what: &'static str },
    /// A nick or a message is longer than its cap, in characters.
    TooLong {
        what: &'static str,
        chars: usize,
        max: usize,
    },
    /// A frame body is larger than the cap.
    FrameTooLarge { bytes: usize, max: usize },
    /// A frame body does not serialize, or does not parse as the message it should be.
    Json(serde_json::Error),
    /// A ticket is not Base58Check, is truncated, or holds an id or a relay URL that does not parse.
    Ticket(&'static str),
    /// A ticket carries another version of the payload.
    TicketVersion { found: u8, expected: u8 },
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty { what } => write!(formatter, "{what} is empty"),
            Self::TooLong { what, chars, max } => {
                write!(formatter, "{what} is {chars} chars, max is {max}")
            }
            Self::FrameTooLarge { bytes, max } => {
                write!(formatter, "frame is {bytes} bytes, max is {max}")
            }
            Self::Json(error) => write!(formatter, "frame body: {error}"),
            Self::Ticket(reason) => write!(formatter, "ticket {reason}"),
            Self::TicketVersion { found, expected } => {
                write!(
                    formatter,
                    "ticket is version {found}, this build speaks {expected}"
                )
            }
        }
    }
}

impl std::error::Error for ProtoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Empty { .. }
            | Self::TooLong { .. }
            | Self::FrameTooLarge { .. }
            | Self::Ticket(_)
            | Self::TicketVersion { .. } => None,
        }
    }
}
