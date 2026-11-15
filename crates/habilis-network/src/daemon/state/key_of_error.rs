//! Why a nickname names no single key.

use std::error::Error;
use std::fmt;

/// Why [`EventLoopState::key_of`](super::EventLoopState::key_of) names no key.
///
/// # Examples
///
/// The error tells a caller why it cannot send to a nickname: no live key uses it, or two or
/// more do. The doc test compiles the match but does not run it.
///
/// ```no_run
/// use habilis_network::embed::{EventLoopState, KeyOfError};
/// use habilis_network::protocol::Nickname;
///
/// # fn demo(state: &EventLoopState, nickname: &Nickname) {
/// match state.key_of(nickname) {
///     Ok(key) => println!("send to {key}"),
///     Err(KeyOfError::Unknown) => println!("no live key uses {nickname}"),
///     Err(KeyOfError::Ambiguous) => println!("two or more live keys use {nickname}"),
///     Err(_) => println!("another reason"),
/// }
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum KeyOfError {
    /// No live key uses the nickname.
    Unknown,
    /// Two or more live keys use the nickname. A nickname is a label, so the engine never picks
    /// one of them.
    Ambiguous,
}

impl fmt::Display for KeyOfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("no live peer uses this nickname"),
            Self::Ambiguous => f.write_str("two or more live peers use this nickname"),
        }
    }
}

impl Error for KeyOfError {}
