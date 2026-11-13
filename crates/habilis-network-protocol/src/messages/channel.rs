//! The shared-state channel of a message: state or meta.

use serde::{Deserialize, Serialize};

use super::MessageKind;

/// Which shared-state channel a slice event belongs to. The two channels share
/// all machinery; this selects the wire kind and the surfaced name.
///
/// # Examples
///
/// The state and the meta channel have different labels.
///
/// ```
/// use habilis_network_protocol::messages::Channel;
///
/// assert_ne!(Channel::State.label(), Channel::Meta.label());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Channel {
    /// The shared state of the mesh.
    State,
    /// The metadata of the members.
    Meta,
}

impl Channel {
    /// The kind of the frame that carries a change on this channel.
    ///
    /// # Examples
    ///
    /// ```
    /// use habilis_network_protocol::{Channel, MessageKind};
    ///
    /// assert_eq!(Channel::Meta.event_kind(), MessageKind::Meta);
    /// ```
    #[must_use]
    pub fn event_kind(self) -> MessageKind {
        match self {
            Channel::State => MessageKind::State,
            Channel::Meta => MessageKind::Meta,
        }
    }

    /// The event name surfaced on the `--output json` stream (`state` / `meta`).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Channel::State => "state",
            Channel::Meta => "meta",
        }
    }
}
