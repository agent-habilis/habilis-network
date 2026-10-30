//! The shared-state channel of a message: state or meta.

use super::MessageKind;

/// Which shared-state channel an event/digest belongs to. The two channels share
/// all machinery; this selects the wire kind, the log, and the surfaced name.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Channel {
    /// The shared state of the mesh.
    State,
    /// The metadata of the members.
    Meta,
}

impl Channel {
    pub(crate) fn event_kind(self) -> MessageKind {
        match self {
            Channel::State => MessageKind::State,
            Channel::Meta => MessageKind::Meta,
        }
    }

    pub(crate) fn digest_kind(self) -> MessageKind {
        match self {
            Channel::State => MessageKind::StateDigest,
            Channel::Meta => MessageKind::MetaDigest,
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
