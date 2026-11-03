//! Counts the frames and the bytes that a node puts on the wire, by class, so a test can state the
//! share of metadata and the number of redundant frames as numbers.

use std::collections::BTreeMap;
use std::fmt;

use crate::protocol::{Message, MessageKind, PresenceSubtype};

/// What a frame is for. Only [`FrameClass::Data`] is payload; every other class is metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FrameClass {
    /// An application frame: the payload that the mesh exists to carry.
    Data,
    /// A `joined` presence.
    Joined,
    /// A peer info: the address of a node.
    Announce,
    /// An `alive` keepalive.
    Alive,
    /// A `left` presence or a link-state vector.
    Membership,
    /// A change or a digest of the shared state or meta document.
    Document,
    /// Anything else: probes and unknown kinds.
    Other,
}

impl FrameClass {
    pub(crate) fn of(kind: &MessageKind) -> Self {
        match kind {
            MessageKind::App { .. } => Self::Data,
            MessageKind::Presence {
                subtype: PresenceSubtype::Joined,
            } => Self::Joined,
            MessageKind::Presence {
                subtype: PresenceSubtype::Alive,
            } => Self::Alive,
            MessageKind::PeerInfo => Self::Announce,
            MessageKind::Presence {
                subtype: PresenceSubtype::Left,
            }
            | MessageKind::LinkState => Self::Membership,
            MessageKind::State
            | MessageKind::Meta
            | MessageKind::StateDigest
            | MessageKind::MetaDigest
            | MessageKind::Digest => Self::Document,
            MessageKind::Ping | MessageKind::Pong { .. } | _ => Self::Other,
        }
    }
}

/// The frames and bytes of a run, by class.
#[derive(Debug, Default, Clone)]
pub(crate) struct WireCounter {
    classes: BTreeMap<FrameClass, (usize, usize)>,
}

impl WireCounter {
    /// Count the wire bytes of `frames`. A frame that does not parse counts as `Other`.
    pub(crate) fn of(frames: &[Vec<u8>]) -> Self {
        let mut counter = Self::default();
        for bytes in frames {
            let class = Message::parse_wire(bytes).map_or(FrameClass::Other, |(message, _)| {
                FrameClass::of(&message.kind)
            });
            let entry = counter.classes.entry(class).or_default();
            entry.0 += 1;
            entry.1 += bytes.len();
        }
        counter
    }

    pub(crate) fn frames(&self, class: FrameClass) -> usize {
        self.classes.get(&class).map_or(0, |entry| entry.0)
    }

    pub(crate) fn bytes(&self, class: FrameClass) -> usize {
        self.classes.get(&class).map_or(0, |entry| entry.1)
    }

    pub(crate) fn total_bytes(&self) -> usize {
        self.classes.values().map(|entry| entry.1).sum()
    }

    /// The bytes of every class but data, as a percentage of all bytes (0 when nothing was sent).
    pub(crate) fn metadata_percent(&self) -> usize {
        let total = self.total_bytes();
        if total == 0 {
            return 0;
        }
        (total - self.bytes(FrameClass::Data)) * 100 / total
    }
}

impl fmt::Display for WireCounter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (class, (frames, bytes)) in &self.classes {
            write!(formatter, "{class:?}: {frames} frames {bytes} bytes; ")?;
        }
        write!(
            formatter,
            "metadata {}% of {} bytes",
            self.metadata_percent(),
            self.total_bytes()
        )
    }
}
