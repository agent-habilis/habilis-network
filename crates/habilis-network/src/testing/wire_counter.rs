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
    /// Anything else: the digest of the message log, probes and unknown kinds.
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
            | MessageKind::MetaDigest => Self::Document,
            MessageKind::Digest | MessageKind::Ping | MessageKind::Pong { .. } | _ => Self::Other,
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

#[cfg(test)]
mod tests {
    use super::{FrameClass, WireCounter};
    use crate::protocol::{
        AppFrameParams, AppTag, Identity, MeshId, Message, MessageBody, MessageKind, UnixSecs,
    };
    use crate::testing;

    /// The wire bytes of a signed frame.
    fn wire(message: Message, by: &Identity) -> Vec<u8> {
        let frame = message.sign(by).serialize().expect("a frame serializes");
        frame.into_bytes().to_vec()
    }

    /// The counter adds the bytes of each class from the length of each frame. The expected
    /// numbers come from the lengths of the encoded frames, not from the counter.
    #[test]
    fn the_counter_adds_the_encoded_length_of_each_class() {
        let mesh = MeshId::from("test");
        let us = testing::nick("swift-cedar");
        let by = Identity::generate();
        let mut alive = Message::new_alive(&mesh, &us);
        alive.timestamp = UnixSecs::now();
        let alive = wire(alive, &by);
        let data = |len: usize| {
            let tag = AppTag::try_new("app_msg").expect("a valid app tag");
            let body = MessageBody::from("x".repeat(len).as_str());
            let mut message =
                Message::new_app(&mesh, &us, AppFrameParams::new(tag, None, None, body));
            message.timestamp = UnixSecs::now();
            wire(message, &by)
        };
        let (small, large) = (data(100), data(400));
        let junk = vec![0u8; 7];
        let frames: Vec<Vec<u8>> = vec![alive.clone(), small.clone(), large.clone(), junk.clone()];

        let counter = WireCounter::of(&frames);

        let data_bytes = small.len() + large.len();
        let total = alive.len() + data_bytes + junk.len();
        assert_eq!(counter.bytes(FrameClass::Data), data_bytes, "data bytes");
        assert_eq!(counter.bytes(FrameClass::Alive), alive.len(), "alive bytes");
        assert_eq!(
            counter.bytes(FrameClass::Other),
            junk.len(),
            "a frame that does not parse counts as other"
        );
        assert_eq!(counter.total_bytes(), total, "total bytes");
        assert_eq!(
            counter.metadata_percent(),
            (total - data_bytes) * 100 / total,
            "the metadata share"
        );
    }

    /// The anti-entropy digest of the chat log is plumbing, not a change of a shared document.
    #[test]
    fn a_message_log_digest_is_not_document_traffic() {
        assert_eq!(
            FrameClass::of(&MessageKind::Digest),
            FrameClass::Other,
            "a message log digest counted as document traffic"
        );
        for kind in [
            MessageKind::State,
            MessageKind::Meta,
            MessageKind::StateDigest,
            MessageKind::MetaDigest,
        ] {
            assert_eq!(FrameClass::of(&kind), FrameClass::Document, "{kind:?}");
        }
    }
}
