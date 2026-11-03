//! Wire bytes by kind of frame, for the `mesh census` line: what a node receives, split into first
//! sightings and repeats, and what it hands to the transport. The body bytes of each frame are
//! counted beside the wire bytes, so the difference is the cost of the envelope: the JSON keys,
//! the ids, the hex of the key and of the signature.
//!
//! The counts read the bytes of a frame, not its parsed form: the send side holds bytes only, and
//! one reader then serves both sides. It relies on the field order of the wire form that
//! `habilis-network-protocol` pins with golden tests; a frame it cannot read counts as `other`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{mem, str};

use memchr::memmem;

/// The most distinct app tags kept per interval and direction. A peer can name any tag, so the
/// rest are added to [`OTHER_TAGS`].
const MAX_TAGS: usize = 32;
const OTHER_TAGS: &str = "~other";
/// The tags that the census line names, largest first.
const TOP_TAGS: usize = 6;
/// How far from the start of a frame the kind, the tag and the start of the body lie.
const HEAD_SCAN: usize = 600;
/// How far from the end of a frame the end of the body and the shard header lie.
const TAIL_SCAN: usize = 2048;

/// The kinds of frame that the census tells apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameClass {
    /// An application payload: chat, tasks, status, artifacts. The tag tells them apart.
    App,
    Presence,
    PeerInfo,
    /// The anti-entropy digest of the chat log.
    Digest,
    StateDigest,
    MetaDigest,
    /// A change of the `state` channel.
    State,
    /// A change of the `meta` channel.
    Meta,
    LinkState,
    PingPong,
    /// One slice of a body that is too large for one frame.
    Shard,
    /// A frame that this reader cannot place.
    Other,
}

pub(crate) const CLASS_COUNT: usize = 12;

impl FrameClass {
    const ALL: [Self; CLASS_COUNT] = [
        Self::App,
        Self::Presence,
        Self::PeerInfo,
        Self::Digest,
        Self::StateDigest,
        Self::MetaDigest,
        Self::State,
        Self::Meta,
        Self::LinkState,
        Self::PingPong,
        Self::Shard,
        Self::Other,
    ];

    /// The name of the class in the census line.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Presence => "presence",
            Self::PeerInfo => "peerinfo",
            Self::Digest => "digest",
            Self::StateDigest => "statedigest",
            Self::MetaDigest => "metadigest",
            Self::State => "state",
            Self::Meta => "meta",
            Self::LinkState => "linkstate",
            Self::PingPong => "pingpong",
            Self::Shard => "shard",
            Self::Other => "other",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }

    /// The class of the `type` of a frame, as the wire spells it.
    fn of_wire_type(wire_type: &[u8]) -> Self {
        match wire_type {
            b"app" => Self::App,
            b"presence" => Self::Presence,
            b"peerinfo" => Self::PeerInfo,
            b"digest" => Self::Digest,
            b"statedigest" => Self::StateDigest,
            b"metadigest" => Self::MetaDigest,
            b"state" => Self::State,
            b"meta" => Self::Meta,
            b"linkstate" => Self::LinkState,
            b"ping" | b"pong" => Self::PingPong,
            _ => Self::Other,
        }
    }
}

/// What the census reads from the bytes of one frame.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameShape<'frame> {
    pub(crate) class: FrameClass,
    /// The bytes on the wire: the frame with its resend trailer, if it has one.
    pub(crate) wire: usize,
    /// The bytes of the body, as written in the JSON. Zero when the frame has no signature block
    /// to end it.
    pub(crate) body: usize,
    /// The tag of an app frame.
    pub(crate) tag: Option<&'frame str>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memmem::find(haystack, needle)
}

/// The bytes after `key` up to the next quote, and where they start.
fn value_after<'frame>(
    frame: &'frame [u8],
    key: &[u8],
    from: usize,
) -> Option<(&'frame [u8], usize)> {
    let head = frame.get(from..frame.len().min(from + HEAD_SCAN))?;
    let start = from + find(head, key)? + key.len();
    let rest = frame.get(start..)?;
    let end = rest.iter().position(|&byte| byte == b'"')?;
    Some((rest.get(..end)?, start))
}

impl<'frame> FrameShape<'frame> {
    /// Read the shape of `frame`. A frame that does not look like ours is `other`, with its wire
    /// bytes and no body.
    pub(crate) fn of(frame: &'frame [u8]) -> Self {
        let other = Self {
            class: FrameClass::Other,
            wire: frame.len(),
            body: 0,
            tag: None,
        };
        let Some((wire_type, type_at)) = value_after(frame, b"\"type\":\"", 0) else {
            return other;
        };
        let mut class = FrameClass::of_wire_type(wire_type);
        let tag = if class == FrameClass::App {
            value_after(frame, b"\"tag\":\"", type_at).and_then(|(tag, _)| str::from_utf8(tag).ok())
        } else {
            None
        };
        let tail_from = frame.len().saturating_sub(TAIL_SCAN).max(type_at);
        let tail = frame.get(tail_from..).unwrap_or_default();
        let signed_at = find(tail, b"\",\"pubkey\":\"").map(|at| tail_from + at);
        let body_start = value_after(frame, b"\"body\":\"", type_at).map(|(_, start)| start);
        let body = match (body_start, signed_at) {
            (Some(start), Some(end)) if end >= start => end - start,
            _ => 0,
        };
        if let Some(at) = signed_at
            && frame
                .get(at..)
                .is_some_and(|rest| find(rest, b",\"shard\":{").is_some())
        {
            class = FrameClass::Shard;
        }
        Self {
            class,
            wire: frame.len(),
            body,
            tag,
        }
    }
}

/// Bytes by app tag. Bounded, because a peer can name any tag.
#[derive(Clone, Default, Debug)]
pub(crate) struct TagBytes(HashMap<String, u64>);

impl TagBytes {
    fn add(&mut self, tag: &str, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        if let Some(total) = self.0.get_mut(tag) {
            *total += bytes;
            return;
        }
        let key = if self.0.len() >= MAX_TAGS {
            OTHER_TAGS
        } else {
            tag
        };
        *self.0.entry(key.to_owned()).or_default() += bytes;
    }

    /// The `TOP_TAGS` tags with the most bytes as `tag:bytes` joined by `,`, or `-`. Ties go by
    /// tag, so the line is stable.
    pub(crate) fn top(&self) -> String {
        let mut rows: Vec<(&String, u64)> =
            self.0.iter().map(|(tag, bytes)| (tag, *bytes)).collect();
        rows.sort_unstable_by(|(left_tag, left), (right_tag, right)| {
            right.cmp(left).then_with(|| left_tag.cmp(right_tag))
        });
        let named: Vec<String> = rows
            .iter()
            .take(TOP_TAGS)
            .map(|(tag, bytes)| format!("{tag}:{bytes}"))
            .collect();
        if named.is_empty() {
            "-".to_owned()
        } else {
            named.join(",")
        }
    }
}

/// `class:bytes` for each class with bytes, joined by `,`, or `-`.
pub(crate) fn by_class(bytes: &[u64; CLASS_COUNT]) -> String {
    let held = FrameClass::ALL
        .iter()
        .filter(|class| bytes[class.index()] > 0);
    let named: Vec<String> = held
        .map(|class| format!("{}:{}", class.name(), bytes[class.index()]))
        .collect();
    if named.is_empty() {
        "-".to_owned()
    } else {
        named.join(",")
    }
}

fn add_bytes(slot: &mut u64, bytes: usize) {
    *slot += u64::try_from(bytes).unwrap_or(u64::MAX);
}

/// The frames that the node received in one census interval.
#[derive(Clone, Default, Debug)]
pub(crate) struct WireIn {
    /// Wire bytes of the frames that were new to the node, by class.
    pub(crate) fresh: [u64; CLASS_COUNT],
    /// Wire bytes of the frames that the dedup dropped as repeats, by class.
    pub(crate) dup: [u64; CLASS_COUNT],
    /// Every frame that reached `ingest`, fresh, repeat or dropped by a later check.
    pub(crate) wire: u64,
    pub(crate) body: u64,
    pub(crate) frames: u64,
    /// Wire bytes of the app frames, fresh and repeat, by tag.
    pub(crate) tags: TagBytes,
    /// Wire bytes, by class, of frames that were new by id and whose content the node already held:
    /// a change that the document had applied. They are part of `fresh`, so a reader adds them to
    /// `dup` to get every byte of content that came again.
    pub(crate) cdup: [u64; CLASS_COUNT],
    /// The class and the wire bytes of the last frame that was new by id, until the next frame.
    last_fresh: Option<(FrameClass, usize)>,
}

impl WireIn {
    pub(crate) fn note_received(&mut self, shape: &FrameShape<'_>) {
        self.last_fresh = None;
        add_bytes(&mut self.wire, shape.wire);
        add_bytes(&mut self.body, shape.body);
        self.frames += 1;
    }

    pub(crate) fn note_fresh(&mut self, shape: &FrameShape<'_>) {
        self.last_fresh = Some((shape.class, shape.wire));
        add_bytes(&mut self.fresh[shape.class.index()], shape.wire);
        self.note_tag(shape);
    }

    pub(crate) fn note_dup(&mut self, shape: &FrameShape<'_>) {
        add_bytes(&mut self.dup[shape.class.index()], shape.wire);
        self.note_tag(shape);
    }

    /// The frame that was just counted as new carried content that the node already held.
    pub(crate) fn note_content_dup(&mut self) {
        if let Some((class, wire)) = self.last_fresh.take() {
            add_bytes(&mut self.cdup[class.index()], wire);
        }
    }

    fn note_tag(&mut self, shape: &FrameShape<'_>) {
        if let Some(tag) = shape.tag {
            self.tags.add(tag, shape.wire);
        }
    }
}

/// The frames that the node handed to the transport in one census interval. A broadcast counts
/// once, whatever the number of neighbors that gossip forwards it to.
#[derive(Clone, Default, Debug)]
pub(crate) struct WireOut {
    pub(crate) bytes: [u64; CLASS_COUNT],
    pub(crate) wire: u64,
    pub(crate) body: u64,
    pub(crate) frames: u64,
    pub(crate) tags: TagBytes,
}

impl WireOut {
    pub(crate) fn note(&mut self, frame: &[u8]) {
        let shape = FrameShape::of(frame);
        add_bytes(&mut self.bytes[shape.class.index()], shape.wire);
        add_bytes(&mut self.wire, shape.wire);
        add_bytes(&mut self.body, shape.body);
        self.frames += 1;
        if let Some(tag) = shape.tag {
            self.tags.add(tag, shape.wire);
        }
    }
}

/// The frames that the senders of one event loop handed to the transport. The send paths hold no
/// `&mut` state, so each loop hands a clone of this handle to its senders and reads the tally with
/// `take`. Two loops in one process do not share a tally.
#[derive(Clone, Default, Debug)]
// Shared: the loop and each of its senders hold a clone of one tally.
pub(crate) struct WireOutTally(Arc<Mutex<WireOut>>);

impl WireOutTally {
    /// Count a frame that went to the transport, on gossip or point to point.
    pub(crate) fn note(&self, frame: &[u8]) {
        if let Ok(mut out) = self.0.lock() {
            out.note(frame);
        }
    }

    /// Read the sent frames of the interval and start the next one.
    pub(super) fn take(&self) -> WireOut {
        self.0
            .lock()
            .map(|mut out| mem::take(&mut *out))
            .unwrap_or_default()
    }

    /// The bytes sent so far under `tag`, read without ending the interval.
    #[cfg(test)]
    pub(crate) fn tag_bytes(&self, tag: &str) -> u64 {
        let Ok(out) = self.0.lock() else {
            return 0;
        };
        out.tags.0.get(tag).copied().unwrap_or(0)
    }
}

/// A frame of the app kind with the given `tag`, as the serializer writes it.
#[cfg(test)]
pub(crate) fn app_frame_with_tag(tag: &str) -> Vec<u8> {
    format!(
        r#"{{"v":"12.0","id":"i","type":"app","tag":"{tag}","mesh":"m","author":"a","ts":1,"body":"b","pubkey":"ab","sig":"cd","ext":{{}}}}"#
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::{CLASS_COUNT, FrameClass, FrameShape, TagBytes, WireIn, WireOut, by_class};
    use crate::protocol::identity::Identity;
    use crate::protocol::messages::{AppFrameParams, AppTag};
    use crate::protocol::{Channel, MeshId, Message, MessageBody};
    use crate::testing;

    const APP: &[u8] = br#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"eeea2aca","seq":3,"ext":{}}"#;

    #[test]
    fn an_app_frame_has_its_tag_its_body_and_its_wire_size() {
        let shape = FrameShape::of(APP);
        assert_eq!(
            shape.class,
            FrameClass::App,
            "the golden frame is an app frame"
        );
        assert_eq!(
            shape.tag,
            Some("app_msg"),
            "the tag of the golden frame is read"
        );
        assert_eq!(
            shape.body,
            "hello, golden".len(),
            "the body of the golden frame is its text"
        );
        assert_eq!(shape.wire, APP.len(), "the wire size is the whole frame");
    }

    /// The reader and the serializer must agree, or the census reads every frame as `other`: the
    /// frames here are made by the real constructors and the real serializer.
    #[test]
    fn frames_from_the_real_serializer_are_read_by_kind_tag_and_body() {
        let mesh = MeshId::from("test");
        let author = testing::nick("alice");
        let tag = AppTag::try_new("app_msg").expect("a valid tag");
        let app = AppFrameParams::new(tag, None, None, "say \"hi\"".into());
        let frames: [(Message, FrameClass); 10] = [
            (Message::new_app(&mesh, &author, app), FrameClass::App),
            (Message::new_joined(&mesh, &author), FrameClass::Presence),
            (
                Message::new_peer_info(&mesh, &author, MessageBody::from("addr")),
                FrameClass::PeerInfo,
            ),
            (
                Message::new_digest(&mesh, &author, MessageBody::from("[]")),
                FrameClass::Digest,
            ),
            (
                Message::new_state_digest(&mesh, &author, MessageBody::from("{}")),
                FrameClass::StateDigest,
            ),
            (
                Message::new_channel_digest(&mesh, &author, MessageBody::from("{}"), Channel::Meta),
                FrameClass::MetaDigest,
            ),
            (
                Message::new_channel_event(
                    &mesh,
                    &author,
                    MessageBody::from("{\"k\":1}"),
                    Channel::State,
                ),
                FrameClass::State,
            ),
            (
                Message::new_channel_event(
                    &mesh,
                    &author,
                    MessageBody::from("{\"k\":1}"),
                    Channel::Meta,
                ),
                FrameClass::Meta,
            ),
            (
                Message::new_link_state(&mesh, &author, MessageBody::from("{}")),
                FrameClass::LinkState,
            ),
            (Message::new_ping(&mesh, &author), FrameClass::PingPong),
        ];
        let identity = Identity::generate();
        for (message, class) in frames {
            let written = message.body.as_str().to_owned();
            let wire = message
                .sign(&identity)
                .serialize()
                .expect("a signed message serializes");
            let shape = FrameShape::of(wire.as_bytes());
            let json_body = serde_json::to_string(&written).expect("a string encodes");
            assert_eq!(shape.class, class, "{written}");
            assert_eq!(
                shape.wire,
                wire.len(),
                "the wire size is the size of the frame that the serializer made"
            );
            assert_eq!(shape.body, json_body.len() - 2, "the body of {class:?}");
            if class == FrameClass::App {
                assert_eq!(shape.tag, Some("app_msg"), "an app frame carries its tag");
            }
        }
    }

    #[test]
    fn a_quoted_body_does_not_end_the_body_early() {
        let frame = br#"{"v":"12.0","id":"i","type":"state","mesh":"m","author":"a","ts":1,"body":"say \",\"pubkey\":\" now","pubkey":"ab","sig":"cd","ext":{}}"#;
        let shape = FrameShape::of(frame);
        assert_eq!(
            shape.class,
            FrameClass::State,
            "a body that holds quotes and key names is still a state frame"
        );
        assert_eq!(
            shape.body,
            r#"say \",\"pubkey\":\" now"#.len(),
            "the escaped body is read to its real end"
        );
    }

    #[test]
    fn the_wire_types_are_told_apart() {
        for (wire_type, class) in [
            ("presence", FrameClass::Presence),
            ("peerinfo", FrameClass::PeerInfo),
            ("digest", FrameClass::Digest),
            ("statedigest", FrameClass::StateDigest),
            ("metadigest", FrameClass::MetaDigest),
            ("meta", FrameClass::Meta),
            ("linkstate", FrameClass::LinkState),
            ("ping", FrameClass::PingPong),
            ("pong", FrameClass::PingPong),
            ("nonsense", FrameClass::Other),
        ] {
            let frame = format!(
                r#"{{"v":"12.0","id":"i","type":"{wire_type}","mesh":"m","author":"a","ts":1,"body":"b","pubkey":"ab","sig":"cd","ext":{{}}}}"#
            );
            assert_eq!(FrameShape::of(frame.as_bytes()).class, class, "{wire_type}");
        }
    }

    #[test]
    fn a_frame_with_a_shard_header_is_a_shard() {
        let frame = br#"{"v":"12.0","id":"i","type":"app","tag":"t","mesh":"m","author":"a","ts":1,"body":"b","pubkey":"ab","sig":"cd","shard":{"group":"g","idx":0,"total":2},"ext":{}}"#;
        assert_eq!(
            FrameShape::of(frame).class,
            FrameClass::Shard,
            "a shard header makes the frame a shard"
        );
    }

    #[test]
    fn bytes_that_are_no_frame_are_other_with_their_wire_size() {
        let junk: &[u8] = b"\xff not a frame";
        let shape = FrameShape::of(junk);
        assert_eq!(
            shape.class,
            FrameClass::Other,
            "bytes that are no frame are other"
        );
        assert_eq!(
            shape.wire,
            junk.len(),
            "the wire size of junk is its length"
        );
        assert_eq!(shape.body, 0, "junk has no body");
    }

    #[test]
    fn the_received_bytes_are_split_by_class_and_by_fresh_and_repeat() {
        let app = FrameShape::of(APP);
        let mut received = WireIn::default();
        for _ in 0..3 {
            received.note_received(&app);
        }
        received.note_fresh(&app);
        received.note_dup(&app);
        received.note_dup(&app);
        assert_eq!(received.frames, 3, "3 frames were received");
        assert_eq!(
            received.wire,
            3 * APP.len() as u64,
            "the wire bytes are 3 frames"
        );
        assert_eq!(
            received.body,
            3 * "hello, golden".len() as u64,
            "the body bytes are 3 bodies"
        );
        assert_eq!(
            by_class(&received.fresh),
            format!("app:{}", APP.len()),
            "the first sighting is counted once"
        );
        assert_eq!(
            by_class(&received.dup),
            format!("app:{}", 2 * APP.len()),
            "the 2 repeats are counted as repeats"
        );
        assert_eq!(
            received.tags.top(),
            format!("app_msg:{}", 3 * APP.len()),
            "the tag bytes cover the 3 frames"
        );
    }

    #[test]
    fn a_frame_new_by_id_can_be_counted_again_as_content_that_came_back() {
        let app = FrameShape::of(APP);
        let mut received = WireIn::default();
        received.note_received(&app);
        received.note_content_dup();
        assert_eq!(by_class(&received.cdup), "-", "nothing was fresh yet");
        received.note_received(&app);
        received.note_fresh(&app);
        received.note_content_dup();
        received.note_content_dup();
        assert_eq!(
            by_class(&received.cdup),
            format!("app:{}", APP.len()),
            "once per frame"
        );
        assert_eq!(
            by_class(&received.fresh),
            format!("app:{}", APP.len()),
            "the content that came back counts as fresh by content"
        );
    }

    #[test]
    fn the_sent_bytes_are_counted_by_class_and_tag() {
        let mut sent = WireOut::default();
        sent.note(APP);
        sent.note(b"junk");
        assert_eq!(sent.frames, 2, "2 frames were sent");
        assert_eq!(
            sent.wire,
            APP.len() as u64 + 4,
            "the wire bytes are the app frame and 4 bytes of junk"
        );
        assert_eq!(
            by_class(&sent.bytes),
            format!("app:{},other:4", APP.len()),
            "the bytes are split by class"
        );
    }

    #[test]
    fn a_tag_that_is_kept_still_counts_when_the_tags_are_full() {
        let mut tags = TagBytes::default();
        for index in 0..super::MAX_TAGS {
            tags.add(&format!("tag-{index}"), 1);
        }

        tags.add("tag-0", 10);
        tags.add("a-new-tag", 5);

        assert_eq!(tags.0["tag-0"], 11, "a kept tag adds up");
        assert_eq!(tags.0[super::OTHER_TAGS], 5, "a new tag goes to the rest");
        assert!(
            !tags.0.contains_key("a-new-tag"),
            "a tag past the cap is not kept"
        );
    }

    #[test]
    fn an_empty_tally_prints_a_dash_and_the_tags_stay_bounded() {
        assert_eq!(by_class(&[0; CLASS_COUNT]), "-", "no bytes, no text");
        assert_eq!(TagBytes::default().top(), "-", "no tags, no text");
        let mut tags = TagBytes::default();
        for index in 0..100 {
            tags.add(&format!("tag-{index}"), 1);
        }
        assert!(tags.0.len() <= super::MAX_TAGS + 1, "{} tags", tags.0.len());
        let total: u64 = tags.0.values().sum();
        assert_eq!(total, 100, "no byte is lost");
    }
}
