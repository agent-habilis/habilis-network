//! Multipart bodies: a logical message whose body exceeds the single-message
//! wire cap ([`MAX_MESSAGE_SIZE`](habilis_network_util::consts::MAX_MESSAGE_SIZE)) is
//! split by the sender into several ordinary signed messages, each carrying a
//! [`Shard`] header. The receiver reassembles them; the split is invisible to
//! agents on both ends. Each shard is a real message (own id/seq/signature);
//! shards of a small group (`total <=`
//! [`LOGGED_SHARD_GROUP_MAX_TOTAL`](habilis_network_util::consts::LOGGED_SHARD_GROUP_MAX_TOTAL))
//! also live in the message log, so anti-entropy heals them exactly as it
//! heals a missing message; a bigger group skips the log on both ends (one
//! huge body must not evict the mesh's anti-entropy history) and heals via
//! **shard repair** — the sender caches its outbound frames
//! (`reassembly::ShardCache`) and a stalled receiver asks for the
//! missing indexes over the `shard/repair` gossip RPC.

use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use uuid::Uuid;

use habilis_network_util::consts::MAX_SHARD_TOTAL;

use habilis_network_util::consts;
use serde::de::Error;
/// Whether a frame belongs in the message log as far as sharding is
/// concerned: unsharded frames and shards of a small group do; a big group's
/// shards stay out on **both** ends. The gate must be two-sided — a sender
/// that logs what receivers refuse to retain makes every anti-entropy digest
/// advertise those shards as missing, and the sender re-floods them every
/// round while the resend budget starves real gaps.
///
/// # Examples
///
/// A small message fits in the log. The shard module is private, so this is not compiled.
///
/// ```ignore
/// use habilis_network_protocol::identity::Identity;
/// use habilis_network_protocol::messages::{AppTag, BuildMsgParams, ChainCtx, MessageBody, build_msg_bytes};
/// use habilis_network_protocol::meshes::MeshId;
/// use habilis_network_protocol::Nickname;
///
/// use habilis_network_protocol::{Mesh, MeshConfig, MeshName, Seed};
///
/// let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
/// let mesh = Mesh::try_new(Seed::new([4u8; 32]), MeshName::try_new("chat").expect("a name"), config)
///     .expect("a mesh");
///
/// let id = MeshId::try_new(&mesh.to_string()).expect("a valid id");
/// let identity = Identity::generate();
/// let author = Nickname::try_new("alice").expect("a nickname");
/// let tag = AppTag::try_new("chat").expect("a tag");
/// let body = MessageBody::try_new("hello").expect("a body");
/// let params = BuildMsgParams::new(tag, &id, &author, body, ChainCtx::genesis());
/// let (_frame, verified) = build_msg_bytes(params, &identity).expect("a message builds");
///
/// assert!(shard_fits_log(&verified));
/// ```
#[must_use]
pub fn shard_fits_log(message: &super::Message) -> bool {
    message
        .shard
        .as_ref()
        .is_none_or(|shard| shard.total <= consts::LOGGED_SHARD_GROUP_MAX_TOTAL)
}

/// The correlation id shared by every shard of one logical body — a UUID v4
/// string form, minted once by the sender when it splits a body. Like
/// task id, deserialization is **validating**, so a
/// non-UUID group is rejected at `Message::parse`.
///
/// # Examples
///
/// A shard group is named by a UUID that reads back as the same text. The shard module is private, so this is not compiled.
///
/// ```ignore
/// let text = "6c0d4f2e-2b1a-4c3d-9e8f-7a6b5c4d3e2f";
/// let group = ShardGroup::parse_uuid(text).expect("a valid group");
/// assert_eq!(group.as_str(), text);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, ::serde::Serialize)]
#[serde(transparent)]
pub struct ShardGroup(String);

impl ShardGroup {
    /// The wrapped string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ShardGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ShardGroup {
    fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
    where
        Decoder: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Uuid::parse_str(&raw).map_err(|_| Error::custom("invalid shard group"))?;
        Ok(Self(raw))
    }
}

impl ShardGroup {
    /// Adopt an existing UUID string as the group id — the chat path names a
    /// split body's group by its payload's own logical id, so the reassembled
    /// logical id *is* the payload's own id. `None` for a non-UUID.
    #[must_use]
    pub fn parse_uuid(raw: &str) -> Option<Self> {
        Uuid::parse_str(raw).ok().map(|_| Self(raw.to_string()))
    }
}

/// The per-message header on one shard of a split body: its correlation
/// [`group`](Shard::group), 0-based index, and the total shard count. Present
/// only on the messages of a multipart body; ordinary messages carry no
/// `shard`. Deserialization is **validating** — `total` must be `2..=`
/// [`MAX_SHARD_TOTAL`] and `idx < total` — an absurd-header tripwire, not a
/// memory guard: the reassembly store is byte-budgeted and never allocates by
/// `total`.
///
/// # Examples
///
/// A shard holds its position and the total count of its group. The shard module is private, so this is not compiled.
///
/// ```ignore
/// let group = ShardGroup::parse_uuid("6c0d4f2e-2b1a-4c3d-9e8f-7a6b5c4d3e2f").expect("a valid group");
/// let shard = Shard::new(group, 3).index(1);
/// assert_eq!(shard.index, 1);
/// assert_eq!(shard.total, 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Shard {
    /// The group that the shard belongs to.
    pub group: ShardGroup,
    /// The position of the shard in its group.
    #[serde(rename = "idx")]
    pub index: u32,
    /// How many shards the group has.
    pub total: u32,
}

impl Shard {
    /// The header of the first shard (index 0) of a group of `total`. Set the position with
    /// [`Self::index`]. It checks nothing: the receiver's `Deserialize` refuses a `total`
    /// outside `2..=MAX_SHARD_TOTAL` and an index past it.
    #[must_use]
    pub fn new(group: ShardGroup, total: u32) -> Self {
        Self {
            group,
            index: 0,
            total,
        }
    }

    /// Set the position of the shard in its group.
    #[must_use]
    pub fn index(mut self, index: u32) -> Self {
        self.index = index;
        self
    }
}

impl<'de> Deserialize<'de> for Shard {
    fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
    where
        Decoder: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            group: ShardGroup,
            #[serde(rename = "idx")]
            index: u32,
            total: u32,
        }
        let raw = Raw::deserialize(deserializer)?;
        // A single message never carries `shard` (the sender only splits when a
        // body won't fit), so the smallest real `total` is 2; the upper bound
        // rejects a header no budget-respecting sender can produce.
        if raw.total < 2 || raw.total > MAX_SHARD_TOTAL {
            return Err(Error::custom("shard total out of range"));
        }
        if raw.index >= raw.total {
            return Err(Error::custom("shard idx out of range"));
        }
        Ok(Shard {
            group: raw.group,
            index: raw.index,
            total: raw.total,
        })
    }
}

#[cfg(test)]
mod shard_tests {
    use super::{Shard, ShardGroup};

    use habilis_network_util::consts;
    const GROUP: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn group_deserialize_rejects_non_uuid() {
        let _guard = ::habilis_network_test_tracing::init();
        let not_uuid: Result<ShardGroup, _> = serde_json::from_str("\"not-a-uuid\"");
        assert!(
            not_uuid.is_err(),
            "a non-uuid shard group is refused on deserialize"
        );
        assert!(
            ShardGroup::parse_uuid("not-a-uuid").is_none(),
            "a non-uuid shard group is refused by parse_uuid"
        );
    }

    #[test]
    fn shard_rejects_out_of_range_total_and_idx() {
        let _guard = ::habilis_network_test_tracing::init();
        let group = ShardGroup::parse_uuid(GROUP).expect("valid group");
        let group = group.as_str();
        // total < 2 (a single shard is never multipart).
        let single: Result<Shard, _> =
            serde_json::from_str(&format!(r#"{{"group":"{group}","idx":0,"total":1}}"#));
        assert!(
            single.is_err(),
            "a shard with an out-of-range total is refused"
        );
        // A large-but-sane total is fine (the store is byte-budgeted)...
        let large: Result<Shard, _> =
            serde_json::from_str(&format!(r#"{{"group":"{group}","idx":0,"total":9999}}"#));
        assert!(
            large.is_ok(),
            "a shard with an out-of-range index is refused"
        );
        // ...but an absurd header past the tripwire is rejected.
        let absurd: Result<Shard, _> = serde_json::from_str(&format!(
            r#"{{"group":"{group}","idx":0,"total":{}}}"#,
            u64::from(super::MAX_SHARD_TOTAL) + 1
        ));
        assert!(absurd.is_err(), "a shard with a zero total is refused");
        // idx must be inside total.
        let index_at_total: Result<Shard, _> =
            serde_json::from_str(&format!(r#"{{"group":"{group}","idx":3,"total":3}}"#));
        assert!(
            index_at_total.is_err(),
            "a shard whose index is not below its total is refused"
        );
    }

    #[test]
    fn shard_total_tripwire_clears_the_reassembly_budget() {
        let _guard = ::habilis_network_test_tracing::init();
        // The tripwire must never reject a body the byte budgets allow: even
        // at a pessimistic ~2 KiB of body per shard, a group at the byte
        // ceiling needs fewer shards than the header bound admits.
        let worst_case_shards = consts::REASSEMBLY_GROUP_MAX_BYTES.div_ceil(2048);
        assert!(
            worst_case_shards <= super::MAX_SHARD_TOTAL as usize,
            "MAX_SHARD_TOTAL ({}) must clear REASSEMBLY_GROUP_MAX_BYTES / 2KiB ({worst_case_shards})",
            super::MAX_SHARD_TOTAL
        );
    }

    #[test]
    fn shard_accepts_valid_header() {
        let _guard = ::habilis_network_test_tracing::init();
        let group = ShardGroup::parse_uuid(GROUP).expect("valid group");
        let group = group.as_str();
        let shard: Shard =
            serde_json::from_str(&format!(r#"{{"group":"{group}","idx":1,"total":3}}"#))
                .expect("the JSON literal in this test is a well-formed shard header");
        assert_eq!(shard.index, 1, "a valid shard keeps its index");
        assert_eq!(shard.total, 3, "a valid shard keeps its total");
    }
}
