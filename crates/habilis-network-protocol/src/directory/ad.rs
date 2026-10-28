//! One directory entry: the mesh that a publisher advertises.

use serde::{Deserialize, Serialize};

use crate::{MeshId, MessageBody};

/// A directory advertisement: the advertised mesh's id plus its
/// live peer count. The id already encodes the mesh name and
/// network mode, so a discoverer decodes those locally — nothing else need
/// be on the wire. Serialized as a JSON object (room for future fields;
/// discoverers ignore unknown keys via serde's default behaviour and
/// ignore unparseable bodies entirely).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Ad {
    /// The mesh that this ad advertises.
    pub id: MeshId,
    /// How many members the mesh has, this advertiser included.
    pub peers: usize,
}

impl Ad {
    /// Render this ad as a [`MessageBody`] for broadcast on the directory.
    /// Infallible: the JSON of an `{id, peers}` object contains no
    /// control characters.
    ///
    /// # Panics
    /// If `Ad` fails to serialize, or its JSON somehow carries a control
    /// character. Neither is reachable for an `{id, peers}` object.
    #[must_use]
    pub fn to_body(&self) -> MessageBody {
        let json = serde_json::to_string(self).expect("Ad always serializes to JSON");
        MessageBody::try_new(json).expect("Ad JSON contains no control characters")
    }

    /// Parse a directory message body as an ad. Returns `None` for any
    /// non-ad body (presence, digests, junk) so the collector can feed
    /// every directory message through without pre-filtering.
    #[must_use]
    pub fn parse(body: &str) -> Option<Self> {
        serde_json::from_str(body).ok()
    }
}
