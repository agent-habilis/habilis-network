//! One directory entry: the mesh that a publisher advertises.

use serde::{Deserialize, Serialize};

use crate::{MeshId, MessageBody};

/// A directory advertisement: the advertised mesh's id plus its
/// live peer count. The id already encodes the mesh name and
/// network mode, so a discoverer decodes those locally — nothing else need
/// be on the wire. Serialized as a JSON object (room for future fields;
/// discoverers ignore unknown keys via serde's default behaviour and
/// ignore unparseable bodies entirely).
///
/// # Examples
///
/// An ad carries a mesh id and its member count, and the body reads back to the same ad.
///
/// ```
/// use habilis_network_protocol::directory::Ad;
///
/// use habilis_network_protocol::{Mesh, MeshConfig, MeshName, Seed};
///
/// let config = MeshConfig::resolve(&[], None, &[]).expect("a loopback mesh");
/// let mesh = Mesh::try_new(Seed::new([4u8; 32]), MeshName::try_new("chat").expect("a name"), config)
///     .expect("a mesh");
///
/// let text = mesh.to_string();
/// let ad = Ad::parse(&format!(r#"{{"id":"{text}","peers":3}}"#)).expect("an ad reads");
/// assert_eq!(ad.peers, 3);
/// let read = Ad::parse(ad.to_body().as_str()).expect("the body reads back");
/// assert_eq!(read.peers, 3);
/// ```
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
        MessageBody::try_new(&json).expect("Ad JSON contains no control characters")
    }

    /// Parse a directory message body as an ad. Returns `None` for any
    /// non-ad body (presence, digests, junk) so the collector can feed
    /// every directory message through without pre-filtering.
    #[must_use]
    pub fn parse(body: &str) -> Option<Self> {
        serde_json::from_str(body).ok()
    }
}
