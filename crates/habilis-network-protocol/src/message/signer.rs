//! The signer of a message: its key and its signature.

use iroh_base::Signature;

use crate::AuthorKey;

/// The key that signed a message and its signature. The two are one value, so a message cannot
/// carry a key with no signature, or a signature with no key.
///
/// # Examples
///
/// A signer holds the key and the signature of the author of a message.
///
/// ```ignore
/// use habilis_network_protocol::identity::Identity;
/// use habilis_network_protocol::message::{AppTag, BuildMsgParams, ChainCtx, MessageBody, build_msg_bytes};
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
/// let signer = verified.signer.as_ref().expect("a built message is signed");
/// assert_eq!(signer.key().as_bytes(), identity.author_key().as_bytes());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signer {
    pub(super) key: AuthorKey,
    pub(super) signature: Signature,
}

impl Signer {
    /// Pair a key with the signature it made. Nothing checks it here: [`Message::verify_signature_with`]
    /// does.
    #[must_use]
    pub(crate) fn new(key: AuthorKey, signature: Signature) -> Self {
        Self { key, signature }
    }

    /// The key that signed.
    #[must_use]
    pub fn key(&self) -> AuthorKey {
        self.key
    }

    /// The detached signature.
    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}
