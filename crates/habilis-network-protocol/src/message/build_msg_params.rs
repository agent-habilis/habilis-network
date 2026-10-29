//! The input parameters of a test message.

use crate::mesh::MeshId;
use crate::nickname_error::Nickname;

use super::{AppTag, ChainCtx, MessageBody};

/// The inputs of a test message: the mesh, the author, the body, the chain and the app tag.
///
/// # Examples
///
/// The parameters name the tag, mesh, author, body, and chain of one message to build.
///
/// ```
/// use habilis_network_protocol::identity::Identity;
/// use habilis_network_protocol::message::{AppTag, BuildMsgParams, ChainCtx, MessageBody, build_msg_bytes};
/// use habilis_network_protocol::mesh::MeshId;
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
/// assert!(verified.signer.is_some());
/// ```
#[cfg(any(test, feature = "test-fixtures"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BuildMsgParams<'mesh> {
    /// The mesh of the message.
    pub mesh: &'mesh MeshId,
    /// The member that signs the message.
    pub author: &'mesh Nickname,
    /// The body to sign.
    pub body: MessageBody,
    /// Where the message sits in its author's chain.
    pub chain: ChainCtx,
    /// The app tag to stamp. A parameter, not a constant: this fixture is used
    /// across crates, and hardcoding one consumer's tag made it build a frame
    /// that consumer would then fail to recognise.
    pub tag: AppTag,
}

#[cfg(any(test, feature = "test-fixtures"))]
impl<'mesh> BuildMsgParams<'mesh> {
    /// The tag, the mesh, the author, the body and the chain of one test message. The five types
    /// differ, so no two arguments can be swapped.
    #[must_use]
    pub fn new(
        tag: AppTag,
        mesh: &'mesh MeshId,
        author: &'mesh Nickname,
        body: MessageBody,
        chain: ChainCtx,
    ) -> Self {
        Self {
            mesh,
            author,
            body,
            chain,
            tag,
        }
    }
}
