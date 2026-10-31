//! Builds the signed wire frame of an outbound message, for tests and fixtures.

use crate::identity::Identity;

use super::{AppFrameParams, BuildMsgParams, Message, MessageError, Verified, WireFrame};

/// Build the serialized wire bytes for an outbound user message
/// (open or directed reply), returning the bytes alongside the
/// canonical [`Message`] so callers can echo it without re-parsing.
/// The single message-construction point shared by the IPC `msg`
/// command, the library API send path, and interactive stdin.
///
/// # Errors
/// A [`MessageError`] from the message encoding: an oversized payload or a JSON failure.
/// Serialization fails, or the message exceeds `MAX_MESSAGE_SIZE`.
///
/// # Examples
///
/// A built message is signed by the identity that built it.
///
/// ```
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
/// let signer = verified.signer.as_ref().expect("a built message is signed");
/// assert_eq!(signer.key().as_bytes(), identity.author_key().as_bytes());
/// ```
#[cfg(any(test, feature = "test-fixtures"))]
pub fn build_msg_bytes(
    params: BuildMsgParams<'_>,
    identity: &Identity,
) -> Result<(WireFrame, Verified), MessageError> {
    let message = Message::new_app(
        params.mesh,
        params.author,
        AppFrameParams {
            tag: params.tag,
            to: None,
            corr: None,
            body: params.body,
        },
    )
    .chain(params.chain.seq, params.chain.previous)
    .parents(params.chain.parents)
    .sign(identity);
    let raw = message.serialize()?;
    Ok((raw, message))
}
