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
#[cfg(any(test, feature = "test-fixtures"))]
pub fn build_msg_bytes(
    params: BuildMsgParams<'_>,
    identity: &Identity,
) -> Result<(WireFrame, Verified), MessageError> {
    let msg = Message::new_app(
        params.mesh,
        params.author,
        AppFrameParams {
            tag: params.tag,
            to: None,
            corr: None,
            body: params.body,
        },
    )
    .with_chain(params.chain.seq, params.chain.previous)
    .with_parents(params.chain.parents)
    .sign(identity);
    let raw = msg.serialize()?;
    Ok((raw, msg))
}
