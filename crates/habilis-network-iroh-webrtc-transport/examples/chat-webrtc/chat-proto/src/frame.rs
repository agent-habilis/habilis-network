use serde::{Serialize, de};

use crate::{MAX_FRAME_BYTES, ProtoError};

// ── framing ──────────────────────────────────────────────────────────────────
//
// `u32` little-endian length ‖ JSON body. One frame per message, many frames
// per stream.
//
// Why a length prefix at all, when QUIC already delimits streams: the stream is
// held open for the whole session, so `finish()` cannot mark a boundary the way
// it does in the one-shot JSEP exchange. And why not one stream per message —
// a chat is a conversation, and opening a stream per line would spend a round
// trip on every "hi".

/// Bytes of the fixed-size header every frame starts with.
pub const FRAME_HEADER_LEN: usize = 4;

/// Encode one message as a frame.
///
/// # Errors
/// The message does not serialize, or its body exceeds [`MAX_FRAME_BYTES`].
pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, ProtoError> {
    let body = serde_json::to_vec(message).map_err(ProtoError::Json)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::FrameTooLarge {
            bytes: body.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let len = u32::try_from(body.len()).map_err(|_| ProtoError::FrameTooLarge {
        bytes: body.len(),
        max: MAX_FRAME_BYTES,
    })?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// How many body bytes follow a header.
///
/// Checked against [`MAX_FRAME_BYTES`] *before* the caller allocates, which is
/// the whole reason for a function, not a `u32::from_le_bytes` at the
/// call site.
///
/// # Errors
/// The length exceeds [`MAX_FRAME_BYTES`].
pub fn decode_frame_len(header: [u8; FRAME_HEADER_LEN]) -> Result<usize, ProtoError> {
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(ProtoError::FrameTooLarge {
            bytes: len,
            max: MAX_FRAME_BYTES,
        });
    }
    Ok(len)
}

/// Decode a frame body.
///
/// # Errors
/// The body is not the expected message.
pub fn decode_body<T: de::DeserializeOwned>(body: &[u8]) -> Result<T, ProtoError> {
    serde_json::from_slice(body).map_err(ProtoError::Json)
}
