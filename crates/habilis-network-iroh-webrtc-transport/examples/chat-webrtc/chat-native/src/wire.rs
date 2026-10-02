//! [`chat_proto`]'s sans-io frame format, applied to iroh's streams.
//!
//! Two functions, and a rule about how they may be used: **never call
//! [`read_msg`] as a branch of a `select!`**. It performs two reads — a header,
//! then a body sized by it — and a cancelled future between them leaves the
//! stream positioned mid-frame with no way to resynchronise. Every reader here
//! therefore owns its stream in a task of its own and hands decoded messages on
//! through a channel, which is cancel-safe in a way a half-read frame is not.

use anyhow::{Context as _, Result};
use chat_proto::{FRAME_HEADER_LEN, decode_body, decode_frame_len, encode_frame};
use habilis_network_iroh_webrtc_transport::iroh::endpoint::{RecvStream, SendStream};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Write one message as a frame.
///
/// # Errors
/// The message does not encode, or the stream is gone.
pub async fn write_msg<T: Serialize>(send: &mut SendStream, msg: &T) -> Result<()> {
    let frame = encode_frame(msg)?;
    send.write_all(&frame).await.context("write frame")?;
    Ok(())
}

/// Read one frame.
///
/// A clean end of stream is an error here rather than `Ok(None)`: every caller
/// treats "the peer stopped talking" as "the peer left", and the two are not
/// worth distinguishing in a chat.
///
/// # Errors
/// The stream ended, the peer announced a frame over
/// [`chat_proto::MAX_FRAME_BYTES`], or the body does not decode.
pub async fn read_msg<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    recv.read_exact(&mut header)
        .await
        .context("read frame header")?;
    // Bound-checked before the allocation below, which is the reason this is a
    // call into `chat_proto` and not four bytes of `from_le_bytes` inline.
    let len = decode_frame_len(header)?;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .context("read frame body")?;
    decode_body(&body)
}
