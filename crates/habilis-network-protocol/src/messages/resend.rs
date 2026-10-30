//! The trailer that marks a resend, so that the gossip layer sees new bytes.

/// The byte that starts the trailer of a resend. JSON text holds no raw 0x1E: control bytes are
/// escaped inside a string and are not whitespace outside one.
const RESEND_TRAILER_MARK: u8 = 0x1e;
/// The length of the nonce of a resend, in bytes.
const RESEND_NONCE_LEN: usize = 8;
/// The bytes a resend adds to a frame: the mark and the nonce. It stays inside the 256 bytes of
/// headroom under the gossip limit that `MAX_MESSAGE_SIZE` leaves.
pub const RESEND_TRAILER_LEN: usize = 1 + RESEND_NONCE_LEN;

/// `frame` (the bytes of `Message::serialize`) with the trailer of a resend: a mark and a
/// nonce. The gossip layer names a message by the hash of its payload and drops a payload it has
/// seen for 90 s, so a resend of the same bytes cannot repair a message that the gossip layer
/// delivered and the app did not read. The nonce gives each resend a new name. It sits outside
/// the signature, so the receiver checks the frame as it checks any other, and a reader that
/// does not know the trailer fails to parse the payload (closed, not silently).
#[must_use]
pub(crate) fn wire_with_resend_nonce(frame: &[u8], nonce: u64) -> Vec<u8> {
    let mut wire = Vec::with_capacity(frame.len() + RESEND_TRAILER_LEN);
    wire.extend_from_slice(frame);
    wire.push(RESEND_TRAILER_MARK);
    wire.extend_from_slice(&nonce.to_be_bytes());
    wire
}

/// Split `data` into the frame and the nonce of a resend, if it ends in the trailer.
pub(super) fn split_resend_trailer(data: &[u8]) -> (&[u8], Option<u64>) {
    let Some(mark_at) = data.len().checked_sub(RESEND_TRAILER_LEN) else {
        return (data, None);
    };
    let Some((&mark, nonce_bytes)) = data.get(mark_at..).and_then(<[u8]>::split_first) else {
        return (data, None);
    };
    let nonce: Result<[u8; RESEND_NONCE_LEN], _> = nonce_bytes.try_into();
    let (Some(body), Ok(nonce)) = (data.get(..mark_at), nonce) else {
        return (data, None);
    };
    if mark != RESEND_TRAILER_MARK {
        return (data, None);
    }
    (body, Some(u64::from_be_bytes(nonce)))
}
