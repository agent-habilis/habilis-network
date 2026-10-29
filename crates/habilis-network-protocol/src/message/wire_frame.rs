//! The bytes of a message as they go on a socket. Only a [`Verified`](super::Verified) makes one
//! ([`Verified::serialize`](super::Verified::serialize)), so an unsigned or an authored view cannot
//! reach the wire by type.

use bytes::Bytes;

/// The wire bytes of one signed message. Its field is private and it has no constructor outside
/// this crate, so a caller that holds one got it from a [`Verified`](super::Verified).
///
/// # Examples
///
/// A frame cannot be built from bytes outside the crate: the field is private.
///
/// ```compile_fail,E0423
/// use habilis_network_protocol::message::WireFrame;
///
/// let _ = WireFrame(bytes::Bytes::from_static(b"not signed"));
/// ```
///
/// A frame from a signed message is the passing control:
///
/// ```
/// use habilis_network_protocol::message::{Message, Verified, WireFrame};
///
/// const SIGNED: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"eeea2aca75b3ef10bd592fe6a835e147def33b203c0bfcf26253edb7b7d06a450e383d6fdd3fb0ef153969d16df0e6d4b97f1a7ca434106378d8f772814ad50e","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;
///
/// let verified: Verified = Message::parse(SIGNED.as_bytes()).unwrap().verify().unwrap();
/// let frame: WireFrame = verified.serialize().unwrap();
/// assert_eq!(frame.as_bytes(), SIGNED.as_bytes());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame(Bytes);

impl WireFrame {
    /// The frame for `bytes` that a [`Verified`](super::Verified) serialized.
    pub(crate) fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// The door for a test that must put exact bytes on the wire: an unsigned frame, or a
    /// malformed one. No engine-made frame can be either, so the adversarial suite needs this.
    ///
    /// It exists in unit tests and in any build that enables `test-fixtures`. A release binary must
    /// not enable that feature, because the door would let it send bytes that no signed message
    /// produced.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn fixture_raw(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// The number of bytes on the wire.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the frame has no bytes. Never true for a frame a `Verified` made.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The frame with a resend nonce trailer: the new name a re-sent frame carries. The signed fields
    /// are unchanged. Call it on a frame from [`Verified::serialize`](super::Verified::serialize); a
    /// frame that already carries a trailer is not re-named.
    #[must_use]
    pub fn with_resend_nonce(&self, nonce: u64) -> WireFrame {
        debug_assert!(
            super::split_resend_trailer(&self.0).1.is_none(),
            "a frame from Verified::serialize has no resend trailer yet"
        );
        WireFrame(Bytes::from(super::wire_with_resend_nonce(&self.0, nonce)))
    }

    /// The bytes, for a consumer that writes them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes as a `Bytes`, for a consumer that hands them to a socket.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::WireFrame;

    #[test]
    fn a_fixture_frame_carries_exactly_the_bytes_it_was_given() {
        let raw: &[u8] = b"\xff not a signed message \x00";
        let frame = WireFrame::fixture_raw(Bytes::copy_from_slice(raw));
        assert_eq!(
            frame.as_bytes(),
            raw,
            "a fixture frame keeps exactly the bytes it was given"
        );
    }
}
