use std::ffi::{c_char, c_int};

/// One received message's metadata, version 2, mirroring `habilis_network_msg_v2` in the
/// header. It adds the key of the sender to [`super::HabilisNetworkMsg`]. The text lands in the
/// caller's own buffer, NUL-terminated; `len` says how many bytes it has, excluding the NUL.
///
/// The caller allocates this struct and sets `size` to its size before the call. The old struct
/// has no size field, so it cannot grow: a caller built with 80 bytes would overrun.
#[repr(C)]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HabilisNetworkMsgV2 {
    /// The size in bytes of the struct the caller allocated. The caller sets it. A call refuses
    /// a size below the size of this struct.
    pub size: usize,
    /// The nickname of the sender, NUL-terminated. Two members can use one nickname.
    pub nick: [c_char; super::NICK_CAP],
    /// The key of the sender: 64 lowercase hex digits and the NUL. A reply to this key goes to
    /// the sender alone.
    pub key: [c_char; super::KEY_CAP],
    /// Non-zero when the message was directed to us.
    pub directed: c_int,
    /// The length of the body, in bytes.
    pub len: usize,
}

impl HabilisNetworkMsgV2 {
    /// No nickname, no key, no directed flag and no text, with `size` set to the size of this
    /// struct, as a caller sets it.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            size: size_of::<Self>(),
            nick: [0; super::NICK_CAP],
            key: [0; super::KEY_CAP],
            directed: 0,
            len: 0,
        }
    }
}

/// The layout `packages/habilis-network-ffi/src/msg.ts` hand-decodes, pinned like
/// [`super::HabilisNetworkMsg`]: `size` at 0, `nick` at 8, `key` at 72, three bytes of padding,
/// `directed` at 140, `len` at 144, 152 bytes in all.
const _: () = {
    use std::mem::{align_of, offset_of};

    assert!(size_of::<HabilisNetworkMsgV2>() == 152, "msg.ts MSG_BYTES");
    assert!(
        align_of::<HabilisNetworkMsgV2>() == 8,
        "HabilisNetworkMsgV2 has the alignment the C header declares, 8"
    );
    assert!(
        offset_of!(HabilisNetworkMsgV2, size) == 0,
        "size is at offset 0 of HabilisNetworkMsgV2"
    );
    assert!(
        offset_of!(HabilisNetworkMsgV2, nick) == 8,
        "nick is at offset 8 of HabilisNetworkMsgV2"
    );
    assert!(
        offset_of!(HabilisNetworkMsgV2, key) == 72,
        "key is at offset 72 of HabilisNetworkMsgV2"
    );
    assert!(
        offset_of!(HabilisNetworkMsgV2, directed) == 140,
        "directed is at offset 140 of HabilisNetworkMsgV2"
    );
    assert!(
        offset_of!(HabilisNetworkMsgV2, len) == 144,
        "len is at offset 144 of HabilisNetworkMsgV2"
    );
};
