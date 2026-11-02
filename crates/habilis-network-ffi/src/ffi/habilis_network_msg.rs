use std::ffi::{c_char, c_int};

/// One received message's metadata, mirroring `habilis_network_msg` in the header. The
/// text itself lands in the caller's own buffer, NUL-terminated; `len` says how
/// many bytes it has, excluding the NUL.
#[repr(C)]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HabilisNetworkMsg {
    /// The nickname of the sender, NUL-terminated.
    pub nick: [c_char; super::NICK_CAP],
    /// Non-zero when the message was directed to us.
    pub directed: c_int,
    /// The length of the body, in bytes.
    pub len: usize,
}

impl HabilisNetworkMsg {
    /// No nickname, no directed flag and no text.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            nick: [0; super::NICK_CAP],
            directed: 0,
            len: 0,
        }
    }
}

/// The layout `packages/habilis-network-ffi/src/msg.ts` hand-decodes, pinned like
/// `HabilisNetworkOpts` above.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};

    assert!(size_of::<HabilisNetworkMsg>() == 80, "msg.ts MSG_BYTES");
    assert!(
        align_of::<HabilisNetworkMsg>() == 8,
        "HabilisNetworkMsg has the alignment the C header declares, 8"
    );
    assert!(
        offset_of!(HabilisNetworkMsg, nick) == 0,
        "nick is at offset 0 of HabilisNetworkMsg"
    );
    assert!(
        offset_of!(HabilisNetworkMsg, directed) == 64,
        "directed is at offset 64 of HabilisNetworkMsg"
    );
    assert!(
        offset_of!(HabilisNetworkMsg, len) == 72,
        "len is at offset 72 of HabilisNetworkMsg"
    );
};
