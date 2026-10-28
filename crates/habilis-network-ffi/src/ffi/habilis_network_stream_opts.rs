use std::ffi::c_char;

/// How a stream node reaches peers, mirroring `habilis_network_stream_opts` in the
/// header: the same three lists `habilis_network_opts` carries, without the mesh
/// selectors a stream has no use for.
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct HabilisNetworkStreamOpts {
    /// The lookups, as a NUL-terminated string.
    pub lookup: *const c_char,
    /// The transports, as a NUL-terminated string.
    pub transport: *const c_char,
    /// The relay URLs, as a NUL-terminated string.
    pub relay_urls: *const c_char,
}

impl HabilisNetworkStreamOpts {
    /// Every pointer NULL, which takes the engine defaults.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            lookup: std::ptr::null(),
            transport: std::ptr::null(),
            relay_urls: std::ptr::null(),
        }
    }
}

/// Pinned like `HabilisNetworkOpts`: a reordered field would silently misread a
/// caller's struct.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};

    assert!(
        size_of::<HabilisNetworkStreamOpts>() == 24,
        "HabilisNetworkStreamOpts has the size the C header declares, 24"
    );
    assert!(
        align_of::<HabilisNetworkStreamOpts>() == 8,
        "HabilisNetworkStreamOpts has the alignment the C header declares, 8"
    );
    assert!(
        offset_of!(HabilisNetworkStreamOpts, lookup) == 0,
        "lookup is at offset 0 of HabilisNetworkStreamOpts"
    );
    assert!(
        offset_of!(HabilisNetworkStreamOpts, transport) == 8,
        "transport is at offset 8 of HabilisNetworkStreamOpts"
    );
    assert!(
        offset_of!(HabilisNetworkStreamOpts, relay_urls) == 16,
        "relay_urls is at offset 16 of HabilisNetworkStreamOpts"
    );
};
