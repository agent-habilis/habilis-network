use std::ffi::c_char;

use std::ptr;
/// The mesh selectors, mirroring `habilis_network_opts` in the header. String fields are
/// NUL-terminated C strings or NULL; `max_peers == 0` and `max_direct == 0` take
/// the engine defaults (G is 32, C is 64).
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct HabilisNetworkOpts {
    /// The mesh id to join, NUL-terminated, or NULL. Set at most one of `mesh` and `topic`.
    pub mesh: *const c_char,
    /// A shared string to derive a public mesh from, NUL-terminated, or NULL.
    pub topic: *const c_char,
    /// The nickname, as a NUL-terminated string.
    pub nick: *const c_char,
    /// The mesh name on create, NUL-terminated. NULL falls back to `habilis-network`.
    pub name: *const c_char,
    /// Comma-separated lookups, any of `mdns`, `dht`, `relay`; NULL ⇒ none
    /// (a loopback mesh on create).
    pub lookup: *const c_char,
    /// Comma-separated transports, any of `udp`, `webrtc`, `multihop`, `gossip`, `relay`;
    /// NULL ⇒ `udp,webrtc,multihop,gossip`, so all data stays peer to peer.
    pub transport: *const c_char,
    /// Comma-separated custom relay ladder; NULL ⇒ the default ladder.
    pub relay_urls: *const c_char,
    /// G: the gossip active-view cap.
    pub max_peers: usize,
    /// C: the ceiling of direct connections, `WebRTC` sessions and unicast connections together.
    pub max_direct: usize,
}

impl HabilisNetworkOpts {
    /// Every pointer NULL and every number zero, which takes the engine defaults.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            mesh: ptr::null(),
            topic: ptr::null(),
            nick: ptr::null(),
            name: ptr::null(),
            lookup: ptr::null(),
            transport: ptr::null(),
            relay_urls: ptr::null(),
            max_peers: 0,
            max_direct: 0,
        }
    }
}

/// The layout `packages/habilis-network-ffi/src/dlopen/opts-struct.ts` hand-encodes,
/// pinned here so the two sides are coupled by a compile error rather than by
/// copied comments. `bun:ffi` and Deno's FFI cannot marshal a struct, so that
/// file writes these exact offsets into a byte buffer; koffi (Node) names the
/// fields instead and does not depend on this block.
///
/// Adding or reordering a field breaks a linked C consumer silently — it keeps
/// passing the old layout — so a failure here is the signal to bump
/// `OPTS_BYTES` in that file, its offset constants, and the CHANGELOG entry
/// together. 64-bit little-endian, the same scope the TypeScript claims.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};

    assert!(
        size_of::<HabilisNetworkOpts>() == 72,
        "opts-struct.ts OPTS_BYTES"
    );
    assert!(
        align_of::<HabilisNetworkOpts>() == 8,
        "HabilisNetworkOpts has the alignment the C header declares, 8"
    );
    assert!(
        offset_of!(HabilisNetworkOpts, mesh) == 0,
        "mesh is at offset 0 of HabilisNetworkOpts"
    );
    assert!(
        offset_of!(HabilisNetworkOpts, topic) == 8,
        "topic is at offset 8 of HabilisNetworkOpts"
    );
    assert!(
        offset_of!(HabilisNetworkOpts, nick) == 16,
        "nick is at offset 16 of HabilisNetworkOpts"
    );
    assert!(
        offset_of!(HabilisNetworkOpts, name) == 24,
        "name is at offset 24 of HabilisNetworkOpts"
    );
    assert!(
        offset_of!(HabilisNetworkOpts, lookup) == 32,
        "lookup is at offset 32 of HabilisNetworkOpts"
    );
    assert!(
        offset_of!(HabilisNetworkOpts, transport) == 40,
        "transport is at offset 40 of HabilisNetworkOpts"
    );
    assert!(
        offset_of!(HabilisNetworkOpts, relay_urls) == 48,
        "relay_urls is at offset 48 of HabilisNetworkOpts"
    );
    assert!(
        offset_of!(HabilisNetworkOpts, max_peers) == 56,
        "max_peers is at offset 56 of HabilisNetworkOpts"
    );
    assert!(
        offset_of!(HabilisNetworkOpts, max_direct) == 64,
        "max_direct is at offset 64 of HabilisNetworkOpts"
    );
};
