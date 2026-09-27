//! The C ABI. `include/fofoca.h` is the hand-written declaration of everything
//! here — change one, change the other; `tests/ffi_smoke.rs` is what catches a
//! mismatch from this side. The out-of-tree consumer is `mallorca`, which links
//! the `staticlib`, so no check in this workspace sees a break there.
//!
//! Conventions, uniform across the surface: a pointer-returning call yields NULL
//! on failure, an `int` call returns `0`/`-1`, and the reason for any failure is
//! in [`fofoca_last_error`] on the calling thread. Every entry point catches
//! unwinds — a Rust panic crossing into C is undefined behaviour.
#![expect(
    unsafe_code,
    reason = "this module *is* the C ABI: raw pointers from the foreign caller, and a boxed handle it owns"
)]

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int, c_long};
use std::panic::AssertUnwindSafe;
use std::sync::OnceLock;
use std::time::Duration;

use crate::mesh::{Inbound, MAX_MSG, Mesh, Opts};
use crate::stream::{Read, ReadEnd, Streams, Writer};

/// Capacity of [`FofocaMsg::nick`], including the NUL. A minted nickname is two
/// short words; a longer chosen one is truncated to 63 bytes.
const NICK_CAP: usize = 64;

thread_local! {
    /// The reason for the most recent failure on this thread. Held as a
    /// `CString` so [`fofoca_last_error`] can hand out a borrowed pointer; valid
    /// until this thread's next `mesh_*` call.
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// The mesh selectors, mirroring `fofoca_opts` in the header. String fields are
/// NUL-terminated C strings or NULL; `max_peers == 0` takes the engine default.
#[repr(C)]
#[derive(Debug)]
pub struct FofocaOpts {
    pub mesh: *const c_char,
    pub topic: *const c_char,
    pub nick: *const c_char,
    pub name: *const c_char,
    /// Comma-separated lookups, any of `mdns`, `dht`, `relay`; NULL ⇒ none
    /// (a loopback mesh on create).
    pub lookup: *const c_char,
    /// Comma-separated transports, `p2p` or `p2p,relay`; NULL ⇒ `p2p`, so
    /// all data stays peer to peer.
    pub transport: *const c_char,
    /// Comma-separated custom relay ladder; NULL ⇒ the default ladder.
    pub relay_urls: *const c_char,
    /// Nonzero disables direct UDP / hole-punched paths.
    pub disable_ip: c_int,
    /// Nonzero disables the `WebRTC` lane.
    pub disable_webrtc: c_int,
    pub max_peers: usize,
}

/// The layout `packages/fofoca-ffi/src/dlopen/opts-struct.ts` hand-encodes,
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

    assert!(size_of::<FofocaOpts>() == 72, "opts-struct.ts OPTS_BYTES");
    assert!(align_of::<FofocaOpts>() == 8);
    assert!(offset_of!(FofocaOpts, mesh) == 0);
    assert!(offset_of!(FofocaOpts, topic) == 8);
    assert!(offset_of!(FofocaOpts, nick) == 16);
    assert!(offset_of!(FofocaOpts, name) == 24);
    assert!(offset_of!(FofocaOpts, lookup) == 32);
    assert!(offset_of!(FofocaOpts, transport) == 40);
    assert!(offset_of!(FofocaOpts, relay_urls) == 48);
    assert!(offset_of!(FofocaOpts, disable_ip) == 56);
    assert!(offset_of!(FofocaOpts, disable_webrtc) == 60);
    assert!(offset_of!(FofocaOpts, max_peers) == 64);
};

/// One received message's metadata, mirroring `fofoca_msg` in the header. The
/// text itself lands in the caller's own buffer, NUL-terminated; `len` says how
/// many bytes it has, excluding the NUL.
#[repr(C)]
#[derive(Debug)]
pub struct FofocaMsg {
    pub nick: [c_char; NICK_CAP],
    pub directed: c_int,
    pub len: usize,
}

/// The layout `packages/fofoca-ffi/src/msg.ts` hand-decodes, pinned like
/// `FofocaOpts` above.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};

    assert!(size_of::<FofocaMsg>() == 80, "msg.ts MSG_BYTES");
    assert!(align_of::<FofocaMsg>() == 8);
    assert!(offset_of!(FofocaMsg, nick) == 0);
    assert!(offset_of!(FofocaMsg, directed) == 64);
    assert!(offset_of!(FofocaMsg, len) == 72);
};

/// The opaque handle behind `fofoca_mesh *`. Holds the [`Mesh`] plus
/// NUL-terminated copies of the identity strings, so [`fofoca_mesh_id`] /
/// [`fofoca_mesh_nickname`] can hand out pointers that stay valid for the
/// handle's lifetime.
#[expect(
    missing_debug_implementations,
    reason = "wraps Mesh, which owns a tokio Runtime and so has no Debug impl"
)]
pub struct FofocaMesh {
    mesh: Mesh,
    id: CString,
    nick: CString,
    name: CString,
}

fn set_error(message: &str) {
    // A NUL inside the message would truncate it; replace rather than drop the
    // whole diagnostic.
    let sanitized = message.replace('\0', "\\0");
    let cstring = CString::new(sanitized).unwrap_or_else(|_| CString::default());
    LAST_ERROR.with_borrow_mut(|slot| *slot = Some(cstring));
}

fn clear_error() {
    LAST_ERROR.with_borrow_mut(|slot| *slot = None);
}

/// Run `body`, converting a panic into `fallback` plus an error message. Every
/// entry point goes through this: unwinding into C is undefined behaviour.
fn guard<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_panic) => {
            set_error("a panic crossed the FFI boundary");
            fallback
        }
    }
}

/// Read a borrowed field off the handle, or NULL when the handle is NULL.
///
/// The three string getters differ only in which `CString` they return, so the
/// panic guard and the null check live here once.
///
/// # Safety
/// `handle` must be a live handle from [`fofoca_mesh_open`], or NULL.
unsafe fn borrowed_field(
    handle: *const FofocaMesh,
    field: impl FnOnce(&FofocaMesh) -> *const c_char,
) -> *const c_char {
    guard(std::ptr::null(), || {
        // SAFETY: live handle or NULL, forwarded from this function's contract.
        match unsafe { handle.as_ref() } {
            Some(handle) => field(handle),
            None => std::ptr::null(),
        }
    })
}

/// Render a JSON document from the mesh into the caller's buffer, following the
/// length-then-fill convention [`copy_out`] implements.
///
/// `name` is the entry point's own name, so a NULL handle still reports which
/// call failed.
///
/// # Safety
/// `handle` must be a live handle from [`fofoca_mesh_open`], or NULL; `buf` NULL
/// or writable for `cap` bytes.
unsafe fn json_out(
    name: &str,
    handle: *mut FofocaMesh,
    buf: *mut c_char,
    cap: usize,
    render: impl FnOnce(&Mesh) -> anyhow::Result<String>,
) -> c_long {
    guard(-1, || {
        clear_error();
        // SAFETY: live handle or NULL, forwarded from this function's contract.
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            set_error(&format!("{name}: handle is NULL"));
            return -1;
        };
        match render(&handle.mesh) {
            // SAFETY: `buf`/`cap` are the caller's buffer, forwarded likewise.
            Ok(json) => unsafe { copy_out(&json, buf, cap) },
            Err(error) => {
                set_error(&format!("{error:#}"));
                -1
            }
        }
    })
}

/// Borrow a caller-provided C string. `Ok(None)` for NULL (every optional field
/// spells "unset" that way); an error for non-UTF-8 bytes.
///
/// # Safety
/// `ptr` is NULL or points to a NUL-terminated string that outlives the call.
unsafe fn optional_str(ptr: *const c_char) -> Result<Option<&'static str>, ()> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller guarantees a NUL-terminated string; the returned
    // lifetime is immediately narrowed by the callers, which only read it
    // during their own call.
    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(text) => Ok(Some(text)),
        Err(error) => {
            set_error(&format!("argument is not valid UTF-8: {error}"));
            Err(())
        }
    }
}

/// Split a comma-separated C list into its parsed entries. NULL and the empty
/// string are the empty list; a name that is not one of the type's choices
/// puts that type's own message (`unknown lookup ...`) in the error slot.
fn comma_list<T: std::str::FromStr>(text: Option<&str>) -> Result<Vec<T>, ()>
where
    T::Err: std::fmt::Display,
{
    text.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry.parse::<T>().map_err(|error| {
                set_error(&error.to_string());
            })
        })
        .collect()
}

/// Copy `text` into a caller buffer, NUL-terminating it. Returns the length
/// `text` needs (excluding the NUL); when that does not fit in `cap` nothing is
/// written and the caller retries with a bigger buffer.
///
/// # Safety
/// `buf` is NULL, or writable for `cap` bytes.
unsafe fn copy_out(text: &str, buf: *mut c_char, cap: usize) -> c_long {
    let bytes = text.as_bytes();
    let needed = bytes.len();
    if !buf.is_null() && needed < cap {
        // SAFETY: `needed + 1 <= cap` bytes are writable per the contract above,
        // and the source is a distinct Rust-owned allocation.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), needed);
            buf.add(needed).write(0);
        }
    }
    // Lengths here are JSON documents bounded by the automerge doc / roster
    // size, never anywhere near `c_long::MAX`.
    c_long::try_from(needed).unwrap_or(c_long::MAX)
}

/// Fill `FofocaMsg::nick`, truncating a pathologically long nickname rather than
/// overflowing the caller's fixed array.
fn write_nick(field: &mut [c_char; NICK_CAP], nick: &str) {
    let bytes = nick.as_bytes();
    let take = bytes.len().min(NICK_CAP - 1);
    // SAFETY: `take < NICK_CAP` elements are written into an array of that size,
    // from a distinct Rust-owned allocation.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), field.as_mut_ptr().cast::<u8>(), take);
    }
    field[take] = 0;
}

/// Create or join a mesh and return an owned handle, or NULL on failure.
///
/// # Safety
/// `opts` must point to a readable [`FofocaOpts`] whose string fields are NULL or
/// NUL-terminated. The returned handle must be released with
/// [`fofoca_mesh_close`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_mesh_open(opts: *const FofocaOpts) -> *mut FofocaMesh {
    guard(std::ptr::null_mut(), || {
        clear_error();
        if opts.is_null() {
            set_error("fofoca_mesh_open: opts is NULL");
            return std::ptr::null_mut();
        }
        // SAFETY: non-NULL and readable per the contract above.
        let opts = unsafe { &*opts };
        // SAFETY: same contract, applied to each optional string field.
        let strings = unsafe {
            (
                optional_str(opts.mesh),
                optional_str(opts.topic),
                optional_str(opts.nick),
                optional_str(opts.name),
            )
        };
        let (Ok(mesh), Ok(topic), Ok(nick), Ok(name)) = strings else {
            return std::ptr::null_mut();
        };
        // SAFETY: NUL-terminated or NULL, per the header contract, for each
        // of the three comma lists.
        let lists = unsafe {
            (
                optional_str(opts.lookup),
                optional_str(opts.transport),
                optional_str(opts.relay_urls),
            )
        };
        let (Ok(lookup), Ok(transport), Ok(relay_urls)) = lists else {
            return std::ptr::null_mut();
        };
        let (Ok(lookup), Ok(transport)) = (comma_list(lookup), comma_list(transport)) else {
            return std::ptr::null_mut();
        };
        let relay_urls: Vec<String> = relay_urls
            .map(|urls| urls.split(',').map(|url| url.trim().to_owned()).collect())
            .unwrap_or_default();
        let parsed = Opts {
            mesh: mesh.map(str::to_owned),
            topic: topic.map(str::to_owned),
            nick: nick.map(str::to_owned),
            name: name.map(str::to_owned),
            lookup,
            transport,
            relay_urls,
            paths: fofoca::net::PathFlags {
                ip: opts.disable_ip == 0,
                webrtc: opts.disable_webrtc == 0,
            },
            max_peers: opts.max_peers,
        };
        match Mesh::open(&parsed) {
            Ok(opened) => {
                // The nickname the engine settled on — not `nick` above, which is
                // only what the caller asked for (and may have been NULL).
                let assigned = CString::new(opened.nickname()).unwrap_or_default();
                let id = CString::new(opened.fofoca_id()).unwrap_or_default();
                let fofoca_name = CString::new(opened.name()).unwrap_or_default();
                Box::into_raw(Box::new(FofocaMesh {
                    mesh: opened,
                    id,
                    nick: assigned,
                    name: fofoca_name,
                }))
            }
            Err(error) => {
                set_error(&format!("{error:#}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// The `mesh id` id of this mesh, borrowed for the handle's lifetime.
///
/// # Safety
/// `handle` must be a live handle from [`fofoca_mesh_open`], or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_mesh_id(handle: *const FofocaMesh) -> *const c_char {
    // SAFETY: live handle or NULL, per the contract above.
    unsafe { borrowed_field(handle, |handle| handle.id.as_ptr()) }
}

/// This mesh's name, borrowed for the handle's lifetime.
///
/// # Safety
/// `handle` must be a live handle from [`fofoca_mesh_open`], or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_mesh_name(handle: *const FofocaMesh) -> *const c_char {
    // SAFETY: live handle or NULL, per the contract above.
    unsafe { borrowed_field(handle, |handle| handle.name.as_ptr()) }
}

/// Our nickname in this mesh, borrowed for the handle's lifetime.
///
/// # Safety
/// `handle` must be a live handle from [`fofoca_mesh_open`], or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_mesh_nickname(handle: *const FofocaMesh) -> *const c_char {
    // SAFETY: live handle or NULL, per the contract above.
    unsafe { borrowed_field(handle, |handle| handle.nick.as_ptr()) }
}

/// Send one message — broadcast when `to` is NULL, directed at that peer's
/// nickname otherwise. Returns 0, or -1 on failure: a message that does not fit
/// one frame is refused, never split.
///
/// # Safety
/// `handle` must be live; `to` NULL or NUL-terminated; `text` NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_msg_send(
    handle: *mut FofocaMesh,
    to: *const c_char,
    text: *const c_char,
) -> c_int {
    guard(-1, || {
        clear_error();
        // SAFETY: live handle or NULL, per the contract above.
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            set_error("fofoca_msg_send: handle is NULL");
            return -1;
        };
        // SAFETY: same contract, applied to the two strings.
        let (Ok(to), Ok(text)) = (unsafe { (optional_str(to), optional_str(text)) }) else {
            return -1;
        };
        let Some(text) = text else {
            set_error("fofoca_msg_send: text is NULL");
            return -1;
        };
        report(handle.mesh.send(to, text))
    })
}

/// Take the next inbound message, waiting up to `timeout_ms`. Returns 1 with
/// the text NUL-terminated in `buf` and `out` filled, 0 on timeout, -1 on
/// failure, or -2 when the text does not fit in `cap`: nothing is written, the
/// message stays queued, and `out->len` holds its length — retry with a buffer
/// of at least `out->len + 1` bytes.
///
/// # Safety
/// `handle` must be live and not used concurrently from another thread; `buf`
/// writable for `cap` bytes; `out` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_msg_recv(
    handle: *mut FofocaMesh,
    buf: *mut c_char,
    cap: usize,
    timeout_ms: c_int,
    out: *mut FofocaMsg,
) -> c_long {
    guard(-1, || {
        clear_error();
        // SAFETY: live, exclusively-owned handle per the contract above.
        let Some(handle) = (unsafe { handle.as_mut() }) else {
            set_error("fofoca_msg_recv: handle is NULL");
            return -1;
        };
        if out.is_null() || buf.is_null() {
            set_error("fofoca_msg_recv: buf or out is NULL");
            return -1;
        }
        let timeout = Duration::from_millis(u64::try_from(timeout_ms.max(0)).unwrap_or(0));
        let msg = match handle.mesh.recv(timeout) {
            Ok(Some(msg)) => msg,
            Ok(None) => return 0,
            Err(error) => {
                set_error(&format!("{error:#}"));
                return -1;
            }
        };
        let mut meta = FofocaMsg {
            nick: [0; NICK_CAP],
            directed: c_int::from(msg.directed),
            len: msg.text.len(),
        };
        write_nick(&mut meta.nick, &msg.nick);
        if msg.text.len() >= cap {
            // SAFETY: non-NULL (checked) and writable per the contract above.
            unsafe { out.write(meta) }
            // Not a failure: the message waits, and `out->len` says how big a
            // buffer the retry needs, so the error slot stays clear.
            handle.mesh.keep(msg);
            return -2;
        }
        let Inbound { text, .. } = msg;
        // SAFETY: `text.len() + 1 <= cap` bytes are writable per the contract
        // above, and the source is a distinct Rust-owned allocation.
        unsafe {
            std::ptr::copy_nonoverlapping(text.as_ptr(), buf.cast::<u8>(), text.len());
            buf.add(text.len()).write(0);
            out.write(meta);
        }
        1
    })
}

/// Apply an RFC 7386 merge document (a JSON object) to the shared `state`
/// channel and gossip the change. Returns 0, or -1 on failure.
///
/// # Safety
/// `handle` must be live; `json` must be a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_mesh_state_merge(
    handle: *mut FofocaMesh,
    json: *const c_char,
) -> c_int {
    guard(-1, || {
        clear_error();
        // SAFETY: live handle or NULL, per the contract above.
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            set_error("fofoca_mesh_state_merge: handle is NULL");
            return -1;
        };
        // SAFETY: same contract, applied to the merge document.
        let Ok(json) = (unsafe { optional_str(json) }) else {
            return -1;
        };
        let Some(json) = json else {
            set_error("fofoca_mesh_state_merge: json is NULL");
            return -1;
        };
        report(handle.mesh.state_merge(json))
    })
}

/// Write the merged shared `state` document as JSON into `buf`. Returns the
/// length the document needs (excluding the NUL) — when that does not fit in
/// `cap`, nothing is written and the caller should retry with a bigger buffer.
/// -1 on failure.
///
/// # Safety
/// `handle` must be live; `buf` NULL or writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_mesh_state_json(
    handle: *mut FofocaMesh,
    buf: *mut c_char,
    cap: usize,
) -> c_long {
    // SAFETY: live handle or NULL, and `buf`/`cap` the caller's buffer, per
    // the contract above.
    unsafe { json_out("fofoca_mesh_state_json", handle, buf, cap, Mesh::state_json) }
}

/// Write the live peer roster as JSON into `buf`. Same length/`cap` convention
/// as [`fofoca_mesh_state_json`].
///
/// # Safety
/// `handle` must be live; `buf` NULL or writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_mesh_peers_json(
    handle: *mut FofocaMesh,
    buf: *mut c_char,
    cap: usize,
) -> c_long {
    // SAFETY: live handle or NULL, and `buf`/`cap` the caller's buffer, per
    // the contract above.
    unsafe { json_out("fofoca_mesh_peers_json", handle, buf, cap, Mesh::peers_json) }
}

/// The number of peers **other than you** in the mesh right now; `0` means you
/// are alone. -1 on failure.
///
/// # Safety
/// `handle` must be a live handle from [`fofoca_mesh_open`], or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_mesh_peer_count(handle: *mut FofocaMesh) -> c_long {
    guard(-1, || {
        clear_error();
        // SAFETY: live handle or NULL, per the contract above.
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            set_error("fofoca_mesh_peer_count: handle is NULL");
            return -1;
        };
        match handle.mesh.peer_count() {
            // A roster is bounded by the active-view cap; this cannot overflow.
            Ok(count) => c_long::try_from(count).unwrap_or(c_long::MAX),
            Err(error) => {
                set_error(&format!("{error:#}"));
                -1
            }
        }
    })
}

/// Leave the mesh and free the handle. Returns 0, or -1 if the event loop
/// reported an error on the way out; the handle is freed either way, so it must
/// not be used again.
///
/// # Safety
/// `handle` must be a live handle from [`fofoca_mesh_open`] (or NULL) and must
/// not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_mesh_close(handle: *mut FofocaMesh) -> c_int {
    guard(-1, || {
        clear_error();
        if handle.is_null() {
            return 0;
        }
        // SAFETY: the handle came from `Box::into_raw` in `fofoca_mesh_open` and the
        // caller promises not to use it again, so reclaiming ownership here is
        // sound.
        let mut owned = unsafe { Box::from_raw(handle) };
        report(owned.mesh.close())
    })
}

/// How a stream node reaches peers, mirroring `fofoca_stream_opts` in the
/// header: the same three lists and two switches `fofoca_opts` carries, without
/// the mesh selectors a stream has no use for.
#[repr(C)]
#[derive(Debug)]
pub struct FofocaStreamOpts {
    pub lookup: *const c_char,
    pub transport: *const c_char,
    pub relay_urls: *const c_char,
    pub disable_ip: c_int,
    pub disable_webrtc: c_int,
}

/// Pinned like `FofocaOpts`: a reordered field would silently misread a
/// caller's struct.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};

    assert!(size_of::<FofocaStreamOpts>() == 32);
    assert!(align_of::<FofocaStreamOpts>() == 8);
    assert!(offset_of!(FofocaStreamOpts, lookup) == 0);
    assert!(offset_of!(FofocaStreamOpts, transport) == 8);
    assert!(offset_of!(FofocaStreamOpts, relay_urls) == 16);
    assert!(offset_of!(FofocaStreamOpts, disable_ip) == 24);
    assert!(offset_of!(FofocaStreamOpts, disable_webrtc) == 28);
};

/// The opaque handle behind `fofoca_streams *`.
#[expect(
    missing_debug_implementations,
    reason = "wraps Streams, which owns a tokio Runtime and so has no Debug impl"
)]
pub struct FofocaStreams {
    streams: Streams,
}

/// The opaque handle behind `fofoca_producer *`, with a NUL-terminated copy of
/// the hash so [`fofoca_stream_hash`] can lend it out.
#[expect(
    missing_debug_implementations,
    reason = "wraps Writer, which holds a tokio Runtime and so has no Debug impl"
)]
pub struct FofocaProducer {
    writer: Writer,
    hash: CString,
}

/// The opaque handle behind `fofoca_reader *`.
#[expect(
    missing_debug_implementations,
    reason = "wraps ReadEnd, which holds a tokio Runtime and so has no Debug impl"
)]
pub struct FofocaReader {
    reader: ReadEnd,
}

fn timeout_of(timeout_ms: c_int) -> Duration {
    Duration::from_millis(u64::try_from(timeout_ms.max(0)).unwrap_or(0))
}

/// Stand up a stream node, or NULL on failure.
///
/// # Safety
/// `opts` must point to a readable [`FofocaStreamOpts`] whose string fields are
/// NULL or NUL-terminated. Release the node with [`fofoca_streams_close`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_streams_bind(opts: *const FofocaStreamOpts) -> *mut FofocaStreams {
    guard(std::ptr::null_mut(), || {
        clear_error();
        if opts.is_null() {
            set_error("fofoca_streams_bind: opts is NULL");
            return std::ptr::null_mut();
        }
        // SAFETY: non-NULL and readable per the contract above.
        let opts = unsafe { &*opts };
        // SAFETY: NUL-terminated or NULL, per the header contract.
        let lists = unsafe {
            (
                optional_str(opts.lookup),
                optional_str(opts.transport),
                optional_str(opts.relay_urls),
            )
        };
        let (Ok(lookup), Ok(transport), Ok(relay_urls)) = lists else {
            return std::ptr::null_mut();
        };
        let (Ok(lookup), Ok(transport)) = (comma_list(lookup), comma_list(transport)) else {
            return std::ptr::null_mut();
        };
        let parsed = fofoca_stream::StreamOpts {
            lookup,
            transport,
            relay_urls: relay_urls
                .map(|urls| urls.split(',').map(|url| url.trim().to_owned()).collect())
                .unwrap_or_default(),
            paths: fofoca::net::PathFlags {
                ip: opts.disable_ip == 0,
                webrtc: opts.disable_webrtc == 0,
            },
        };
        boxed(Streams::bind(&parsed).map(|streams| FofocaStreams { streams }))
    })
}

/// Stand up a stream node that can reach the producer of `hash`: the hash's
/// own lookups and relay policy. NULL on failure.
///
/// # Safety
/// `hash` must be NUL-terminated. Release the node with [`fofoca_streams_close`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_streams_bind_for(hash: *const c_char) -> *mut FofocaStreams {
    guard(std::ptr::null_mut(), || {
        clear_error();
        // SAFETY: NUL-terminated or NULL, per the contract above.
        let Ok(Some(hash)) = (unsafe { optional_str(hash) }) else {
            set_error("fofoca_streams_bind_for: hash is NULL or not UTF-8");
            return std::ptr::null_mut();
        };
        boxed(Streams::bind_for(hash).map(|streams| FofocaStreams { streams }))
    })
}

/// Shut a stream node down and free it. Its producers and readers stay valid
/// handles, but their streams are abandoned. NULL is a no-op; returns 0.
///
/// # Safety
/// `handle` must come from a `fofoca_streams_bind*` call (or be NULL) and must
/// not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_streams_close(handle: *mut FofocaStreams) -> c_int {
    guard(-1, || {
        clear_error();
        if handle.is_null() {
            return 0;
        }
        // SAFETY: from `Box::into_raw` in a bind call, and not used again.
        let mut owned = unsafe { Box::from_raw(handle) };
        owned.streams.close();
        0
    })
}

/// Open a new stream for one consumer. With a relay lookup it blocks (at most
/// 5 s, once) until the node reaches its home relay, so the hash carries it.
/// NULL on failure. Release it with [`fofoca_stream_close`].
///
/// # Safety
/// `handle` must be a live stream node, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_stream_create(handle: *mut FofocaStreams) -> *mut FofocaProducer {
    guard(std::ptr::null_mut(), || {
        clear_error();
        // SAFETY: live handle or NULL, per the contract above.
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            set_error("fofoca_stream_create: handle is NULL");
            return std::ptr::null_mut();
        };
        boxed(handle.streams.create().map(|writer| FofocaProducer {
            hash: CString::new(writer.hash()).unwrap_or_default(),
            writer,
        }))
    })
}

/// The hash a consumer opens this stream with, borrowed for the producer's
/// lifetime.
///
/// # Safety
/// `handle` must be a live producer, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_stream_hash(handle: *const FofocaProducer) -> *const c_char {
    guard(std::ptr::null(), || {
        // SAFETY: live handle or NULL, per the contract above.
        match unsafe { handle.as_ref() } {
            Some(handle) => handle.hash.as_ptr(),
            None => std::ptr::null(),
        }
    })
}

/// Write all `len` bytes. Returns 1 once written, 0 when no consumer attached
/// within `timeout_ms` (nothing was written), or -1 on failure. Once a consumer
/// has attached, the write runs to the end, paced by the consumer.
///
/// # Safety
/// `handle` must be a live producer; `buf` readable for `len` bytes (NULL when
/// `len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_stream_write(
    handle: *mut FofocaProducer,
    buf: *const u8,
    len: usize,
    timeout_ms: c_int,
) -> c_int {
    guard(-1, || {
        clear_error();
        // SAFETY: live, exclusively-owned handle per the contract above.
        let Some(handle) = (unsafe { handle.as_mut() }) else {
            set_error("fofoca_stream_write: handle is NULL");
            return -1;
        };
        if len > 0 && buf.is_null() {
            set_error("fofoca_stream_write: buf is NULL with a non-zero len");
            return -1;
        }
        let bytes = if len == 0 {
            &[][..]
        } else {
            // SAFETY: readable for `len` bytes per the contract above.
            unsafe { std::slice::from_raw_parts(buf, len) }
        };
        match handle.writer.write(bytes, timeout_of(timeout_ms)) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(error) => {
                set_error(&format!("{error:#}"));
                -1
            }
        }
    })
}

/// End the stream and free the producer. With a consumer attached, it reads
/// everything written and then the end of stream; with none, the stream is
/// abandoned. The producer is freed even on -1. NULL is a no-op.
///
/// # Safety
/// `handle` must be a live producer (or NULL) and must not be used after.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_stream_close(handle: *mut FofocaProducer) -> c_int {
    guard(-1, || {
        clear_error();
        if handle.is_null() {
            return 0;
        }
        // SAFETY: from `Box::into_raw` in `fofoca_stream_create`, not used again.
        let mut owned = unsafe { Box::from_raw(handle) };
        report(owned.writer.close())
    })
}

/// Take the consumer slot of the stream behind `hash`. NULL on failure: the
/// producer cannot be reached, or refuses the hash. Release the reader with
/// [`fofoca_reader_close`].
///
/// # Safety
/// `handle` must be a live stream node; `hash` NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_stream_open(
    handle: *mut FofocaStreams,
    hash: *const c_char,
) -> *mut FofocaReader {
    guard(std::ptr::null_mut(), || {
        clear_error();
        // SAFETY: live handle or NULL, per the contract above.
        let Some(handle) = (unsafe { handle.as_ref() }) else {
            set_error("fofoca_stream_open: handle is NULL");
            return std::ptr::null_mut();
        };
        // SAFETY: NUL-terminated or NULL, per the contract above.
        let Ok(Some(hash)) = (unsafe { optional_str(hash) }) else {
            set_error("fofoca_stream_open: hash is NULL or not UTF-8");
            return std::ptr::null_mut();
        };
        boxed(
            handle
                .streams
                .open(hash)
                .map(|reader| FofocaReader { reader }),
        )
    })
}

/// Read the next bytes into `buf`, waiting up to `timeout_ms`. Returns how many
/// bytes were written (> 0), 0 on timeout, -1 on failure (the producer refused
/// or abandoned the stream, or the link was lost), or -2 at the end of the
/// stream. Bytes that do not fit in `cap` wait for the next call.
///
/// # Safety
/// `handle` must be a live reader; `buf` writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_stream_read(
    handle: *mut FofocaReader,
    buf: *mut u8,
    cap: usize,
    timeout_ms: c_int,
) -> c_long {
    guard(-1, || {
        clear_error();
        // SAFETY: live, exclusively-owned handle per the contract above.
        let Some(handle) = (unsafe { handle.as_mut() }) else {
            set_error("fofoca_stream_read: handle is NULL");
            return -1;
        };
        if buf.is_null() || cap == 0 {
            set_error("fofoca_stream_read: buf is NULL or cap is 0");
            return -1;
        }
        // SAFETY: writable for `cap` bytes per the contract above.
        let buf = unsafe { std::slice::from_raw_parts_mut(buf, cap) };
        match handle.reader.read(buf, timeout_of(timeout_ms)) {
            Ok(Read::Bytes(read)) => c_long::try_from(read).unwrap_or(c_long::MAX),
            Ok(Read::Timeout) => 0,
            Ok(Read::End) => -2,
            Err(error) => {
                set_error(&format!("{error:#}"));
                -1
            }
        }
    })
}

/// Free a reader, giving up the stream. NULL is a no-op; returns 0.
///
/// # Safety
/// `handle` must be a live reader (or NULL) and must not be used after.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fofoca_reader_close(handle: *mut FofocaReader) -> c_int {
    guard(-1, || {
        clear_error();
        if !handle.is_null() {
            // SAFETY: from `Box::into_raw` in `fofoca_stream_open`, not used again.
            drop(unsafe { Box::from_raw(handle) });
        }
        0
    })
}

/// Box a handle for the caller, or record the error and return NULL.
fn boxed<T>(made: anyhow::Result<T>) -> *mut T {
    match made {
        Ok(value) => Box::into_raw(Box::new(value)),
        Err(error) => {
            set_error(&format!("{error:#}"));
            std::ptr::null_mut()
        }
    }
}

/// The reason for the most recent failure on this thread, or NULL if the last
/// call succeeded. Borrowed until this thread's next `mesh_*` call.
#[unsafe(no_mangle)]
pub extern "C" fn fofoca_last_error() -> *const c_char {
    guard(std::ptr::null(), || {
        LAST_ERROR.with_borrow(|slot| match slot {
            Some(message) => message.as_ptr(),
            None => std::ptr::null(),
        })
    })
}

/// The engine's build version stamp. Borrowed for the process's lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn fofoca_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    guard(std::ptr::null(), || {
        VERSION
            .get_or_init(|| CString::new(fofoca::VERSION).unwrap_or_else(|_| CString::default()))
            .as_ptr()
    })
}

/// The longest text in bytes [`fofoca_msg_send`] always accepts. Most text fits
/// well past it; a longer message is refused, not split.
#[unsafe(no_mangle)]
pub extern "C" fn fofoca_max_msg() -> usize {
    MAX_MSG
}

/// Collapse a fallible operation into the `0` / `-1` return code, recording the
/// reason for a foreign caller that has no other way to see it.
fn report(outcome: anyhow::Result<()>) -> c_int {
    match outcome {
        Ok(()) => 0,
        Err(error) => {
            set_error(&format!("{error:#}"));
            -1
        }
    }
}
