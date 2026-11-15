//! The C ABI, driven from Rust through the crate's `rlib`.
//!
//! Every assertion here is about the *boundary* rather than the mesh: NULL
//! handling, the error slot, the length-then-fill buffer convention. It needs no
//! C compiler, so the contract stays covered on any host.
//!
//! A test that needs one handle to see another is behind `cfg(any(feature = "mdns", feature =
//! "dht"))`: both features turn on the engine feature `host`, and a build without it has no
//! socket, so no handle ever sees a peer.
#![expect(
    unsafe_code,
    reason = "the surface under test is `unsafe extern \"C\"`; calling it is the test"
)]

#[cfg(any(feature = "mdns", feature = "dht"))]
use std::ffi::c_int;
use std::ffi::{CStr, CString, c_char, c_long};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(any(feature = "mdns", feature = "dht"))]
use habilis_network_ffi::ffi;
use habilis_network_ffi::ffi::{
    HabilisNetworkMesh, HabilisNetworkMsg, HabilisNetworkOpts, HabilisNetworkProducer,
    HabilisNetworkStreamOpts, HabilisNetworkStreams, habilis_network_last_error,
    habilis_network_max_msg, habilis_network_mesh_close, habilis_network_mesh_id,
    habilis_network_mesh_name, habilis_network_mesh_nickname, habilis_network_mesh_open,
    habilis_network_mesh_peer_count, habilis_network_mesh_peers_json,
    habilis_network_mesh_state_json, habilis_network_mesh_state_merge, habilis_network_msg_recv,
    habilis_network_msg_send, habilis_network_reader_close, habilis_network_stream_close,
    habilis_network_stream_create, habilis_network_stream_hash, habilis_network_stream_open,
    habilis_network_stream_read, habilis_network_stream_write, habilis_network_streams_bind,
    habilis_network_streams_close, habilis_network_version,
};

use std::ptr;
/// Zeroed selectors: no id and no topic, so [`habilis_network_mesh_open`] mints a private
/// loopback mesh — no discovery, no network, nothing to clean up but the handle.
fn create_opts(nick: &CStr) -> HabilisNetworkOpts {
    let mut options = HabilisNetworkOpts::empty();
    options.nick = nick.as_ptr();
    options
}

/// The error slot's current contents, as an owned string.
fn last_error() -> Option<String> {
    let ptr = habilis_network_last_error();
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non-NULL means the slot holds a live `CString` owned by this
    // thread; it stays valid until this thread's next `mesh_*` call, and the
    // copy below happens before any.
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn open(options: &HabilisNetworkOpts) -> *mut HabilisNetworkMesh {
    // SAFETY: `opts` is a live, fully-initialized `HabilisNetworkOpts` whose string fields
    // are NULL or point at `CStr`s that outlive the call.
    unsafe { habilis_network_mesh_open(options) }
}

/// Read a JSON document out through the two-call convention: ask for the length,
/// then fill a buffer of that size.
fn read_json(
    handle: *mut HabilisNetworkMesh,
    reader: unsafe extern "C" fn(*mut HabilisNetworkMesh, *mut c_char, usize) -> c_long,
) -> String {
    // SAFETY: a NULL buffer with a zero capacity is the documented "how long is
    // it?" query — the callee writes nothing.
    let needed = unsafe { reader(handle, ptr::null_mut(), 0) };
    assert!(needed >= 0, "length query failed: {:?}", last_error());
    let mut buffer = vec![0_u8; usize::try_from(needed).expect("a sane length") + 1];
    let destination: *mut c_char = buffer.as_mut_ptr().cast();
    // SAFETY: the buffer is writable for exactly the capacity being passed.
    let written = unsafe { reader(handle, destination, buffer.len()) };
    assert_eq!(written, needed, "the second call must agree on the length");
    buffer.truncate(usize::try_from(written).expect("a sane length"));
    String::from_utf8(buffer).expect("the document is UTF-8")
}

#[test]
fn version_and_max_msg_are_reported() {
    let version = habilis_network_version();
    assert!(!version.is_null(), "habilis_network_version returned NULL");
    // SAFETY: non-NULL, and the pointer is valid for the process's lifetime.
    let version = unsafe { CStr::from_ptr(version) };
    assert!(
        !version.to_bytes().is_empty(),
        "the version stamp is empty: {version:?}"
    );
    assert!(
        habilis_network_max_msg() > 0,
        "a message must carry at least one byte of text"
    );
}

#[test]
fn a_bad_mesh_id_fails_with_a_reason() {
    let nick = CString::new("solo").expect("no interior NUL");
    let bogus = CString::new("not-a-mesh-id").expect("no interior NUL");
    let mut options = create_opts(&nick);
    options.mesh = bogus.as_ptr();

    let handle = open(&options);
    assert!(handle.is_null(), "an unparseable id must not open a handle");
    let error = last_error().expect("a failure must leave a reason in the error slot");
    assert!(
        !error.is_empty(),
        "the error slot holds an empty string rather than a reason"
    );
}

#[test]
fn null_arguments_are_errors_not_crashes() {
    // Each rejected call is checked on the spot: a call clears the error slot on
    // entry, so only the most recent outcome is ever in there.
    // SAFETY: passing NULL is explicitly part of each function's contract — the
    // point of this test is that it is rejected rather than dereferenced.
    unsafe {
        assert!(
            habilis_network_mesh_open(ptr::null()).is_null(),
            "a null mesh open is an error, not a crash"
        );
        assert!(
            last_error().is_some(),
            "habilis_network_mesh_open(NULL) left no reason"
        );

        assert_eq!(
            habilis_network_msg_send(ptr::null_mut(), ptr::null(), c"hi".as_ptr()),
            -1,
            "a null send is an error"
        );
        assert!(
            last_error().is_some(),
            "habilis_network_msg_send(NULL) left no reason"
        );

        assert_eq!(
            habilis_network_mesh_state_merge(ptr::null_mut(), ptr::null()),
            -1,
            "a null state merge is an error"
        );
        assert!(
            last_error().is_some(),
            "habilis_network_mesh_state_merge(NULL) left no reason"
        );

        assert_eq!(
            habilis_network_mesh_state_json(ptr::null_mut(), ptr::null_mut(), 0),
            -1,
            "a null state json is an error"
        );
        assert!(
            last_error().is_some(),
            "habilis_network_mesh_state_json(NULL) left no reason"
        );

        assert_eq!(
            habilis_network_mesh_peer_count(ptr::null_mut()),
            -1,
            "a null peer count is an error"
        );
        assert!(
            last_error().is_some(),
            "habilis_network_mesh_peer_count(NULL) left no reason"
        );

        assert!(
            habilis_network_mesh_id(ptr::null()).is_null(),
            "a null mesh id is null"
        );
        assert!(
            habilis_network_mesh_name(ptr::null()).is_null(),
            "a null mesh name is null"
        );
        assert!(
            habilis_network_mesh_nickname(ptr::null()).is_null(),
            "a null nickname is null"
        );

        // Closing NULL is a no-op success, so a caller's cleanup path needs no
        // guard of its own — and succeeding clears the slot.
        assert_eq!(
            habilis_network_mesh_close(ptr::null_mut()),
            0,
            "a null close is an error"
        );
        assert!(
            last_error().is_none(),
            "a successful call must clear the error slot"
        );
    }
}

#[test]
fn a_handle_serves_identity_state_and_roster() {
    let nick = CString::new("solo").expect("no interior NUL");
    let options = create_opts(&nick);
    let handle = open(&options);
    assert!(
        !handle.is_null(),
        "habilis_network_mesh_open failed: {:?}",
        last_error()
    );

    // SAFETY: `handle` is live for the rest of this test; the returned pointers
    // are borrowed from it and read before it is closed.
    let (id, mine) = unsafe {
        (
            habilis_network_mesh_id(handle),
            habilis_network_mesh_nickname(handle),
        )
    };
    assert!(
        !id.is_null() && !mine.is_null(),
        "a handle serves its identity, state, and roster"
    );
    // SAFETY: both are non-NULL NUL-terminated strings owned by the handle.
    let (id, mine) = unsafe { (CStr::from_ptr(id), CStr::from_ptr(mine)) };
    let id_str = id.to_str().expect("the id is UTF-8");
    assert!(
        !id_str.contains("://") && id_str.is_ascii(),
        "expected a bare base58 id, got {id_str:?}"
    );
    assert_eq!(
        mine.to_bytes(),
        b"solo",
        "the requested nickname is in force"
    );

    // A merge is readable back out of the local replica immediately.
    let merge = CString::new(r#"{"probe":"ffi-smoke"}"#).expect("no interior NUL");
    // SAFETY: live handle, NUL-terminated JSON.
    let merged = unsafe { habilis_network_mesh_state_merge(handle, merge.as_ptr()) };
    assert_eq!(merged, 0, "state_merge failed: {:?}", last_error());
    let state = read_json(handle, habilis_network_mesh_state_json);
    assert!(
        state.contains("ffi-smoke"),
        "the merged key is missing from the state document: {state}"
    );

    // The roster is the `agent-gossip peers` shape: this node alone, counting itself.
    let peers = read_json(handle, habilis_network_mesh_peers_json);
    let parsed: serde_json::Value = serde_json::from_str(&peers).expect("the roster is valid JSON");
    assert_eq!(parsed["count"], 1, "a lone member counts itself: {peers}");
    assert_eq!(
        parsed["peers"].as_array().map(Vec::len),
        Some(0),
        "a lone member has no peers: {peers}"
    );

    // `habilis_network_mesh_peer_count` answers with the same number as the JSON's `count`:
    // a lone member reads 1. A caller waiting for company loops on this one.
    // SAFETY: live handle for the rest of this test.
    let members = unsafe { habilis_network_mesh_peer_count(handle) };
    assert_eq!(
        members,
        1,
        "a lone member counts itself: {:?}",
        last_error()
    );

    // An undersized buffer must report the length it needs and write nothing.
    let mut too_small = [0_u8; 4];
    let too_small_destination: *mut c_char = too_small.as_mut_ptr().cast();
    // SAFETY: live handle, and the buffer really is 4 bytes.
    let needed = unsafe { habilis_network_mesh_state_json(handle, too_small_destination, 4) };
    assert!(
        needed > 4,
        "the state document should not fit in 4 bytes (got {needed})"
    );
    assert_eq!(
        too_small, [0; 4],
        "nothing may be written when the buffer is too small"
    );

    // Nobody else is here, so a receive can only time out.
    let mut message = empty_msg();
    let mut buffer = vec![0_u8; 64];
    let destination: *mut c_char = buffer.as_mut_ptr().cast();
    // SAFETY: live handle, buffer writable for the capacity passed, `out` writable.
    let got = unsafe {
        habilis_network_msg_recv(handle, destination, buffer.len(), 200, &raw mut message)
    };
    assert_eq!(got, 0, "expected a timeout, got {got}: {:?}", last_error());

    // SAFETY: the handle came from `habilis_network_mesh_open` and is not used after this.
    let closed = unsafe { habilis_network_mesh_close(handle) };
    assert_eq!(
        closed,
        0,
        "habilis_network_mesh_close failed: {:?}",
        last_error()
    );
}

/// The mesh name is decoded from the mesh id itself (not gossiped), so a
/// creator's chosen name is already visible through `habilis_network_mesh_name()` on a joiner
/// the instant `habilis_network_mesh_open` returns — no roster wait needed.
#[test]
fn a_joiner_reads_back_the_creators_mesh_name() {
    let creator_nick = CString::new("alice").expect("no interior NUL");
    let creator_name = CString::new("jam-room").expect("no interior NUL");
    let mut create_opts = create_opts(&creator_nick);
    create_opts.name = creator_name.as_ptr();

    let creator = open(&create_opts);
    assert!(
        !creator.is_null(),
        "habilis_network_mesh_open (create) failed: {:?}",
        last_error()
    );

    // SAFETY: `creator` is live for the rest of this test; the returned
    // pointers are borrowed from it and read before it is closed.
    let (id, name) = unsafe {
        (
            habilis_network_mesh_id(creator),
            habilis_network_mesh_name(creator),
        )
    };
    assert!(!id.is_null(), "habilis_network_mesh_id returned NULL");
    assert!(!name.is_null(), "habilis_network_mesh_name returned NULL");
    // SAFETY: both are non-NULL NUL-terminated strings owned by the handle.
    let (id, name) = unsafe { (CStr::from_ptr(id), CStr::from_ptr(name)) };
    assert_eq!(
        name.to_bytes(),
        b"jam-room",
        "the creator's own habilis_network_mesh_name must echo what it asked for"
    );
    let id = id.to_owned();

    let joiner_nick = CString::new("bob").expect("no interior NUL");
    let join_opts = create_opts_for_join(&id, &joiner_nick);
    let joiner = open(&join_opts);
    assert!(
        !joiner.is_null(),
        "habilis_network_mesh_open (join) failed: {:?}",
        last_error()
    );

    // SAFETY: `joiner` is live for the rest of this test.
    let joined_name = unsafe { habilis_network_mesh_name(joiner) };
    assert!(
        !joined_name.is_null(),
        "habilis_network_mesh_name (joiner) returned NULL"
    );
    // SAFETY: non-NULL NUL-terminated string owned by the handle.
    let joined_name = unsafe { CStr::from_ptr(joined_name) };
    assert_eq!(
        joined_name.to_bytes(),
        b"jam-room",
        "a joiner must read back the same mesh name the creator minted"
    );

    // SAFETY: each handle came from `habilis_network_mesh_open` and is not used after this.
    unsafe {
        assert_eq!(
            habilis_network_mesh_close(joiner),
            0,
            "habilis_network_mesh_close (joiner) failed"
        );
        assert_eq!(
            habilis_network_mesh_close(creator),
            0,
            "habilis_network_mesh_close (creator) failed"
        );
    }
}

fn empty_msg() -> HabilisNetworkMsg {
    HabilisNetworkMsg::empty()
}

/// Receive one message into a buffer of `cap` bytes, waiting up to 20 s.
/// Returns the call's result, the metadata, and the text when it was written.
#[cfg(any(feature = "mdns", feature = "dht"))]
fn recv(handle: *mut HabilisNetworkMesh, cap: usize) -> (c_long, HabilisNetworkMsg, String) {
    recv_within(handle, cap, 20_000)
}

/// [`recv`], waiting up to `millis`.
#[cfg(any(feature = "mdns", feature = "dht"))]
fn recv_within(
    handle: *mut HabilisNetworkMesh,
    cap: usize,
    millis: c_int,
) -> (c_long, HabilisNetworkMsg, String) {
    let mut message = empty_msg();
    let mut buffer = vec![0_u8; cap];
    let destination: *mut c_char = buffer.as_mut_ptr().cast();
    // SAFETY: live handle, buffer writable for `cap` bytes, `out` writable.
    let got =
        unsafe { habilis_network_msg_recv(handle, destination, cap, millis, &raw mut message) };
    let text: String = if got == 1 {
        let source: *const c_char = buffer.as_ptr().cast();
        // SAFETY: a result of 1 means `buf` holds a NUL-terminated text.
        unsafe { CStr::from_ptr(source) }
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };
    (got, message, text)
}

#[cfg(any(feature = "mdns", feature = "dht"))]
fn nick_of(message: &HabilisNetworkMsg) -> String {
    // SAFETY: `write_nick` always NUL-terminates inside the array.
    unsafe { CStr::from_ptr(message.nick.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// Two handles on one loopback mesh: a broadcast and a directed message each
/// arrive with their author and their kind, and a buffer too small for a
/// message keeps it queued rather than truncating or dropping it.
#[cfg(any(feature = "mdns", feature = "dht"))]
#[test]
fn two_handles_exchange_messages() {
    let alice_nick = CString::new("alice").expect("no interior NUL");
    let alice = open(&create_opts(&alice_nick));
    assert!(
        !alice.is_null(),
        "habilis_network_mesh_open failed: {:?}",
        last_error()
    );
    // SAFETY: live handle; the id is copied before anything else is called.
    let id = unsafe { CStr::from_ptr(habilis_network_mesh_id(alice)) }.to_owned();
    let bob_nick = CString::new("bob").expect("no interior NUL");
    let bob = open(&create_opts_for_join(&id, &bob_nick));
    assert!(
        !bob.is_null(),
        "habilis_network_mesh_open (join) failed: {:?}",
        last_error()
    );

    let deadline = Instant::now() + Duration::from_secs(45);
    // SAFETY: both handles stay live until the end of the test.
    while unsafe {
        habilis_network_mesh_peer_count(alice) < 2 || habilis_network_mesh_peer_count(bob) < 2
    } {
        assert!(
            Instant::now() < deadline,
            "the two handles never saw each other"
        );
        thread::sleep(Duration::from_millis(200));
    }

    // SAFETY: live handle, NUL-terminated strings.
    let broadcast = unsafe { habilis_network_msg_send(alice, ptr::null(), c"hello mesh".as_ptr()) };
    assert_eq!(broadcast, 0, "broadcast failed: {:?}", last_error());
    let (heard, heard_meta, heard_text) = recv(bob, 256);
    assert_eq!(heard, 1, "bob got no broadcast: {:?}", last_error());
    assert_eq!(
        (
            nick_of(&heard_meta).as_str(),
            heard_meta.directed,
            heard_text.as_str()
        ),
        ("alice", 0, "hello mesh"),
        "bob hears alice's meta message"
    );
    assert_eq!(
        heard_meta.len,
        heard_text.len(),
        "bob's text length matches what was sent"
    );

    let long = "a directed message longer than sixteen bytes";
    let long_c = CString::new(long).expect("no interior NUL");
    // SAFETY: live handle, NUL-terminated strings.
    let directed = unsafe { habilis_network_msg_send(bob, c"alice".as_ptr(), long_c.as_ptr()) };
    assert_eq!(directed, 0, "directed send failed: {:?}", last_error());
    let (short, short_meta, _) = recv(alice, 16);
    assert_eq!(
        short,
        -2,
        "a too-small buffer must report -2: {:?}",
        last_error()
    );
    assert_eq!(
        short_meta.len,
        long.len(),
        "out->len holds the length needed"
    );
    let (retried, retried_meta, retried_text) = recv(alice, short_meta.len + 1);
    assert_eq!(
        retried,
        1,
        "the kept message must come back: {:?}",
        last_error()
    );
    assert_eq!(
        (
            nick_of(&retried_meta).as_str(),
            retried_meta.directed,
            retried_text.as_str()
        ),
        ("bob", 1, long),
        "the retried meta message reaches bob"
    );

    // SAFETY: each handle came from `habilis_network_mesh_open` and is not used after this.
    unsafe {
        assert_eq!(
            habilis_network_mesh_close(bob),
            0,
            "bob's close returns zero"
        );
        assert_eq!(
            habilis_network_mesh_close(alice),
            0,
            "alice's close returns zero"
        );
    }
}

/// Two handles on one loopback mesh, each seeing the other: `(alice, bob)`.
#[cfg(any(feature = "mdns", feature = "dht"))]
fn pair() -> (*mut HabilisNetworkMesh, *mut HabilisNetworkMesh) {
    let alice_nick = CString::new("alice").expect("no interior NUL");
    let alice = open(&create_opts(&alice_nick));
    assert!(!alice.is_null(), "open failed: {:?}", last_error());
    // SAFETY: live handle; the id is copied before anything else is called.
    let id = unsafe { CStr::from_ptr(habilis_network_mesh_id(alice)) }.to_owned();
    let bob_nick = CString::new("bob").expect("no interior NUL");
    let bob = open(&create_opts_for_join(&id, &bob_nick));
    assert!(!bob.is_null(), "open (join) failed: {:?}", last_error());
    let deadline = Instant::now() + Duration::from_secs(45);
    // SAFETY: both handles stay live until the caller closes them.
    while unsafe {
        habilis_network_mesh_peer_count(alice) < 2 || habilis_network_mesh_peer_count(bob) < 2
    } {
        assert!(
            Instant::now() < deadline,
            "the two handles never saw each other"
        );
        thread::sleep(Duration::from_millis(200));
    }
    (alice, bob)
}

/// A receive gives the nickname, the key and the text of a message. The key is 64 lowercase hex
/// digits, the address of a reply.
#[cfg(any(feature = "mdns", feature = "dht"))]
#[test]
fn the_recv_gives_the_nickname_the_key_and_the_text() {
    let (alice, bob) = pair();
    // SAFETY: live handle, NUL-terminated strings.
    let sent = unsafe { habilis_network_msg_send(alice, ptr::null(), c"hello".as_ptr()) };
    assert_eq!(sent, 0, "broadcast failed: {:?}", last_error());

    let (got, meta, text) = recv(bob, 64);
    assert_eq!(got, 1, "the message was lost: {:?}", last_error());
    assert_eq!(
        (nick_of(&meta).as_str(), meta.directed, text.as_str()),
        ("alice", 0, "hello"),
        "the receive does not give the message"
    );
    let key = key_of(&meta);
    assert!(
        key.len() == 64
            && key
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
        "the key is not 64 lowercase hex digits: {key:?}"
    );

    // SAFETY: each handle came from `habilis_network_mesh_open` and is not used after this.
    unsafe {
        assert_eq!(
            habilis_network_mesh_close(bob),
            0,
            "bob's close returns zero"
        );
        assert_eq!(
            habilis_network_mesh_close(alice),
            0,
            "alice's close returns zero"
        );
    }
}

/// A text that does not fit in the buffer gives -2 from the receive. The call writes the
/// length of the text into `out->len` and keeps the message, and the retry with a buffer of
/// `out->len + 1` bytes gets the same message with the same key.
#[cfg(any(feature = "mdns", feature = "dht"))]
#[test]
fn the_recv_reports_a_small_buffer_and_the_retry_gets_the_same_key() {
    let (alice, bob) = pair();
    // SAFETY: live handle, NUL-terminated strings.
    let sent =
        unsafe { habilis_network_msg_send(alice, ptr::null(), c"a text of some length".as_ptr()) };
    assert_eq!(sent, 0, "broadcast failed: {:?}", last_error());

    let (too_small, short_meta, _) = recv_within(bob, 4, 20_000);
    assert_eq!(too_small, -2, "a buffer of 4 bytes was enough");
    assert_eq!(
        short_meta.len,
        "a text of some length".len(),
        "the call does not say how long the text is"
    );

    let (got, meta, text) = recv_within(bob, short_meta.len + 1, 20_000);
    assert_eq!(got, 1, "the retry lost the message: {:?}", last_error());
    assert_eq!(text, "a text of some length", "the retry gets another text");
    assert_eq!(
        key_of(&meta),
        key_of(&short_meta),
        "the retry gets another key"
    );
    assert_eq!(key_of(&meta).len(), 64, "the key is not 64 digits");

    // SAFETY: each handle came from `habilis_network_mesh_open` and is not used after this.
    unsafe {
        assert_eq!(
            habilis_network_mesh_close(bob),
            0,
            "bob's close returns zero"
        );
        assert_eq!(
            habilis_network_mesh_close(alice),
            0,
            "alice's close returns zero"
        );
    }
}

#[cfg(any(feature = "mdns", feature = "dht"))]
fn key_of(message: &HabilisNetworkMsg) -> String {
    // SAFETY: the receive call always NUL-terminates `key` inside the array.
    unsafe { CStr::from_ptr(message.key.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// A send to the key of one of two members, read from the key of its message, reaches that member
/// and not the other. A text that is not a key is an error with a reason.
#[cfg(any(feature = "mdns", feature = "dht"))]
#[test]
fn a_send_to_a_key_reaches_one_of_two_members() {
    let first_nick = CString::new("alpha").expect("no interior NUL");
    let second_nick = CString::new("beta").expect("no interior NUL");
    let first = open(&create_opts(&first_nick));
    assert!(!first.is_null(), "open failed: {:?}", last_error());
    // SAFETY: live handle; the id is copied before anything else is called.
    let id = unsafe { CStr::from_ptr(habilis_network_mesh_id(first)) }.to_owned();
    let second = open(&create_opts_for_join(&id, &second_nick));
    assert!(
        !second.is_null(),
        "open (second) failed: {:?}",
        last_error()
    );
    let sender_nick = CString::new("sender").expect("no interior NUL");
    let sender = open(&create_opts_for_join(&id, &sender_nick));
    assert!(
        !sender.is_null(),
        "open (sender) failed: {:?}",
        last_error()
    );

    let deadline = Instant::now() + Duration::from_secs(45);
    let sees_fewer_than_three = |handle: &*mut HabilisNetworkMesh| {
        // SAFETY: the three handles stay live until the end of the test.
        unsafe { habilis_network_mesh_peer_count(*handle) < 3 }
    };
    while [first, second, sender].iter().any(sees_fewer_than_three) {
        assert!(
            Instant::now() < deadline,
            "the three handles never saw each other"
        );
        thread::sleep(Duration::from_millis(200));
    }

    // Each member broadcasts alone, so the sender reads the key of each one in a known order.
    let mut keys: Vec<String> = Vec::new();
    for (member, name) in [(first, "alpha"), (second, "beta")] {
        // SAFETY: live handle, NUL-terminated strings.
        let sent =
            unsafe { habilis_network_msg_send(member, ptr::null(), c"i am a member".as_ptr()) };
        assert_eq!(sent, 0, "broadcast failed: {:?}", last_error());
        let (got, meta, _) = recv_within(sender, 256, 20_000);
        assert_eq!(got, 1, "the sender heard no member: {:?}", last_error());
        assert_eq!(nick_of(&meta), name, "the message names the nickname");
        keys.push(key_of(&meta));
    }
    assert_eq!(keys[0].len(), 64, "the key of a message is 64 hex digits");
    assert_ne!(keys[0], keys[1], "the two members have two keys");
    // Each member heard the broadcast of the other: drain it, so the next read is the send.
    for member in [first, second] {
        let (got, meta, _) = recv_within(member, 256, 20_000);
        assert_eq!(
            (got, meta.directed),
            (1, 0),
            "a member missed the broadcast of the other"
        );
    }

    let first_key = CString::new(keys[0].as_str()).expect("hex has no NUL");
    // SAFETY: live handle, NUL-terminated strings.
    let by_key = unsafe {
        ffi::habilis_network_msg_send_to_key(sender, first_key.as_ptr(), c"for one".as_ptr())
    };
    assert_eq!(by_key, 0, "send to a key failed: {:?}", last_error());
    let (got, meta, body) = recv_within(first, 256, 20_000);
    assert_eq!(got, 1, "the chosen member got nothing: {:?}", last_error());
    assert_eq!(
        (meta.directed, body.as_str()),
        (1, "for one"),
        "the chosen member gets a directed message"
    );
    let (other, _, _) = recv_within(second, 256, 2_000);
    assert_eq!(other, 0, "the other member got the message of the first");

    // SAFETY: live handles, NUL-terminated strings and NULL where the contract allows it.
    unsafe {
        assert_eq!(
            ffi::habilis_network_msg_send_to_key(sender, c"alpha".as_ptr(), c"x".as_ptr()),
            -1,
            "a nickname was read as a key"
        );
        assert!(
            last_error().is_some_and(|reason| reason.contains("64 lowercase hex")),
            "the refusal does not say what a key is: {:?}",
            last_error()
        );
        assert_eq!(
            ffi::habilis_network_msg_send_to_key(sender, ptr::null(), c"x".as_ptr()),
            -1,
            "a NULL key is an error"
        );
        assert_eq!(
            ffi::habilis_network_msg_send_to_key(
                ptr::null_mut(),
                first_key.as_ptr(),
                c"x".as_ptr()
            ),
            -1,
            "a NULL handle is an error"
        );
        for handle in [sender, second, first] {
            assert_eq!(habilis_network_mesh_close(handle), 0, "close returns zero");
        }
    }
}

/// A nickname that a member key proved names one member. A second member under it, with another
/// member key, is no peer: of three handles, two under one nickname and one observer, each sees
/// one peer besides itself, and not two.
///
/// Only a build that has a member key can bind a nickname: the key exists on a target with files
/// (`unix`) under the engine feature `host`, and both features of this crate (`mdns`, `dht`) turn
/// `host` on. A build without it has no sockets, so no handle sees a peer, and a target with no
/// files sends no proof, so a nickname binds nothing and the three handles can all join.
#[cfg(all(unix, any(feature = "mdns", feature = "dht")))]
#[test]
fn a_second_member_under_a_bound_nickname_is_no_peer() {
    let shared = CString::new("alpha").expect("no interior NUL");
    let first = open(&create_opts(&shared));
    assert!(!first.is_null(), "open failed: {:?}", last_error());
    // SAFETY: live handle; the id is copied before anything else is called.
    let id = unsafe { CStr::from_ptr(habilis_network_mesh_id(first)) }.to_owned();
    let second = open(&create_opts_for_join(&id, &shared));
    let observer_nick = CString::new("gamma").expect("no interior NUL");
    let observer = open(&create_opts_for_join(&id, &observer_nick));
    assert!(
        !second.is_null() && !observer.is_null(),
        "open: {:?}",
        last_error()
    );
    let handles = [first, second, observer];
    // SAFETY: the three handles stay live until the end of the test.
    let counts = || handles.map(|handle| unsafe { habilis_network_mesh_peer_count(handle) });
    let deadline = Instant::now() + Duration::from_secs(45);
    while counts().iter().any(|count| *count < 2) {
        assert!(Instant::now() < deadline, "the handles never saw a peer");
        thread::sleep(Duration::from_millis(200));
    }
    // A second admission would come with the next frames: give it time, then count.
    thread::sleep(Duration::from_secs(6));
    assert_eq!(counts(), [2, 2, 2], "the nickname named two peers");
    for handle in handles {
        // SAFETY: live handle.
        let closed = unsafe { habilis_network_mesh_close(handle) };
        assert_eq!(closed, 0, "close returns zero");
    }
}

/// Zeroed selectors except `mesh`, so [`habilis_network_mesh_open`] joins the given id rather
/// than creating a fresh mesh.
fn create_opts_for_join(id: &CStr, nick: &CStr) -> HabilisNetworkOpts {
    let mut options = HabilisNetworkOpts::empty();
    options.mesh = id.as_ptr();
    options.nick = nick.as_ptr();
    options
}

/// Four peers (creator + 3 joiners) must each see the other three.
/// Regression for rooms that stalled at 3 total participants.
fn four_peers_converge(public: bool) {
    let creator_nick = CString::new("p0").expect("no interior NUL");
    let mut options = create_opts(&creator_nick);
    if public {
        // Match a typical consumer's default create-room lookups.
        options.lookup = c"mdns,dht,relay".as_ptr();
    }
    let creator = open(&options);
    assert!(
        !creator.is_null(),
        "habilis_network_mesh_open (create) failed: {:?}",
        last_error()
    );

    // SAFETY: creator is live until the end of the test.
    let id_ptr = unsafe { habilis_network_mesh_id(creator) };
    assert!(!id_ptr.is_null(), "habilis_network_mesh_id returned NULL");
    // SAFETY: non-NULL NUL-terminated string owned by the handle.
    let id = unsafe { CStr::from_ptr(id_ptr) }.to_owned();

    let joiner_nicks = [
        CString::new("p1").expect("no interior NUL"),
        CString::new("p2").expect("no interior NUL"),
        CString::new("p3").expect("no interior NUL"),
    ];
    let mut handles = vec![creator];
    for nick in &joiner_nicks {
        let handle = open(&create_opts_for_join(&id, nick));
        assert!(
            !handle.is_null(),
            "habilis_network_mesh_open (join {}) failed: {:?}",
            nick.to_string_lossy(),
            last_error()
        );
        handles.push(handle);
    }

    let deadline = Instant::now() + Duration::from_secs(45);
    let mut counts = vec![0_i64; handles.len()];
    let indexed_handles: Vec<(usize, &*mut HabilisNetworkMesh)> =
        handles.iter().enumerate().collect();
    while Instant::now() < deadline {
        for &(index, &handle) in &indexed_handles {
            // SAFETY: each handle came from habilis_network_mesh_open and is still open.
            counts[index] = unsafe { habilis_network_mesh_peer_count(handle) };
        }
        if counts.iter().all(|&count| count == 4) {
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }

    assert!(
        counts.iter().all(|&count| count == 4),
        "expected every member to count 4 members (itself and 3 others) within 45s (public={public}); peer_counts={counts:?}"
    );

    // One member leaves: every member that stays must count 3, so a count that never falls
    // after a departure fails here.
    let leaver = handles.remove(0);
    // SAFETY: the handle came from habilis_network_mesh_open and is not used after this.
    unsafe {
        assert_eq!(
            habilis_network_mesh_close(leaver),
            0,
            "habilis_network_mesh_close failed: {:?}",
            last_error()
        );
    }
    let leave_deadline = Instant::now() + Duration::from_secs(45);
    let mut left_counts = vec![0_i64; handles.len()];
    let staying: Vec<(usize, &*mut HabilisNetworkMesh)> = handles.iter().enumerate().collect();
    while Instant::now() < leave_deadline {
        for &(index, &handle) in &staying {
            // SAFETY: each handle came from habilis_network_mesh_open and is still open.
            left_counts[index] = unsafe { habilis_network_mesh_peer_count(handle) };
        }
        if left_counts.iter().all(|&count| count == 3) {
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }
    assert!(
        left_counts.iter().all(|&count| count == 3),
        "expected every member that stayed to count 3 members after one left within 45s (public={public}); peer_counts={left_counts:?}"
    );

    for handle in handles {
        // SAFETY: each handle came from habilis_network_mesh_open and is not used after this.
        unsafe {
            assert_eq!(
                habilis_network_mesh_close(handle),
                0,
                "habilis_network_mesh_close failed: {:?}",
                last_error()
            );
        }
    }
}

#[cfg(any(feature = "mdns", feature = "dht"))]
#[test]
fn four_peers_converge_on_loopback() {
    four_peers_converge(false);
}

#[test]
#[ignore = "needs the public relay ladder and the mainline DHT; run with --ignored"]
fn four_peers_converge_on_public() {
    four_peers_converge(true);
}

fn loopback_streams() -> *mut HabilisNetworkStreams {
    let options = HabilisNetworkStreamOpts::empty();
    // SAFETY: a fully-initialized struct with NULL strings.
    let streams = unsafe { habilis_network_streams_bind(&raw const options) };
    assert!(
        !streams.is_null(),
        "habilis_network_streams_bind failed: {:?}",
        last_error()
    );
    streams
}

/// Create → write → read over two loopback nodes, with a read buffer smaller
/// than the stream so the remainder must wait for the next read, and the end
/// of stream reported as -2.
#[test]
fn a_stream_carries_bytes_to_its_one_reader() {
    let (producing, consuming) = (loopback_streams(), loopback_streams());
    // SAFETY: live node handles for the rest of this test.
    let producer = unsafe { habilis_network_stream_create(producing) };
    assert!(
        !producer.is_null(),
        "habilis_network_stream_create failed: {:?}",
        last_error()
    );
    // SAFETY: live producer; the hash is copied before the producer moves.
    let hash = unsafe { CStr::from_ptr(habilis_network_stream_hash(producer)) }.to_owned();

    let sent: Vec<u8> = (0..100_000_u32).map(|index| (index % 251) as u8).collect();
    let producer_addr = producer as usize;
    let payload = sent.clone();
    let writer = thread::spawn(move || {
        let owned = producer_addr as *mut HabilisNetworkProducer;
        // SAFETY: the producer is used by this thread alone from here on.
        unsafe {
            let wrote =
                habilis_network_stream_write(owned, payload.as_ptr(), payload.len(), 30_000);
            assert_eq!(
                wrote,
                1,
                "habilis_network_stream_write failed: {:?}",
                last_error()
            );
            assert_eq!(
                habilis_network_stream_close(owned),
                0,
                "close failed: {:?}",
                last_error()
            );
        }
    });

    // SAFETY: live node, NUL-terminated hash.
    let reader = unsafe { habilis_network_stream_open(consuming, hash.as_ptr()) };
    assert!(
        !reader.is_null(),
        "habilis_network_stream_open failed: {:?}",
        last_error()
    );
    let mut got = Vec::new();
    let mut small = [0_u8; 1000];
    loop {
        // SAFETY: live reader, buffer writable for its length.
        let read =
            unsafe { habilis_network_stream_read(reader, small.as_mut_ptr(), small.len(), 10_000) };
        match read {
            -2 => break,
            read if read > 0 => {
                got.extend_from_slice(&small[..usize::try_from(read).expect("positive")]);
            }
            other => panic!("read returned {other}: {:?}", last_error()),
        }
    }
    writer.join().expect("writer thread");
    assert!(
        got == sent,
        "the bytes differ ({} of {})",
        got.len(),
        sent.len()
    );

    // SAFETY: each handle is released once and not used after.
    unsafe {
        assert_eq!(
            habilis_network_reader_close(reader),
            0,
            "the reader closes with zero"
        );
        assert_eq!(
            habilis_network_streams_close(consuming),
            0,
            "the consuming stream closes with zero"
        );
        assert_eq!(
            habilis_network_streams_close(producing),
            0,
            "the producing stream closes with zero"
        );
    }
}

#[test]
fn a_write_with_no_consumer_times_out_and_a_wrong_hash_is_refused() {
    let streams = loopback_streams();
    // SAFETY: live node for the rest of this test.
    let producer = unsafe { habilis_network_stream_create(streams) };
    // SAFETY: live producer; one byte from a live array.
    let wrote = unsafe { habilis_network_stream_write(producer, [7_u8].as_ptr(), 1, 200) };
    assert_eq!(wrote, 0, "no consumer means a timeout: {:?}", last_error());

    // SAFETY: live node, NUL-terminated string that is not a hash.
    let reader = unsafe { habilis_network_stream_open(streams, c"not-a-hash".as_ptr()) };
    assert!(reader.is_null(), "a malformed hash must not open");
    assert!(last_error().is_some(), "a refused open leaves a reason");

    // SAFETY: each handle is released once and not used after.
    unsafe {
        assert_eq!(
            habilis_network_stream_close(producer),
            0,
            "abandoning is not a failure"
        );
        assert_eq!(
            habilis_network_streams_close(streams),
            0,
            "a write with no consumer times out and a wrong hash is refused"
        );
    }
}
