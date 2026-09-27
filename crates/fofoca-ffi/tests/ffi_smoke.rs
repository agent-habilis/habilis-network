//! The C ABI, driven from Rust through the crate's `rlib`.
//!
//! Every assertion here is about the *boundary* rather than the mesh: NULL
//! handling, the error slot, the length-then-fill buffer convention. It needs no
//! C compiler, so the contract stays covered on any host.
#![expect(
    unsafe_code,
    reason = "the surface under test is `unsafe extern \"C\"`; calling it is the test"
)]

use std::ffi::{CStr, CString, c_char, c_long};
use std::thread;
use std::time::{Duration, Instant};

use fofoca_ffi::ffi::{
    FofocaMesh, FofocaMsg, FofocaOpts, FofocaProducer, FofocaStreamOpts, FofocaStreams,
    fofoca_last_error, fofoca_max_msg, fofoca_mesh_close, fofoca_mesh_id, fofoca_mesh_name,
    fofoca_mesh_nickname, fofoca_mesh_open, fofoca_mesh_peer_count, fofoca_mesh_peers_json,
    fofoca_mesh_state_json, fofoca_mesh_state_merge, fofoca_msg_recv, fofoca_msg_send,
    fofoca_reader_close, fofoca_stream_close, fofoca_stream_create, fofoca_stream_hash,
    fofoca_stream_open, fofoca_stream_read, fofoca_stream_write, fofoca_streams_bind,
    fofoca_streams_close, fofoca_version,
};

/// Zeroed selectors: no id and no topic, so [`fofoca_mesh_open`] mints a private
/// loopback mesh — no discovery, no network, nothing to clean up but the handle.
fn create_opts(nick: &CStr) -> FofocaOpts {
    FofocaOpts {
        mesh: std::ptr::null(),
        topic: std::ptr::null(),
        nick: nick.as_ptr(),
        name: std::ptr::null(),
        lookup: std::ptr::null(),
        transport: std::ptr::null(),
        relay_urls: std::ptr::null(),
        disable_ip: 0,
        disable_webrtc: 0,
        max_peers: 0,
    }
}

/// The error slot's current contents, as an owned string.
fn last_error() -> Option<String> {
    let ptr = fofoca_last_error();
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

fn open(opts: &FofocaOpts) -> *mut FofocaMesh {
    // SAFETY: `opts` is a live, fully-initialized `FofocaOpts` whose string fields
    // are NULL or point at `CStr`s that outlive the call.
    unsafe { fofoca_mesh_open(opts) }
}

/// Read a JSON document out through the two-call convention: ask for the length,
/// then fill a buffer of that size.
fn read_json(
    handle: *mut FofocaMesh,
    reader: unsafe extern "C" fn(*mut FofocaMesh, *mut c_char, usize) -> c_long,
) -> String {
    // SAFETY: a NULL buffer with a zero capacity is the documented "how long is
    // it?" query — the callee writes nothing.
    let needed = unsafe { reader(handle, std::ptr::null_mut(), 0) };
    assert!(needed >= 0, "length query failed: {:?}", last_error());
    let mut buf = vec![0_u8; usize::try_from(needed).expect("a sane length") + 1];
    // SAFETY: the buffer is writable for exactly the capacity being passed.
    let written = unsafe { reader(handle, buf.as_mut_ptr().cast::<c_char>(), buf.len()) };
    assert_eq!(written, needed, "the second call must agree on the length");
    buf.truncate(usize::try_from(written).expect("a sane length"));
    String::from_utf8(buf).expect("the document is UTF-8")
}

#[test]
fn version_and_max_msg_are_reported() {
    let version = fofoca_version();
    assert!(!version.is_null(), "fofoca_version returned NULL");
    // SAFETY: non-NULL, and the pointer is valid for the process's lifetime.
    let version = unsafe { CStr::from_ptr(version) };
    assert!(
        !version.to_bytes().is_empty(),
        "the version stamp is empty: {version:?}"
    );
    assert!(
        fofoca_max_msg() > 0,
        "a message must carry at least one byte of text"
    );
}

#[test]
fn a_bad_mesh_id_fails_with_a_reason() {
    let nick = CString::new("solo").expect("no interior NUL");
    let bogus = CString::new("not-a-mesh-id").expect("no interior NUL");
    let mut opts = create_opts(&nick);
    opts.mesh = bogus.as_ptr();

    let handle = open(&opts);
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
        assert!(fofoca_mesh_open(std::ptr::null()).is_null());
        assert!(
            last_error().is_some(),
            "fofoca_mesh_open(NULL) left no reason"
        );

        assert_eq!(
            fofoca_msg_send(std::ptr::null_mut(), std::ptr::null(), c"hi".as_ptr()),
            -1
        );
        assert!(
            last_error().is_some(),
            "fofoca_msg_send(NULL) left no reason"
        );

        assert_eq!(
            fofoca_mesh_state_merge(std::ptr::null_mut(), std::ptr::null()),
            -1
        );
        assert!(
            last_error().is_some(),
            "fofoca_mesh_state_merge(NULL) left no reason"
        );

        assert_eq!(
            fofoca_mesh_state_json(std::ptr::null_mut(), std::ptr::null_mut(), 0),
            -1
        );
        assert!(
            last_error().is_some(),
            "fofoca_mesh_state_json(NULL) left no reason"
        );

        assert_eq!(fofoca_mesh_peer_count(std::ptr::null_mut()), -1);
        assert!(
            last_error().is_some(),
            "fofoca_mesh_peer_count(NULL) left no reason"
        );

        assert!(fofoca_mesh_id(std::ptr::null()).is_null());
        assert!(fofoca_mesh_name(std::ptr::null()).is_null());
        assert!(fofoca_mesh_nickname(std::ptr::null()).is_null());

        // Closing NULL is a no-op success, so a caller's cleanup path needs no
        // guard of its own — and succeeding clears the slot.
        assert_eq!(fofoca_mesh_close(std::ptr::null_mut()), 0);
        assert!(
            last_error().is_none(),
            "a successful call must clear the error slot"
        );
    }
}

#[test]
fn a_handle_serves_identity_state_and_roster() {
    let nick = CString::new("solo").expect("no interior NUL");
    let opts = create_opts(&nick);
    let handle = open(&opts);
    assert!(
        !handle.is_null(),
        "fofoca_mesh_open failed: {:?}",
        last_error()
    );

    // SAFETY: `handle` is live for the rest of this test; the returned pointers
    // are borrowed from it and read before it is closed.
    let (id, mine) = unsafe { (fofoca_mesh_id(handle), fofoca_mesh_nickname(handle)) };
    assert!(!id.is_null() && !mine.is_null());
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
    let merged = unsafe { fofoca_mesh_state_merge(handle, merge.as_ptr()) };
    assert_eq!(merged, 0, "state_merge failed: {:?}", last_error());
    let state = read_json(handle, fofoca_mesh_state_json);
    assert!(
        state.contains("ffi-smoke"),
        "the merged key is missing from the state document: {state}"
    );

    // The roster is the `agent-gossip peers` shape: this node alone, counting itself.
    let peers = read_json(handle, fofoca_mesh_peers_json);
    let parsed: serde_json::Value = serde_json::from_str(&peers).expect("the roster is valid JSON");
    assert_eq!(parsed["count"], 1, "a lone member counts itself: {peers}");
    assert_eq!(
        parsed["peers"].as_array().map(Vec::len),
        Some(0),
        "a lone member has no peers: {peers}"
    );

    // `fofoca_mesh_peer_count` deliberately answers the other question — how many
    // *others* — so a lone member reads 0 where the JSON's `count` reads 1. A
    // caller waiting for company loops on this one.
    // SAFETY: live handle for the rest of this test.
    let others = unsafe { fofoca_mesh_peer_count(handle) };
    assert_eq!(
        others,
        0,
        "a lone member has no peers but itself: {:?}",
        last_error()
    );

    // An undersized buffer must report the length it needs and write nothing.
    let mut too_small = [0_u8; 4];
    // SAFETY: live handle, and the buffer really is 4 bytes.
    let needed =
        unsafe { fofoca_mesh_state_json(handle, too_small.as_mut_ptr().cast::<c_char>(), 4) };
    assert!(
        needed > 4,
        "the state document should not fit in 4 bytes (got {needed})"
    );
    assert_eq!(
        too_small, [0; 4],
        "nothing may be written when the buffer is too small"
    );

    // Nobody else is here, so a receive can only time out.
    let mut msg = empty_msg();
    let mut buf = vec![0_u8; 64];
    // SAFETY: live handle, buffer writable for the capacity passed, `out` writable.
    let got = unsafe {
        fofoca_msg_recv(
            handle,
            buf.as_mut_ptr().cast::<c_char>(),
            buf.len(),
            200,
            &raw mut msg,
        )
    };
    assert_eq!(got, 0, "expected a timeout, got {got}: {:?}", last_error());

    // SAFETY: the handle came from `fofoca_mesh_open` and is not used after this.
    let closed = unsafe { fofoca_mesh_close(handle) };
    assert_eq!(closed, 0, "fofoca_mesh_close failed: {:?}", last_error());
}

/// The mesh name is decoded from the mesh id itself (not gossiped), so a
/// creator's chosen name is already visible through `fofoca_mesh_name()` on a joiner
/// the instant `fofoca_mesh_open` returns — no roster wait needed.
#[test]
fn a_joiner_reads_back_the_creators_mesh_name() {
    let creator_nick = CString::new("alice").expect("no interior NUL");
    let creator_name = CString::new("jam-room").expect("no interior NUL");
    let mut create_opts = create_opts(&creator_nick);
    create_opts.name = creator_name.as_ptr();

    let creator = open(&create_opts);
    assert!(
        !creator.is_null(),
        "fofoca_mesh_open (create) failed: {:?}",
        last_error()
    );

    // SAFETY: `creator` is live for the rest of this test; the returned
    // pointers are borrowed from it and read before it is closed.
    let (id, name) = unsafe { (fofoca_mesh_id(creator), fofoca_mesh_name(creator)) };
    assert!(!id.is_null(), "fofoca_mesh_id returned NULL");
    assert!(!name.is_null(), "fofoca_mesh_name returned NULL");
    // SAFETY: both are non-NULL NUL-terminated strings owned by the handle.
    let (id, name) = unsafe { (CStr::from_ptr(id), CStr::from_ptr(name)) };
    assert_eq!(
        name.to_bytes(),
        b"jam-room",
        "the creator's own fofoca_mesh_name must echo what it asked for"
    );
    let id = id.to_owned();

    let joiner_nick = CString::new("bob").expect("no interior NUL");
    let join_opts = create_opts_for_join(&id, &joiner_nick);
    let joiner = open(&join_opts);
    assert!(
        !joiner.is_null(),
        "fofoca_mesh_open (join) failed: {:?}",
        last_error()
    );

    // SAFETY: `joiner` is live for the rest of this test.
    let joined_name = unsafe { fofoca_mesh_name(joiner) };
    assert!(
        !joined_name.is_null(),
        "fofoca_mesh_name (joiner) returned NULL"
    );
    // SAFETY: non-NULL NUL-terminated string owned by the handle.
    let joined_name = unsafe { CStr::from_ptr(joined_name) };
    assert_eq!(
        joined_name.to_bytes(),
        b"jam-room",
        "a joiner must read back the same mesh name the creator minted"
    );

    // SAFETY: each handle came from `fofoca_mesh_open` and is not used after this.
    unsafe {
        assert_eq!(
            fofoca_mesh_close(joiner),
            0,
            "fofoca_mesh_close (joiner) failed"
        );
        assert_eq!(
            fofoca_mesh_close(creator),
            0,
            "fofoca_mesh_close (creator) failed"
        );
    }
}

fn empty_msg() -> FofocaMsg {
    FofocaMsg {
        nick: [0; 64],
        directed: 0,
        len: 0,
    }
}

/// Receive one message into a buffer of `cap` bytes, waiting up to 20 s.
/// Returns the call's result, the metadata, and the text when it was written.
fn recv(handle: *mut FofocaMesh, cap: usize) -> (c_long, FofocaMsg, String) {
    let mut msg = empty_msg();
    let mut buf = vec![0_u8; cap];
    // SAFETY: live handle, buffer writable for `cap` bytes, `out` writable.
    let got = unsafe {
        fofoca_msg_recv(
            handle,
            buf.as_mut_ptr().cast::<c_char>(),
            cap,
            20_000,
            &raw mut msg,
        )
    };
    let text = if got == 1 {
        // SAFETY: a result of 1 means `buf` holds a NUL-terminated text.
        unsafe { CStr::from_ptr(buf.as_ptr().cast::<c_char>()) }
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };
    (got, msg, text)
}

fn nick_of(msg: &FofocaMsg) -> String {
    // SAFETY: `write_nick` always NUL-terminates inside the array.
    unsafe { CStr::from_ptr(msg.nick.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// Two handles on one loopback mesh: a broadcast and a directed message each
/// arrive with their author and their kind, and a buffer too small for a
/// message keeps it queued rather than truncating or dropping it.
#[test]
fn two_handles_exchange_messages() {
    let alice_nick = CString::new("alice").expect("no interior NUL");
    let alice = open(&create_opts(&alice_nick));
    assert!(
        !alice.is_null(),
        "fofoca_mesh_open failed: {:?}",
        last_error()
    );
    // SAFETY: live handle; the id is copied before anything else is called.
    let id = unsafe { CStr::from_ptr(fofoca_mesh_id(alice)) }.to_owned();
    let bob_nick = CString::new("bob").expect("no interior NUL");
    let bob = open(&create_opts_for_join(&id, &bob_nick));
    assert!(
        !bob.is_null(),
        "fofoca_mesh_open (join) failed: {:?}",
        last_error()
    );

    let deadline = Instant::now() + Duration::from_secs(45);
    // SAFETY: both handles stay live until the end of the test.
    while unsafe { fofoca_mesh_peer_count(alice) < 1 || fofoca_mesh_peer_count(bob) < 1 } {
        assert!(
            Instant::now() < deadline,
            "the two handles never saw each other"
        );
        thread::sleep(Duration::from_millis(200));
    }

    // SAFETY: live handle, NUL-terminated strings.
    let broadcast = unsafe { fofoca_msg_send(alice, std::ptr::null(), c"hello mesh".as_ptr()) };
    assert_eq!(broadcast, 0, "broadcast failed: {:?}", last_error());
    let (heard, heard_meta, heard_text) = recv(bob, 256);
    assert_eq!(heard, 1, "bob got no broadcast: {:?}", last_error());
    assert_eq!(
        (
            nick_of(&heard_meta).as_str(),
            heard_meta.directed,
            heard_text.as_str()
        ),
        ("alice", 0, "hello mesh")
    );
    assert_eq!(heard_meta.len, heard_text.len());

    let long = "a directed message longer than sixteen bytes";
    let long_c = CString::new(long).expect("no interior NUL");
    // SAFETY: live handle, NUL-terminated strings.
    let directed = unsafe { fofoca_msg_send(bob, c"alice".as_ptr(), long_c.as_ptr()) };
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
        ("bob", 1, long)
    );

    // SAFETY: each handle came from `fofoca_mesh_open` and is not used after this.
    unsafe {
        assert_eq!(fofoca_mesh_close(bob), 0);
        assert_eq!(fofoca_mesh_close(alice), 0);
    }
}

/// Zeroed selectors except `mesh`, so [`fofoca_mesh_open`] joins the given id rather
/// than creating a fresh mesh.
fn create_opts_for_join(id: &CStr, nick: &CStr) -> FofocaOpts {
    FofocaOpts {
        mesh: id.as_ptr(),
        topic: std::ptr::null(),
        nick: nick.as_ptr(),
        name: std::ptr::null(),
        lookup: std::ptr::null(),
        transport: std::ptr::null(),
        relay_urls: std::ptr::null(),
        disable_ip: 0,
        disable_webrtc: 0,
        max_peers: 0,
    }
}

/// Four peers (creator + 3 joiners) must each see the other three.
/// Regression for rooms that stalled at 3 total participants.
fn four_peers_converge(public: bool) {
    let creator_nick = CString::new("p0").expect("no interior NUL");
    let mut opts = create_opts(&creator_nick);
    if public {
        // Match mallorca's default create-room lookups.
        opts.lookup = c"mdns,dht,relay".as_ptr();
    }
    let creator = open(&opts);
    assert!(
        !creator.is_null(),
        "fofoca_mesh_open (create) failed: {:?}",
        last_error()
    );

    // SAFETY: creator is live until the end of the test.
    let id_ptr = unsafe { fofoca_mesh_id(creator) };
    assert!(!id_ptr.is_null(), "fofoca_mesh_id returned NULL");
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
            "fofoca_mesh_open (join {}) failed: {:?}",
            nick.to_string_lossy(),
            last_error()
        );
        handles.push(handle);
    }

    let deadline = Instant::now() + Duration::from_secs(45);
    let mut counts = vec![0_i64; handles.len()];
    while Instant::now() < deadline {
        for (idx, &handle) in handles.iter().enumerate() {
            // SAFETY: each handle came from fofoca_mesh_open and is still open.
            counts[idx] = unsafe { fofoca_mesh_peer_count(handle) };
        }
        if counts.iter().all(|&count| count >= 3) {
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }

    assert!(
        counts.iter().all(|&count| count >= 3),
        "expected every peer to see ≥3 others within 45s (public={public}); peer_counts={counts:?}"
    );

    // SAFETY: each handle came from fofoca_mesh_open and is not used after this.
    for handle in handles {
        unsafe {
            assert_eq!(
                fofoca_mesh_close(handle),
                0,
                "fofoca_mesh_close failed: {:?}",
                last_error()
            );
        }
    }
}

#[test]
fn four_peers_converge_on_loopback() {
    four_peers_converge(false);
}

#[test]
fn four_peers_converge_on_public() {
    four_peers_converge(true);
}

fn loopback_streams() -> *mut FofocaStreams {
    let opts = FofocaStreamOpts {
        lookup: std::ptr::null(),
        transport: std::ptr::null(),
        relay_urls: std::ptr::null(),
        disable_ip: 0,
        disable_webrtc: 0,
    };
    // SAFETY: a fully-initialized struct with NULL strings.
    let streams = unsafe { fofoca_streams_bind(&raw const opts) };
    assert!(
        !streams.is_null(),
        "fofoca_streams_bind failed: {:?}",
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
    let producer = unsafe { fofoca_stream_create(producing) };
    assert!(
        !producer.is_null(),
        "fofoca_stream_create failed: {:?}",
        last_error()
    );
    // SAFETY: live producer; the hash is copied before the producer moves.
    let hash = unsafe { CStr::from_ptr(fofoca_stream_hash(producer)) }.to_owned();

    let sent: Vec<u8> = (0..100_000_u32).map(|index| (index % 251) as u8).collect();
    let producer_addr = producer as usize;
    let payload = sent.clone();
    let writer = thread::spawn(move || {
        let owned = producer_addr as *mut FofocaProducer;
        // SAFETY: the producer is used by this thread alone from here on.
        unsafe {
            let wrote = fofoca_stream_write(owned, payload.as_ptr(), payload.len(), 30_000);
            assert_eq!(wrote, 1, "fofoca_stream_write failed: {:?}", last_error());
            assert_eq!(
                fofoca_stream_close(owned),
                0,
                "close failed: {:?}",
                last_error()
            );
        }
    });

    // SAFETY: live node, NUL-terminated hash.
    let reader = unsafe { fofoca_stream_open(consuming, hash.as_ptr()) };
    assert!(
        !reader.is_null(),
        "fofoca_stream_open failed: {:?}",
        last_error()
    );
    let mut got = Vec::new();
    let mut small = [0_u8; 1000];
    loop {
        // SAFETY: live reader, buffer writable for its length.
        let read = unsafe { fofoca_stream_read(reader, small.as_mut_ptr(), small.len(), 10_000) };
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
        assert_eq!(fofoca_reader_close(reader), 0);
        assert_eq!(fofoca_streams_close(consuming), 0);
        assert_eq!(fofoca_streams_close(producing), 0);
    }
}

#[test]
fn a_write_with_no_consumer_times_out_and_a_wrong_hash_is_refused() {
    let streams = loopback_streams();
    // SAFETY: live node for the rest of this test.
    let producer = unsafe { fofoca_stream_create(streams) };
    // SAFETY: live producer; one byte from a live array.
    let wrote = unsafe { fofoca_stream_write(producer, [7_u8].as_ptr(), 1, 200) };
    assert_eq!(wrote, 0, "no consumer means a timeout: {:?}", last_error());

    // SAFETY: live node, NUL-terminated string that is not a hash.
    let reader = unsafe { fofoca_stream_open(streams, c"not-a-hash".as_ptr()) };
    assert!(reader.is_null(), "a malformed hash must not open");
    assert!(last_error().is_some(), "a refused open leaves a reason");

    // SAFETY: each handle is released once and not used after.
    unsafe {
        assert_eq!(
            fofoca_stream_close(producer),
            0,
            "abandoning is not a failure"
        );
        assert_eq!(fofoca_streams_close(streams), 0);
    }
}
