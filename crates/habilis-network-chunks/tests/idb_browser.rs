//! The browser backend, in a real browser.
//!
//! `IndexedDB` needs a browser, so this cannot ride the native conformance
//! suite — but it is held to the same contract, and the cases below are
//! transcribed from it rather than invented. The predecessor crate shipped its
//! `IndexedDB` backend with **no test coverage at all**, which is exactly the
//! sort of gap that only shows up as a user losing a download.
//!
//! Run with:
//!
//! ```text
//! wasm-pack test --headless --chrome crates/habilis-network-chunks
//! wasm-pack test --headless --safari crates/habilis-network-chunks
//! ```

#![cfg(target_arch = "wasm32")]

use habilis_network_chunks::{
    CHUNK_BYTES_USIZE, ChunkHash, ChunkMap, ChunkSource, ChunkStore, Coverage, FileId, chunk_hash,
    idb::IdbStore,
};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| {
            u8::try_from(index % 251)
                .unwrap_or(0)
                .wrapping_mul(31)
                .wrapping_add(seed)
        })
        .collect()
}

/// A database nothing else touches.
///
/// Every case gets its own, because `IndexedDB` outlives the test that made it
/// and a shared database would let one case's leftovers satisfy another's
/// assertions.
async fn fresh(tag: &str) -> IdbStore {
    // A counter rather than a clock: two cases in the same millisecond would
    // otherwise collide, and the failure would look like a flake.
    use core::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    IdbStore::open(&format!("habilis-network-chunks-test-{tag}-{unique}"))
        .await
        .expect("IndexedDB is available")
}

#[wasm_bindgen_test]
async fn round_trip() {
    let store = fresh("round-trip").await;
    let chunk = body(CHUNK_BYTES_USIZE, 1);
    let hash = chunk_hash(&chunk);

    assert!(!store.has(hash).await.expect("has"));
    assert_eq!(store.get(hash).await.expect("get"), None);

    store.put(hash, &chunk).await.expect("put");
    assert!(store.has(hash).await.expect("has"));
    assert_eq!(store.get(hash).await.expect("get"), Some(chunk));
}

/// The rule that matters most, and the one a browser is least likely to get
/// right by accident: bytes that address something else are refused, and
/// nothing is written.
#[wasm_bindgen_test]
async fn a_lying_chunk_is_refused_and_stores_nothing() {
    let store = fresh("lying").await;
    let honest = body(1024, 2);
    let hash = chunk_hash(&honest);

    assert!(store.put(hash, &body(1024, 3)).await.is_err());
    assert!(!store.has(hash).await.expect("has"));

    store.put(hash, &honest).await.expect("put");
    assert_eq!(store.get(hash).await.expect("get"), Some(honest));
}

#[wasm_bindgen_test]
async fn a_one_bit_difference_is_caught() {
    let store = fresh("one-bit").await;
    let chunk = body(1024, 4);
    let mut wrong = *chunk_hash(&chunk).as_bytes();
    wrong[31] ^= 1;
    assert!(
        store
            .put(ChunkHash::from_bytes(wrong), &chunk)
            .await
            .is_err()
    );
}

#[wasm_bindgen_test]
async fn maps_round_trip() {
    let store = fresh("maps").await;
    let map = ChunkMap::build(&body(CHUNK_BYTES_USIZE * 2 + 7, 5));
    assert_eq!(store.map(map.root()).await.expect("map"), None);
    store.put_map(&map).await.expect("put_map");
    assert_eq!(store.map(map.root()).await.expect("map"), Some(map));
}

/// Partial holdings are first-class: coverage grows chunk by chunk, and a tab
/// that stopped halfway still helps everyone else.
#[wasm_bindgen_test]
async fn coverage_grows_chunk_by_chunk() {
    let store = fresh("coverage").await;
    let bytes = body(CHUNK_BYTES_USIZE * 4, 6);
    let map = ChunkMap::build(&bytes);
    store.put_map(&map).await.expect("put_map");
    assert_eq!(store.coverage(map.root()).await.expect("cov").count(), 0);

    // Out of order, the way a swarm delivers.
    for index in [2usize, 0, 3, 1] {
        let range = map.range_of(index);
        let start = usize::try_from(range.start).expect("fits");
        let end = usize::try_from(range.end).expect("fits");
        store
            .put(map.leaf(index).expect("in range"), &bytes[start..end])
            .await
            .expect("put");
        assert!(
            store
                .coverage(map.root())
                .await
                .expect("cov")
                .contains(index)
        );
    }
    assert!(store.coverage(map.root()).await.expect("cov").is_complete());
}

/// **The case only a real browser can fail.**
///
/// `coverage` probes one root's leaves and `coverage_of` enumerates the keyspace
/// once, and both of them issue every request before awaiting any — because an
/// `IndexedDB` transaction goes inactive the moment control returns to the event
/// loop with nothing outstanding, and because a request that completes before
/// its `onsuccess` is attached never fires it. Get either wrong and this hangs
/// or raises `TransactionInactiveError`; nothing on the host can tell.
///
/// Several roots and several chunks each, since a single-request answer would
/// pass whatever the transaction handling did.
#[wasm_bindgen_test]
async fn coverage_of_answers_many_roots_in_one_pass() {
    let store = fresh("coverage-of").await;
    let whole = body(CHUNK_BYTES_USIZE * 3, 41);
    let partial = body(CHUNK_BYTES_USIZE * 4, 42);
    let untouched = body(CHUNK_BYTES_USIZE * 2, 43);

    let whole_map = ChunkMap::build(&whole);
    let partial_map = ChunkMap::build(&partial);
    let untouched_map = ChunkMap::build(&untouched);
    for map in [&whole_map, &partial_map, &untouched_map] {
        store.put_map(map).await.expect("put_map");
    }

    for index in 0..whole_map.len() {
        let range = whole_map.range_of(index);
        let start = usize::try_from(range.start).expect("fits");
        let end = usize::try_from(range.end).expect("fits");
        store
            .put(whole_map.leaf(index).expect("in range"), &whole[start..end])
            .await
            .expect("put");
    }
    // One chunk in the middle: a hole, not a prefix.
    let range = partial_map.range_of(2);
    let start = usize::try_from(range.start).expect("fits");
    let end = usize::try_from(range.end).expect("fits");
    store
        .put(partial_map.leaf(2).expect("in range"), &partial[start..end])
        .await
        .expect("put");

    let roots = [whole_map.root(), partial_map.root(), untouched_map.root()];
    let batched = store.coverage_of(&roots).await.expect("coverage_of");
    assert_eq!(batched.len(), 3, "one answer per root, in order");
    assert!(batched[0].is_complete());
    assert_eq!(batched[1].count(), 1);
    assert!(batched[1].contains(2));
    assert_eq!(batched[2].count(), 0);

    // And the two routes to the same answer agree, which is the contract the
    // host suite states and only this can check for `IdbStore`.
    for (root, batch) in roots.iter().zip(&batched) {
        let single = store.coverage(*root).await.expect("coverage");
        assert_eq!(batch.as_bits(), single.as_bits(), "routes disagreed");
        assert_eq!(batch.len(), single.len());
    }
}

/// A root the store never saw keeps its slot rather than being dropped, or
/// every later answer slides onto the wrong file.
#[wasm_bindgen_test]
async fn coverage_of_keeps_its_place_for_an_unknown_root() {
    let store = fresh("coverage-of-unknown").await;
    let known = body(CHUNK_BYTES_USIZE, 44);
    let map = ChunkMap::build(&known);
    store.put_map(&map).await.expect("put_map");
    store
        .put(map.leaf(0).expect("in range"), &known)
        .await
        .expect("put");

    let stranger = ChunkMap::build(&body(4096, 45)).root();
    let coverages = store
        .coverage_of(&[stranger, map.root()])
        .await
        .expect("coverage_of");
    assert_eq!(coverages.len(), 2);
    assert_eq!(coverages[0].count(), 0);
    assert!(coverages[1].is_complete());

    assert!(
        store.coverage_of(&[]).await.expect("empty").is_empty(),
        "asking about nothing is not an error"
    );
}

/// Dedup, in the browser: two files sharing a chunk store it once, and the
/// second file is partly held without ever being fetched.
#[wasm_bindgen_test]
async fn a_shared_chunk_covers_both_files() {
    let store = fresh("shared").await;
    let shared = body(CHUNK_BYTES_USIZE, 42);
    let mut first = shared.clone();
    first.extend_from_slice(&body(CHUNK_BYTES_USIZE, 7));
    let mut second = body(CHUNK_BYTES_USIZE, 8);
    second.extend_from_slice(&shared);

    let first_map = ChunkMap::build(&first);
    let second_map = ChunkMap::build(&second);
    store.put_map(&first_map).await.expect("put_map");
    store.put_map(&second_map).await.expect("put_map");

    for index in 0..first_map.len() {
        let range = first_map.range_of(index);
        let start = usize::try_from(range.start).expect("fits");
        let end = usize::try_from(range.end).expect("fits");
        store
            .put(first_map.leaf(index).expect("in range"), &first[start..end])
            .await
            .expect("put");
    }

    let coverage = store.coverage(second_map.root()).await.expect("cov");
    assert!(coverage.contains(1), "the shared chunk counts for both");
    assert!(!coverage.contains(0));
}

#[wasm_bindgen_test]
async fn stored_chunks_still_verify_against_their_map() {
    let store = fresh("verify").await;
    let bytes = body(CHUNK_BYTES_USIZE * 3 + 13, 9);
    let map = ChunkMap::build(&bytes);
    store.put_map(&map).await.expect("put_map");
    for index in 0..map.len() {
        let range = map.range_of(index);
        let start = usize::try_from(range.start).expect("fits");
        let end = usize::try_from(range.end).expect("fits");
        store
            .put(map.leaf(index).expect("in range"), &bytes[start..end])
            .await
            .expect("put");
    }

    let mut rebuilt = Vec::new();
    for index in 0..map.len() {
        let chunk = store
            .get(map.leaf(index).expect("in range"))
            .await
            .expect("get")
            .expect("held");
        assert!(map.verify(index, &chunk));
        rebuilt.extend_from_slice(&chunk);
    }
    assert_eq!(rebuilt, bytes);
}

#[wasm_bindgen_test]
async fn a_sweep_keeps_marked_and_drops_the_rest() {
    let store = fresh("sweep").await;
    let kept_bytes = body(1024, 10);
    let kept = ChunkMap::build(&kept_bytes);
    let junk_bytes = body(1024, 11);
    let junk = ChunkMap::build(&junk_bytes);

    store.put_map(&kept).await.expect("put_map");
    store.put_map(&junk).await.expect("put_map");
    store
        .put(kept.leaf(0).expect("one"), &kept_bytes)
        .await
        .expect("put");
    store
        .put(junk.leaf(0).expect("one"), &junk_bytes)
        .await
        .expect("put");

    store.start_marking().await.expect("start");
    store.mark(kept.root()).await.expect("mark");
    assert_eq!(store.sweep().await.expect("sweep"), 1);

    assert!(store.has(kept.leaf(0).expect("one")).await.expect("has"));
    assert!(!store.has(junk.leaf(0).expect("one")).await.expect("has"));
}

/// Marks are the only thing keeping data alive, in the browser too.
#[wasm_bindgen_test]
async fn a_sweep_with_no_marks_clears_everything() {
    let store = fresh("sweep-empty").await;
    let bytes = body(1024, 12);
    let map = ChunkMap::build(&bytes);
    store.put_map(&map).await.expect("put_map");
    store
        .put(map.leaf(0).expect("one"), &bytes)
        .await
        .expect("put");

    store.start_marking().await.expect("start");
    assert_eq!(store.sweep().await.expect("sweep"), 1);
    assert!(!store.has(map.leaf(0).expect("one")).await.expect("has"));
}

#[wasm_bindgen_test]
async fn marking_a_root_with_no_stored_map_is_refused() {
    let store = fresh("mark-orphan").await;
    let orphan = ChunkMap::build(&body(512, 13));
    store.start_marking().await.expect("start");
    assert!(store.mark(orphan.root()).await.is_err());
}

#[wasm_bindgen_test]
async fn clear_drops_only_what_it_names() {
    let store = fresh("clear").await;
    let one = body(512, 14);
    let two = body(512, 15);
    let one_hash = chunk_hash(&one);
    let two_hash = chunk_hash(&two);
    store.put(one_hash, &one).await.expect("put");
    store.put(two_hash, &two).await.expect("put");

    store.clear(&[one_hash]).await.expect("clear");
    assert!(!store.has(one_hash).await.expect("has"));
    assert!(store.has(two_hash).await.expect("has"));

    // Clearing something absent races a sweep in practice, and is a no-op.
    store.clear(&[one_hash]).await.expect("clear again");
}

#[wasm_bindgen_test]
async fn binding_survives_and_a_version_change_breaks_it() {
    let store = fresh("bind").await;
    let map = ChunkMap::build(&body(2048, 16));
    let file = FileId {
        key: "doc.txt".to_owned(),
        size: 2048,
        mtime: 1_700_000_000,
    };

    assert_eq!(store.bind(&file).await.expect("bind"), None);
    store.set_bind(&file, map.root()).await.expect("set_bind");
    assert_eq!(store.bind(&file).await.expect("bind"), Some(map.root()));

    let touched = FileId {
        mtime: file.mtime + 1,
        ..file.clone()
    };
    assert_eq!(store.bind(&touched).await.expect("bind"), None);
}

/// A tab that reloads must find what it seeded, or every refresh would cost the
/// swarm a seeder.
#[wasm_bindgen_test]
async fn a_reopened_database_still_holds_what_was_stored() {
    let name = "habilis-network-chunks-test-reopen";
    let bytes = body(CHUNK_BYTES_USIZE, 17);
    let map = ChunkMap::build(&bytes);
    {
        let store = IdbStore::open(name).await.expect("open");
        store.put_map(&map).await.expect("put_map");
        store
            .put(map.leaf(0).expect("one"), &bytes)
            .await
            .expect("put");
    }
    let reopened = IdbStore::open(name).await.expect("reopen");
    assert_eq!(
        reopened.get(map.leaf(0).expect("one")).await.expect("get"),
        Some(bytes)
    );
    assert!(
        reopened
            .coverage(map.root())
            .await
            .expect("cov")
            .is_complete()
    );
}

#[wasm_bindgen_test]
async fn an_empty_file_is_complete_immediately() {
    let store = fresh("empty").await;
    let map = ChunkMap::build(b"");
    store.put_map(&map).await.expect("put_map");
    let coverage = store.coverage(map.root()).await.expect("cov");
    assert_eq!(coverage.len(), 0);
    assert!(coverage.is_complete());
}

#[wasm_bindgen_test]
async fn coverage_survives_being_described_and_rebuilt() {
    let store = fresh("describe").await;
    let bytes = body(CHUNK_BYTES_USIZE * 5, 18);
    let map = ChunkMap::build(&bytes);
    store.put_map(&map).await.expect("put_map");
    for index in [0usize, 2, 4] {
        let range = map.range_of(index);
        let start = usize::try_from(range.start).expect("fits");
        let end = usize::try_from(range.end).expect("fits");
        store
            .put(map.leaf(index).expect("in range"), &bytes[start..end])
            .await
            .expect("put");
    }
    let coverage = store.coverage(map.root()).await.expect("cov");
    let rebuilt = Coverage::from_bits(coverage.as_bits(), coverage.len()).expect("rebuild");
    assert_eq!(rebuilt.held().collect::<Vec<_>>(), vec![0, 2, 4]);
}
