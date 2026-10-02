//! The conformance suite every backend must pass.
//!
//! Written once against the traits, run per backend. That is the whole reason
//! [`ChunkSource`] and [`ChunkStore`] are traits at all: an in-memory map, a
//! directory of files and an `IndexedDB` database differ in every way except the
//! behaviour asserted here — and the expensive failures are behaviour, not
//! implementation. Storing bytes that address something else. Reporting
//! coverage for chunks that are gone. Sweeping away live data.
//!
//! Add a backend by implementing [`Harness`] and adding one `backends!` line.
//! Anything that only passes for one backend is in the wrong file.

// Host-only: these backends are `std::fs`-bound, and a wasm build simply does
// not have them. The browser backend is exercised in `idb_browser.rs`, which
// needs a real browser and a real executor that this suite has neither of.
#![cfg(not(target_arch = "wasm32"))]

use std::future::Future;

use habilis_network_chunks::{
    CHUNK_BYTES_USIZE, ChunkHash, ChunkMap, ChunkSource, ChunkStore, Coverage, FileId, FsStore,
    MemStore, chunk_hash,
};

/// Bytes that differ per position and per seed, so a chunk lifted from one file
/// cannot accidentally equal a chunk from another — which would make the dedup
/// assertions pass for the wrong reason.
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

/// Store one chunk of `bytes` as `map` describes it.
///
/// The four lines this replaces appear verbatim wherever a case needs a file to
/// be part-held, which is most of the coverage ones.
async fn store_chunk(store: &impl ChunkStore, map: &ChunkMap, bytes: &[u8], index: usize) {
    let range = map.range_of(index);
    let start = usize::try_from(range.start).expect("fits");
    let end = usize::try_from(range.end).expect("fits");
    let leaf = map.leaf(index).expect("in range");
    store.put(leaf, &bytes[start..end]).await.expect("put");
}

/// What a backend supplies beyond the traits.
///
/// One thing, and it is exactly what the traits keep opaque: **where a file
/// lives**. `MemStore` accepts any key; a filesystem backend needs a path it can
/// open. A suite that hardcoded either would be testing one backend.
trait Harness {
    type Store: ChunkStore;
    fn store(&self) -> &Self::Store;
    /// A key this backend can actually use for a file called `name`.
    fn key(&self, name: &str) -> String;

    fn file(&self, name: &str, size: u64) -> FileId {
        FileId {
            key: self.key(name),
            size,
            mtime: 1_700_000_000,
        }
    }
}

/// Run one async body on a plain executor.
///
/// Hand-rolled rather than `#[tokio::test]`: the traits' futures are `?Send`, so
/// binding this to a tokio runtime would bake in the one thing the crate must
/// stay free of — and `tests/isolation.rs` would fail the build for the
/// dev-dependency anyway.
fn block_on<F: Future>(future: F) -> F::Output {
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    let mut future = Box::pin(future);
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    // Polled once, deliberately: every future here resolves without yielding. A
    // backend that introduces real async I/O will park, and should bring its own
    // driver rather than have this one silently spin.
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("a conformance future parked; this suite has no reactor"),
    }
}

struct MemHarness(MemStore);

impl Harness for MemHarness {
    type Store = MemStore;
    fn store(&self) -> &MemStore {
        &self.0
    }
    fn key(&self, name: &str) -> String {
        name.to_owned()
    }
}

/// The case list, written once and applied to each backend.
///
/// A callback macro rather than a nested repetition, because `macro_rules`
/// cannot iterate two independent metavariable groups against each other — the
/// cases and the backends repeat different numbers of times. Each backend
/// defines a one-case macro and hands it here; see `mod mem` below for the
/// shape, which is three lines to add a backend.
macro_rules! for_each_case {
    ($case:ident) => {
        $case!(round_trip);
        $case!(a_lying_chunk_is_refused_and_stores_nothing);
        $case!(an_unknown_chunk_is_absent_not_an_error);
        $case!(an_empty_chunk_is_storable);
        $case!(maps_round_trip);
        $case!(an_unknown_root_covers_nothing);
        $case!(coverage_grows_chunk_by_chunk);
        $case!(an_empty_file_is_complete_immediately);
        $case!(a_shared_chunk_is_stored_once_and_covers_both_files);
        $case!(binding_survives_and_a_version_change_breaks_it);
        $case!(a_sweep_keeps_marked_and_drops_the_rest);
        $case!(a_sweep_with_no_marks_clears_everything);
        $case!(a_shared_chunk_survives_a_sweep_that_marks_only_one_owner);
        $case!(marking_a_root_with_no_stored_map_is_refused);
        $case!(a_new_pass_forgets_the_previous_marks);
        $case!(clear_drops_only_what_it_names);
        $case!(coverage_shrinks_when_chunks_are_cleared);
        $case!(stored_chunks_still_verify_against_their_map);
        $case!(coverage_survives_being_described_and_rebuilt);
        $case!(coverage_of_agrees_with_coverage_root_for_root);
        $case!(coverage_of_keeps_its_place_for_a_root_it_does_not_know);
        $case!(coverage_of_nothing_is_nothing);
        $case!(putting_a_held_chunk_again_is_idempotent);
        $case!(a_one_bit_difference_is_caught);
    };
}

// ---------------------------------------------------------------------------
// Storing and addressing
// ---------------------------------------------------------------------------

async fn round_trip(harness: &impl Harness) {
    let store = harness.store();
    let chunk = body(CHUNK_BYTES_USIZE, 1);
    let hash = chunk_hash(&chunk);

    assert!(!store.has(hash).await.expect("has"), "nothing stored yet");
    assert_eq!(store.get(hash).await.expect("get"), None);

    store.put(hash, &chunk).await.expect("put");
    assert!(store.has(hash).await.expect("has"));
    assert_eq!(store.get(hash).await.expect("get"), Some(chunk));
}

/// The single most important rule in the crate: a chunk that does not address
/// what the caller claims is refused, **and nothing is written**. A peer that
/// lies must cost its own bandwidth and nothing of ours.
async fn a_lying_chunk_is_refused_and_stores_nothing(harness: &impl Harness) {
    let store = harness.store();
    let honest = body(1024, 2);
    let hash = chunk_hash(&honest);
    let lie = body(1024, 3);

    let refused = store.put(hash, &lie).await;
    assert!(
        refused.is_err(),
        "bytes addressing something else must fail"
    );
    assert!(
        !store.has(hash).await.expect("has"),
        "a refused put must leave no record"
    );
    assert_eq!(store.get(hash).await.expect("get"), None);
    // And the honest bytes still work afterwards, so the refusal poisoned
    // nothing.
    store.put(hash, &honest).await.expect("put");
    assert_eq!(store.get(hash).await.expect("get"), Some(honest));
}

/// An unknown address is "not held", not a failure. A peer asking for something
/// we never had is ordinary traffic.
async fn an_unknown_chunk_is_absent_not_an_error(harness: &impl Harness) {
    let store = harness.store();
    let hash = chunk_hash(b"never stored");
    assert_eq!(store.get(hash).await.expect("get"), None);
    assert!(!store.has(hash).await.expect("has"));
}

async fn an_empty_chunk_is_storable(harness: &impl Harness) {
    let store = harness.store();
    let hash = chunk_hash(b"");
    store.put(hash, b"").await.expect("put");
    assert_eq!(store.get(hash).await.expect("get"), Some(Vec::new()));
}

// ---------------------------------------------------------------------------
// Maps and coverage
// ---------------------------------------------------------------------------

async fn maps_round_trip(harness: &impl Harness) {
    let store = harness.store();
    let map = ChunkMap::build(&body(CHUNK_BYTES_USIZE * 2 + 7, 4));
    assert_eq!(store.map(map.root()).await.expect("map"), None);
    store.put_map(&map).await.expect("put_map");
    assert_eq!(store.map(map.root()).await.expect("map"), Some(map));
}

async fn an_unknown_root_covers_nothing(harness: &impl Harness) {
    let store = harness.store();
    let map = ChunkMap::build(&body(4096, 5));
    let coverage = store.coverage(map.root()).await.expect("coverage");
    assert_eq!(coverage.len(), 0);
    assert_eq!(coverage.count(), 0);
}

/// The batched question must answer exactly what the single one does.
///
/// A backend is free to reach the two answers by different routes — the browser
/// store probes one root's leaves and enumerates the keyspace for many — and
/// this is what holds those routes to one meaning. Asked over a mix of held,
/// part-held and untouched files, because a disagreement is likeliest where the
/// answer is neither empty nor full.
async fn coverage_of_agrees_with_coverage_root_for_root(harness: &impl Harness) {
    let store = harness.store();
    let whole = body(CHUNK_BYTES_USIZE * 2, 21);
    let partial = body(CHUNK_BYTES_USIZE * 3, 22);
    let untouched = body(CHUNK_BYTES_USIZE, 23);

    let whole_map = ChunkMap::build(&whole);
    let partial_map = ChunkMap::build(&partial);
    let untouched_map = ChunkMap::build(&untouched);
    store.put_map(&whole_map).await.expect("put_map");
    store.put_map(&partial_map).await.expect("put_map");
    store.put_map(&untouched_map).await.expect("put_map");

    for index in 0..whole_map.len() {
        store_chunk(store, &whole_map, &whole, index).await;
    }
    // The middle chunk only, so the run has a hole in it rather than a prefix.
    store_chunk(store, &partial_map, &partial, 1).await;

    let roots = [whole_map.root(), partial_map.root(), untouched_map.root()];
    let batched = store.coverage_of(&roots).await.expect("coverage_of");
    assert_eq!(batched.len(), roots.len(), "one answer per root, in order");
    for (root, batch) in roots.iter().zip(&batched) {
        let single = store.coverage(*root).await.expect("coverage");
        assert_eq!(
            batch.len(),
            single.len(),
            "disagreed on length for {root:?}"
        );
        assert_eq!(
            batch.as_bits(),
            single.as_bits(),
            "disagreed on which chunks for {root:?}"
        );
    }
    assert!(batched[0].is_complete());
    assert_eq!(batched[1].count(), 1);
    assert_eq!(batched[2].count(), 0);
}

/// Positional, so a caller can zip the answers onto what it asked about. A root
/// the store never saw has to hold its slot rather than being skipped — dropping
/// it would slide every later answer onto the wrong file.
async fn coverage_of_keeps_its_place_for_a_root_it_does_not_know(harness: &impl Harness) {
    let store = harness.store();
    let known = body(CHUNK_BYTES_USIZE, 24);
    let map = ChunkMap::build(&known);
    store.put_map(&map).await.expect("put_map");
    store_chunk(store, &map, &known, 0).await;

    let stranger = ChunkMap::build(&body(4096, 25)).root();
    let coverages = store
        .coverage_of(&[stranger, map.root(), stranger])
        .await
        .expect("coverage_of");

    assert_eq!(coverages.len(), 3);
    assert_eq!(coverages[0].count(), 0);
    assert_eq!(coverages[0].len(), 0, "an unknown root covers nothing");
    assert!(coverages[1].is_complete(), "the known root kept its slot");
    assert_eq!(coverages[2].count(), 0);
}

/// Asking about nothing is not an error. The callers build this slice from
/// whatever rows they happen to hold, and a peer that has learned none is the
/// ordinary state on a tab that has only browsed.
async fn coverage_of_nothing_is_nothing(harness: &impl Harness) {
    let store = harness.store();
    let coverages = store.coverage_of(&[]).await.expect("coverage_of");
    assert!(coverages.is_empty());
}

/// **Partial is a first-class answer.** This is the behaviour that replaces the
/// old rule that a file had to be held in full before it could be shared, and
/// the reason a cancelled download still helps the swarm.
async fn coverage_grows_chunk_by_chunk(harness: &impl Harness) {
    let store = harness.store();
    let bytes = body(CHUNK_BYTES_USIZE * 4, 6);
    let map = ChunkMap::build(&bytes);
    store.put_map(&map).await.expect("put_map");

    assert_eq!(store.coverage(map.root()).await.expect("cov").count(), 0);

    // Land them out of order, the way a swarm actually delivers.
    for index in [2usize, 0, 3, 1] {
        let range = map.range_of(index);
        let start = usize::try_from(range.start).expect("fits");
        let end = usize::try_from(range.end).expect("fits");
        let leaf = map.leaf(index).expect("in range");
        store.put(leaf, &bytes[start..end]).await.expect("put");

        let coverage = store.coverage(map.root()).await.expect("cov");
        assert!(coverage.contains(index), "chunk {index} should be held");
    }

    let coverage = store.coverage(map.root()).await.expect("cov");
    assert!(coverage.is_complete());
    assert_eq!(coverage.count(), 4);
}

/// A zero-byte file is complete the moment its row is known — there is nothing
/// left to want, so anyone who knows the root can answer for it.
async fn an_empty_file_is_complete_immediately(harness: &impl Harness) {
    let store = harness.store();
    let map = ChunkMap::build(b"");
    store.put_map(&map).await.expect("put_map");
    let coverage = store.coverage(map.root()).await.expect("cov");
    assert_eq!(coverage.len(), 0);
    assert!(coverage.is_complete());
}

/// The dedup claim, asserted directly: two different files that happen to share
/// a 64 `KiB` chunk store it once, and **both** report holding it.
///
/// This is what content addressing buys and what bao could never do, so if this
/// case ever goes red the crate has lost its reason to exist.
async fn a_shared_chunk_is_stored_once_and_covers_both_files(harness: &impl Harness) {
    let store = harness.store();
    let shared = body(CHUNK_BYTES_USIZE, 42);

    let mut first = shared.clone();
    first.extend_from_slice(&body(CHUNK_BYTES_USIZE, 8));
    let mut second = body(CHUNK_BYTES_USIZE, 9);
    second.extend_from_slice(&shared);

    let first_map = ChunkMap::build(&first);
    let second_map = ChunkMap::build(&second);
    store.put_map(&first_map).await.expect("put_map");
    store.put_map(&second_map).await.expect("put_map");

    // The shared chunk sits at index 0 of one file and index 1 of the other,
    // and addresses the same either way.
    assert_eq!(first_map.leaf(0), second_map.leaf(1));

    // Fetch the whole of the first file only.
    for index in 0..first_map.len() {
        let range = first_map.range_of(index);
        let start = usize::try_from(range.start).expect("fits");
        let end = usize::try_from(range.end).expect("fits");
        let leaf = first_map.leaf(index).expect("in range");
        store.put(leaf, &first[start..end]).await.expect("put");
    }

    // The second file is now partially held without ever being fetched.
    let coverage = store.coverage(second_map.root()).await.expect("cov");
    assert!(
        coverage.contains(1),
        "the shared chunk must count towards the other file too"
    );
    assert!(!coverage.contains(0), "the unshared chunk is still missing");
    assert!((coverage.fraction() - 0.5).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// Version binding
// ---------------------------------------------------------------------------

async fn binding_survives_and_a_version_change_breaks_it(harness: &impl Harness) {
    let store = harness.store();
    let map = ChunkMap::build(&body(2048, 10));
    let file = harness.file("doc.txt", 2048);

    assert_eq!(
        store.bind(&file).await.expect("bind"),
        None,
        "nothing bound"
    );
    store.set_bind(&file, map.root()).await.expect("set_bind");
    assert_eq!(store.bind(&file).await.expect("bind"), Some(map.root()));

    // A file that grew, and a file merely touched, are both different content
    // as far as this gate is concerned. Answering for either under the old root
    // is the silent corruption the gate exists to prevent.
    let grown = FileId {
        size: 4096,
        ..file.clone()
    };
    let touched = FileId {
        mtime: file.mtime + 1,
        ..file.clone()
    };
    assert_eq!(store.bind(&grown).await.expect("bind"), None);
    assert_eq!(store.bind(&touched).await.expect("bind"), None);
}

// ---------------------------------------------------------------------------
// Reclamation — the cases most likely to lose user data if wrong
// ---------------------------------------------------------------------------

async fn a_sweep_keeps_marked_and_drops_the_rest(harness: &impl Harness) {
    let store = harness.store();
    let kept_bytes = body(1024, 11);
    let kept = ChunkMap::build(&kept_bytes);
    let junk_bytes = body(1024, 12);
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
    let dropped = store.sweep().await.expect("sweep");

    assert_eq!(dropped, 1);
    assert!(store.has(kept.leaf(0).expect("one")).await.expect("has"));
    assert!(!store.has(junk.leaf(0).expect("one")).await.expect("has"));
}

/// Marks are the *only* thing that keeps data alive. A sweep with nothing
/// marked clears everything, and that has to be true rather than defensively
/// softened — a caller who forgot to mark should find out on the first run,
/// not after months of silent growth followed by one catastrophic pass.
async fn a_sweep_with_no_marks_clears_everything(harness: &impl Harness) {
    let store = harness.store();
    let bytes = body(1024, 13);
    let map = ChunkMap::build(&bytes);
    store.put_map(&map).await.expect("put_map");
    store
        .put(map.leaf(0).expect("one"), &bytes)
        .await
        .expect("put");

    store.start_marking().await.expect("start");
    let dropped = store.sweep().await.expect("sweep");

    assert_eq!(dropped, 1);
    assert!(!store.has(map.leaf(0).expect("one")).await.expect("has"));
}

/// The case a reference count would get wrong and mark-and-sweep gets right for
/// free: a chunk two files share survives a pass that marks only one of them.
async fn a_shared_chunk_survives_a_sweep_that_marks_only_one_owner(harness: &impl Harness) {
    let store = harness.store();
    let shared = body(CHUNK_BYTES_USIZE, 44);

    let mut first = shared.clone();
    first.extend_from_slice(&body(CHUNK_BYTES_USIZE, 14));
    let second = shared.clone();

    let first_map = ChunkMap::build(&first);
    let second_map = ChunkMap::build(&second);
    store.put_map(&first_map).await.expect("put_map");
    store.put_map(&second_map).await.expect("put_map");

    let shared_hash = second_map.leaf(0).expect("one");
    store.put(shared_hash, &shared).await.expect("put");
    let tail = first_map.leaf(1).expect("two");
    store
        .put(tail, &first[CHUNK_BYTES_USIZE..])
        .await
        .expect("put");

    // Mark only the *second* file, which is nothing but the shared chunk.
    store.start_marking().await.expect("start");
    store.mark(second_map.root()).await.expect("mark");
    store.sweep().await.expect("sweep");

    assert!(
        store.has(shared_hash).await.expect("has"),
        "a chunk reachable from a marked root must survive"
    );
    assert!(
        !store.has(tail).await.expect("has"),
        "the unmarked file's own chunk is garbage"
    );
}

/// Marking a root with no stored row is refused, because the only safe live set
/// is one derived from persisted maps. An in-memory held-set that lost an entry
/// to a reload would otherwise sweep live data away — the exact footgun
/// hypercore documents for its own mark-and-sweep.
async fn marking_a_root_with_no_stored_map_is_refused(harness: &impl Harness) {
    let store = harness.store();
    let orphan = ChunkMap::build(&body(512, 15));
    store.start_marking().await.expect("start");
    assert!(store.mark(orphan.root()).await.is_err());
}

/// A pass starts clean: marks from a previous sweep must not keep this one's
/// garbage alive.
async fn a_new_pass_forgets_the_previous_marks(harness: &impl Harness) {
    let store = harness.store();
    let bytes = body(1024, 16);
    let map = ChunkMap::build(&bytes);
    store.put_map(&map).await.expect("put_map");
    store
        .put(map.leaf(0).expect("one"), &bytes)
        .await
        .expect("put");

    store.start_marking().await.expect("start");
    store.mark(map.root()).await.expect("mark");
    store.sweep().await.expect("sweep");
    assert!(store.has(map.leaf(0).expect("one")).await.expect("has"));

    // Second pass, marking nothing: the earlier mark must not carry over.
    store.start_marking().await.expect("start");
    store.sweep().await.expect("sweep");
    assert!(!store.has(map.leaf(0).expect("one")).await.expect("has"));
}

async fn clear_drops_only_what_it_names(harness: &impl Harness) {
    let store = harness.store();
    let one = body(512, 17);
    let two = body(512, 18);
    let one_hash = chunk_hash(&one);
    let two_hash = chunk_hash(&two);
    store.put(one_hash, &one).await.expect("put");
    store.put(two_hash, &two).await.expect("put");

    store.clear(&[one_hash]).await.expect("clear");
    assert!(!store.has(one_hash).await.expect("has"));
    assert!(store.has(two_hash).await.expect("has"));

    // Clearing something absent is a no-op rather than an error: eviction races
    // with a sweep, and both removing the same chunk is ordinary.
    store.clear(&[one_hash]).await.expect("clear again");
    store
        .clear(&[chunk_hash(b"never stored")])
        .await
        .expect("clear unknown");
}

/// Coverage must follow eviction down, not just up. A store still claiming a
/// chunk it dropped is the "peer that lies" failure the ordering rule exists to
/// prevent, seen from the other side.
async fn coverage_shrinks_when_chunks_are_cleared(harness: &impl Harness) {
    let store = harness.store();
    let bytes = body(CHUNK_BYTES_USIZE * 2, 19);
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
    assert!(store.coverage(map.root()).await.expect("cov").is_complete());

    store
        .clear(&[map.leaf(0).expect("one")])
        .await
        .expect("clear");
    let coverage = store.coverage(map.root()).await.expect("cov");
    assert!(!coverage.is_complete());
    assert!(!coverage.contains(0));
    assert!(coverage.contains(1));
}

/// Every chunk fetched through a map verifies against that map. The round trip
/// through storage must not alter a byte.
async fn stored_chunks_still_verify_against_their_map(harness: &impl Harness) {
    let store = harness.store();
    let bytes = body(CHUNK_BYTES_USIZE * 3 + 13, 20);
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
        let leaf = map.leaf(index).expect("in range");
        let chunk = store.get(leaf).await.expect("get").expect("held");
        assert!(map.verify(index, &chunk), "chunk {index} must verify");
        rebuilt.extend_from_slice(&chunk);
    }
    assert_eq!(rebuilt, bytes, "the file reassembles byte for byte");
}

/// Coverage handed to a peer and rebuilt from its bits describes the same set.
/// This is the shape that later rides a peer card, so a mismatch here becomes a
/// peer sent to the wrong place.
async fn coverage_survives_being_described_and_rebuilt(harness: &impl Harness) {
    let store = harness.store();
    let bytes = body(CHUNK_BYTES_USIZE * 5, 21);
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
    assert_eq!(rebuilt, coverage);
    assert_eq!(rebuilt.held().collect::<Vec<_>>(), vec![0, 2, 4]);
}

/// Re-storing a chunk already held is idempotent, which matters because a swarm
/// in endgame deliberately asks several peers for the same chunk.
async fn putting_a_held_chunk_again_is_idempotent(harness: &impl Harness) {
    let store = harness.store();
    let chunk = body(4096, 22);
    let hash = chunk_hash(&chunk);
    store.put(hash, &chunk).await.expect("put");
    store.put(hash, &chunk).await.expect("put again");
    assert_eq!(store.get(hash).await.expect("get"), Some(chunk));
}

/// A hash that differs from the real one in a single bit is refused. Guards
/// against a comparison that only checks a prefix.
async fn a_one_bit_difference_is_caught(harness: &impl Harness) {
    let store = harness.store();
    let chunk = body(1024, 23);
    let mut wrong = *chunk_hash(&chunk).as_bytes();
    wrong[31] ^= 1;
    assert!(
        store
            .put(ChunkHash::from_bytes(wrong), &chunk)
            .await
            .is_err()
    );
}

/// A throwaway directory, removed on drop.
///
/// Hand-rolled rather than pulling `tempfile` in: a dev-dependency is still a
/// dependency to audit, `tests/isolation.rs` scans for exactly that, and this
/// is twelve lines.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "habilis-network-chunks-{tag}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("a temp directory");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct FsHarness {
    dir: TempDir,
    store: FsStore,
}

impl FsHarness {
    fn new() -> Self {
        let dir = TempDir::new("store");
        let store = FsStore::open(dir.0.join("store")).expect("open");
        Self { dir, store }
    }
}

impl Harness for FsHarness {
    type Store = FsStore;
    fn store(&self) -> &FsStore {
        &self.store
    }
    fn key(&self, name: &str) -> String {
        self.dir.0.join(name).display().to_string()
    }
}

/// The in-memory backend. A backend costs one module like this one.
mod mem {
    use super::{MemHarness, MemStore, block_on};

    macro_rules! run {
        ($case:ident) => {
            #[test]
            fn $case() {
                // A fresh store per case: conformance must not depend on what
                // some earlier case happened to leave behind.
                block_on(super::$case(&MemHarness(MemStore::new())));
            }
        };
    }

    for_each_case!(run);
}

/// The filesystem backend, held to exactly the same contract.
mod fs_store {
    use super::{FsHarness, block_on};

    macro_rules! run {
        ($case:ident) => {
            #[test]
            fn $case() {
                block_on(super::$case(&FsHarness::new()));
            }
        };
    }

    for_each_case!(run);
}

/// Dedup is a storage-level claim, so assert it at storage level too: the
/// `MemStore` really does keep one record for a chunk two files share.
#[test]
fn mem_stores_a_shared_chunk_exactly_once() {
    let store = MemStore::new();
    block_on(async {
        let shared = body(CHUNK_BYTES_USIZE, 45);
        let hash = chunk_hash(&shared);
        store.put(hash, &shared).await.expect("put");
        store.put(hash, &shared).await.expect("put again");
        assert_eq!(store.stored_chunks(), 1);
    });
}
