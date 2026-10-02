//! The non-owning half: serving the user's own files where they already sit.
//!
//! [`FsOrigin`] is the reason this crate exists rather than reaching for an
//! ordinary content-addressed store. It answers a bare chunk address — no file,
//! no offset, because that is all a peer sends — by resolving it back to a place
//! on disk and reading through. Nothing is copied, so publishing a large tree
//! costs a `stat` walk plus one read per file anyone actually asks about.
//!
//! The cases below are the ones where "read through to a file we do not own"
//! differs from "keep a copy", which is where the bugs live.

// Host-only: these backends are `std::fs`-bound, and a wasm build simply does
// not have them. The browser backend is exercised in `idb_browser.rs`, which
// needs a real browser and a real executor that this suite has neither of.
#![cfg(not(target_arch = "wasm32"))]

use std::future::Future;
use std::path::Path;

use habilis_network_chunks::{CHUNK_BYTES_USIZE, ChunkSource, FileId, FsOrigin, chunk_hash};

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
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("an origin future parked; this suite has no reactor"),
    }
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "habilis-network-chunks-origin-{tag}-{}-{unique}",
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

/// A [`FileId`] describing what is actually on disk right now.
///
/// Read from the filesystem rather than assumed, because the version gate
/// compares against the real mtime and a made-up one would either never match
/// or never differ.
fn describe(path: &Path) -> FileId {
    let meta = std::fs::metadata(path).expect("the file exists");
    let mtime = meta
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|since| i64::try_from(since.as_secs()).ok())
        .unwrap_or(0);
    FileId {
        key: path.display().to_string(),
        size: meta.len(),
        mtime,
    }
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.0.join(name);
    std::fs::write(&path, bytes).expect("write");
    path
}

/// The central claim: an origin answers for a chunk by address alone, having
/// copied nothing.
#[test]
fn an_origin_serves_by_address_without_copying() {
    let dir = TempDir::new("serve");
    let bytes = body(CHUNK_BYTES_USIZE * 3 + 17, 1);
    let path = write(&dir, "movie.bin", &bytes);
    let origin = FsOrigin::new();

    block_on(async {
        let root = origin.adopt(&describe(&path), &path).expect("adopt");
        let map = origin.map(root).await.expect("map").expect("adopted");
        assert_eq!(map.size(), bytes.len() as u64);
        assert_eq!(map.len(), 4);

        // Reassemble the file purely by asking for addresses, the way a peer
        // would, and confirm it is byte-for-byte what is on disk.
        let mut rebuilt = Vec::new();
        for index in 0..map.len() {
            let leaf = map.leaf(index).expect("in range");
            let chunk = origin.get(leaf).await.expect("get").expect("held");
            assert!(map.verify(index, &chunk));
            rebuilt.extend_from_slice(&chunk);
        }
        assert_eq!(rebuilt, bytes);

        // Nothing was written anywhere: the only file in the directory is the
        // one the user put there.
        let entries: Vec<_> = std::fs::read_dir(&dir.0)
            .expect("readdir")
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        assert_eq!(entries.len(), 1, "an origin copies nothing: {entries:?}");
    });
}

/// An origin holds every chunk of a file it still has, and none of a file that
/// moved. There is no middle state — it either has the file or it does not.
#[test]
fn coverage_is_all_or_nothing_and_follows_the_file() {
    let dir = TempDir::new("coverage");
    let bytes = body(CHUNK_BYTES_USIZE * 2, 2);
    let path = write(&dir, "doc.bin", &bytes);
    let origin = FsOrigin::new();

    block_on(async {
        let root = origin.adopt(&describe(&path), &path).expect("adopt");
        assert!(origin.coverage(root).await.expect("cov").is_complete());

        // Replace the contents with something a different length.
        std::fs::write(&path, body(CHUNK_BYTES_USIZE, 3)).expect("rewrite");
        let coverage = origin.coverage(root).await.expect("cov");
        assert_eq!(coverage.count(), 0, "a file that moved is served no more");
    });
}

/// The version gate on the read path, which is what stops an editor's save from
/// being served as the file somebody started downloading.
#[test]
fn a_changed_file_stops_answering_for_its_old_addresses() {
    let dir = TempDir::new("gate");
    let bytes = body(CHUNK_BYTES_USIZE * 2, 4);
    let path = write(&dir, "notes.bin", &bytes);
    let origin = FsOrigin::new();

    block_on(async {
        let root = origin.adopt(&describe(&path), &path).expect("adopt");
        let map = origin.map(root).await.expect("map").expect("adopted");
        let leaf = map.leaf(0).expect("first");
        assert!(origin.get(leaf).await.expect("get").is_some());

        // A save that changes the length is caught by size alone.
        std::fs::write(&path, body(CHUNK_BYTES_USIZE * 2 + 1, 4)).expect("rewrite");
        assert_eq!(
            origin.get(leaf).await.expect("get"),
            None,
            "the old address must not be answered from new bytes"
        );
    });
}

/// The subtle one: a file edited **in place**, same length, same mtime second.
///
/// Neither half of the version gate catches this, which is exactly why the read
/// path re-hashes what it read before answering. Without that check an origin
/// would serve bytes that do not address what was asked for, and a downloader
/// would only find out when its own verification failed — three hops away, with
/// nothing pointing back here.
#[test]
fn bytes_that_changed_under_a_stable_stat_are_still_caught() {
    let dir = TempDir::new("inplace");
    let bytes = body(CHUNK_BYTES_USIZE, 5);
    let path = write(&dir, "same-size.bin", &bytes);
    let origin = FsOrigin::new();

    block_on(async {
        let described = describe(&path);
        let root = origin.adopt(&described, &path).expect("adopt");
        let map = origin.map(root).await.expect("map").expect("adopted");
        let leaf = map.leaf(0).expect("first");

        // Same length, written back with the original mtime restored, so the
        // stat-based gate sees nothing at all.
        let mut altered = bytes.clone();
        altered[0] ^= 0xff;
        std::fs::write(&path, &altered).expect("rewrite");
        set_mtime(&path, described.mtime);
        assert_eq!(describe(&path).size, described.size);

        assert_eq!(
            origin.get(leaf).await.expect("get"),
            None,
            "re-hashing on read is the last line of defence, and it must hold"
        );
    });
}

/// Restore an mtime so the stat-based gate genuinely cannot tell the file
/// changed. Uses `touch -t`, which is portable enough for the platforms this
/// runs on and avoids a dependency for one syscall.
fn set_mtime(path: &Path, mtime: i64) {
    let stamp = std::process::Command::new("touch")
        .arg("-t")
        .arg(format_stamp(mtime))
        .arg(path)
        .status();
    assert!(stamp.is_ok_and(|status| status.success()), "touch");
}

/// `[[CC]YY]MMDDhhmm[.ss]`, which is what `touch -t` wants.
fn format_stamp(mtime: i64) -> String {
    // Days since epoch to a civil date, via the usual days-from-civil inverse.
    let days = mtime.div_euclid(86_400);
    let secs_of_day = mtime.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}.{second:02}")
}

/// Howard Hinnant's `civil_from_days`, transcribed. Cheaper than a date crate
/// for the one place a test needs it.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Two files sharing a chunk resolve that address to whichever was adopted
/// first, and both answers are correct — the bytes are the same bytes. This is
/// dedup on the serving side.
#[test]
fn a_shared_chunk_answers_from_whichever_file_was_adopted_first() {
    let dir = TempDir::new("shared");
    let shared = body(CHUNK_BYTES_USIZE, 6);
    let mut first = shared.clone();
    first.extend_from_slice(&body(CHUNK_BYTES_USIZE, 7));
    let second = shared.clone();

    let first_path = write(&dir, "first.bin", &first);
    let second_path = write(&dir, "second.bin", &second);
    let origin = FsOrigin::new();

    block_on(async {
        let first_root = origin
            .adopt(&describe(&first_path), &first_path)
            .expect("adopt");
        let second_root = origin
            .adopt(&describe(&second_path), &second_path)
            .expect("adopt");
        assert_ne!(first_root, second_root, "different files, different roots");

        let shared_hash = chunk_hash(&shared);
        let served = origin.get(shared_hash).await.expect("get").expect("held");
        assert_eq!(served, shared);

        // And both files report holding it.
        assert!(origin.coverage(first_root).await.expect("cov").contains(0));
        assert!(origin.coverage(second_root).await.expect("cov").contains(0));
    });
}

/// Forgetting a root drops its addresses too, so a stale reverse-index entry
/// cannot keep pointing at a file that is no longer served.
#[test]
fn forgetting_a_root_drops_its_addresses() {
    let dir = TempDir::new("forget");
    let bytes = body(CHUNK_BYTES_USIZE, 8);
    let path = write(&dir, "gone.bin", &bytes);
    let origin = FsOrigin::new();

    block_on(async {
        let root = origin.adopt(&describe(&path), &path).expect("adopt");
        let leaf = chunk_hash(&bytes);
        assert!(origin.get(leaf).await.expect("get").is_some());

        origin.forget(root).expect("forget");
        assert_eq!(origin.get(leaf).await.expect("get"), None);
        assert!(origin.map(root).await.expect("map").is_none());
        assert_eq!(origin.coverage(root).await.expect("cov").len(), 0);
    });
}

/// An address nobody adopted is absent rather than an error — the ordinary
/// answer to a peer asking for a chunk from a share we do not serve.
#[test]
fn an_unadopted_address_is_absent() {
    let origin = FsOrigin::new();
    block_on(async {
        assert_eq!(
            origin.get(chunk_hash(b"never adopted")).await.expect("get"),
            None
        );
        assert!(!origin.has(chunk_hash(b"never adopted")).await.expect("has"));
    });
}

/// A file whose size does not match what the caller described is refused at
/// adopt time, rather than producing a row that describes neither.
#[test]
fn adopting_a_file_that_disagrees_with_its_description_fails() {
    let dir = TempDir::new("mismatch");
    let path = write(&dir, "grew.bin", &body(1024, 9));
    let origin = FsOrigin::new();
    let mut described = describe(&path);
    described.size += 1;
    assert!(origin.adopt(&described, &path).is_err());
}

/// Empty and sub-chunk files are ordinary, not edge cases to be refused.
#[test]
fn tiny_and_empty_files_adopt_cleanly() {
    let dir = TempDir::new("tiny");
    let empty = write(&dir, "empty.bin", b"");
    let tiny = write(&dir, "tiny.bin", b"hello");
    let origin = FsOrigin::new();

    block_on(async {
        let empty_root = origin.adopt(&describe(&empty), &empty).expect("adopt");
        let empty_map = origin.map(empty_root).await.expect("map").expect("adopted");
        assert_eq!(empty_map.len(), 0);
        assert!(
            origin
                .coverage(empty_root)
                .await
                .expect("cov")
                .is_complete()
        );

        let tiny_root = origin.adopt(&describe(&tiny), &tiny).expect("adopt");
        let tiny_map = origin.map(tiny_root).await.expect("map").expect("adopted");
        assert_eq!(tiny_map.len(), 1);
        let leaf = tiny_map.leaf(0).expect("one");
        assert_eq!(
            origin.get(leaf).await.expect("get"),
            Some(b"hello".to_vec())
        );
    });
}

/// A file exactly on a chunk boundary must not gain a phantom trailing chunk,
/// which would make its root disagree with every other peer's.
#[test]
fn a_file_on_an_exact_chunk_boundary_has_no_trailing_chunk() {
    let dir = TempDir::new("boundary");
    let bytes = body(CHUNK_BYTES_USIZE * 2, 10);
    let path = write(&dir, "exact.bin", &bytes);
    let origin = FsOrigin::new();

    block_on(async {
        let root = origin.adopt(&describe(&path), &path).expect("adopt");
        let map = origin.map(root).await.expect("map").expect("adopted");
        assert_eq!(map.len(), 2);
        // And it agrees with the in-memory path, which is what every other peer
        // computes.
        assert_eq!(map, habilis_network_chunks::ChunkMap::build(&bytes));
    });
}

/// The bind table is the version gate at file granularity, and an origin keeps
/// it as a side effect of adopting.
#[test]
fn adopting_records_a_binding_that_a_version_change_breaks() {
    let dir = TempDir::new("bind");
    let bytes = body(2048, 11);
    let path = write(&dir, "bound.bin", &bytes);
    let origin = FsOrigin::new();

    block_on(async {
        let described = describe(&path);
        let root = origin.adopt(&described, &path).expect("adopt");
        assert_eq!(origin.bind(&described).await.expect("bind"), Some(root));

        let moved = FileId {
            size: described.size + 1,
            ..described.clone()
        };
        assert_eq!(origin.bind(&moved).await.expect("bind"), None);
    });
}
