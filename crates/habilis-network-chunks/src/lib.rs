//! Content-addressed chunks over data you already own.
//!
//! A file is a **merkle leaf row**: fixed 64 `KiB` chunks, each addressed by
//! `blake3` of its own bytes, plus an ordered list of those addresses that
//! names the file. Two properties fall out, and the crate exists for both:
//!
//! > **A chunk proves itself.** Hash what arrived, compare it to the address
//! > you asked for. No proof, no tree walk, no outboard — so a chunk is
//! > acceptable from any peer, with zero trust and no per-peer bookkeeping.
//!
//! > **The store never chooses where bytes live.** An origin's file stays
//! > exactly where the user put it; the store holds addresses beside it and
//! > reads through. That is what keeps serving a 500 GB tree a `stat` walk
//! > instead of a full read of it.
//!
//! # Why not bao
//!
//! `BLAKE3` threads a chunk counter into its compression function, so a bao
//! subtree hash is bound to *where* the bytes sit. Excellent as a proof of
//! placement, useless as a content address: the same 64 `KiB` at two offsets
//! hashes two ways, so nothing ever dedups and no peer can answer for a chunk
//! without first agreeing which file and which offset it came from. Placement
//! is proved here by the leaf row instead — leaf *k* belongs at offset
//! *k* × [`CHUNK_BYTES`], and the row is what the root commits to.
//!
//! That is also what separated this crate from the retired `habilis-network-blobs`:
//! blobs proved *placement* (bao outboards over one file), chunks proves
//! *content*. This crate replaced it after v0.6.0.
//!
//! # What this crate is not
//!
//! No transport, no ALPN, no framing. No discovery. No download scheduler —
//! that needs peer budgets and connection state, and making it generic is how
//! a blob-transfer library gets rebuilt by accident. No manifests, no shares,
//! no tokens. It takes a hash, some bytes and a chunk map. See
//! `tests/isolation.rs`, which fails the build if that stops being true.
//!
//! # Both runtimes
//!
//! The same store runs under tokio and in a browser, so every future here is
//! `?Send`: an `IndexedDB` backend holds `Rc`-flavoured state and an OPFS one is
//! pinned to a single Worker thread. Callers that need `Send` get it from their
//! own backend, not from this trait.

/// Bytes per chunk.
///
/// Fixed offsets, deliberately, rather than content-defined chunking. CDC
/// dedups content that shifted, but it breaks the fixed `offset -> index`
/// mapping that lets a caller turn a byte range into chunk numbers without
/// consulting anything. Everything downstream — range reads, availability,
/// scheduling — depends on that mapping being arithmetic.
pub const CHUNK_BYTES: u64 = 64 * 1024;

/// [`CHUNK_BYTES`] as a `usize`, for slicing.
///
/// Written as a literal rather than a cast so it is correct on a 32-bit target
/// by construction; `chunk_bytes_agree` pins the two together.
pub const CHUNK_BYTES_USIZE: usize = 64 * 1024;

mod chunk_hash;
mod chunk_map;
mod chunk_store;
mod coverage;

pub use chunk_hash::{ChunkHash, Root, chunk_hash};
pub use chunk_map::{ChunkMap, ChunkMapBuilder, chunk_count};
pub use chunk_store::{ChunkSource, ChunkStore};
pub use coverage::{Coverage, FileId};

mod chunk_error;

pub use chunk_error::ChunkError;

/// The filesystem backends. Host-only, and gated on the target rather than a
/// feature so it cannot be misconfigured: a wasm build simply does not have
/// `std::fs`, and the browser backends are what it uses instead.
#[cfg(not(target_arch = "wasm32"))]
pub mod fs;
/// The browser backend. Main-thread capable, so a tab can seed without a Worker.
#[cfg(target_arch = "wasm32")]
pub mod idb_store;
pub mod in_memory_store;

#[cfg(not(target_arch = "wasm32"))]
pub use fs::{DiskOrigin, DiskStore};
#[cfg(target_arch = "wasm32")]
pub use idb_store::IdbStore;
pub use in_memory_store::InMemoryStore;

#[cfg(test)]
mod tests {
    use super::{
        CHUNK_BYTES, CHUNK_BYTES_USIZE, ChunkHash, ChunkMap, ChunkMapBuilder, Coverage, FileId,
        Root, chunk_count, chunk_hash,
    };
    use habilis_network_test_tracing::test;

    /// Bytes that differ per position and per seed, so a chunk taken from one
    /// place cannot accidentally equal a chunk taken from another.
    fn body(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|index| {
                u8::try_from(index % 256)
                    .unwrap_or(0)
                    .wrapping_mul(31)
                    .wrapping_add(seed)
            })
            .collect()
    }

    /// The two spellings of the chunk size must agree, or every slice in the
    /// crate is off by whatever the difference is.
    #[test]
    fn chunk_bytes_agree() {
        assert_eq!(u64::try_from(CHUNK_BYTES_USIZE).expect("fits"), CHUNK_BYTES);
    }

    /// The crate's premise in one assertion: the same bytes at different
    /// offsets get the same address. This is exactly what bao cannot do, and
    /// the reason dedup and serve-by-hash are possible at all.
    #[test]
    fn the_same_bytes_address_the_same_wherever_they_sit() {
        let chunk = body(CHUNK_BYTES_USIZE, 7);
        let mut early = Vec::new();
        early.extend_from_slice(&chunk);
        early.extend_from_slice(&body(CHUNK_BYTES_USIZE, 99));

        let mut late = Vec::new();
        late.extend_from_slice(&body(CHUNK_BYTES_USIZE, 99));
        late.extend_from_slice(&chunk);

        let early_map = ChunkMap::build(&early);
        let late_map = ChunkMap::build(&late);

        assert_eq!(early_map.leaf(0), late_map.leaf(1));
        assert_eq!(early_map.leaf(1), late_map.leaf(0));
        // Same leaves, different order, so the files are not the same file.
        assert_ne!(early_map.root(), late_map.root());
    }

    #[test]
    fn a_root_commits_to_order_and_to_size() {
        let leaves = vec![chunk_hash(b"a"), chunk_hash(b"b")];
        let forward = ChunkMap::from_leaves(leaves.clone(), CHUNK_BYTES + 1).expect("two chunks");
        let reversed: Vec<ChunkHash> = leaves.into_iter().rev().collect();
        let backward = ChunkMap::from_leaves(reversed, CHUNK_BYTES + 1).expect("two chunks");
        assert_ne!(forward.root(), backward.root());
    }

    /// A row that does not describe the size it claims is refused, rather than
    /// producing a map that would verify against nothing.
    #[test]
    fn a_row_that_disagrees_with_its_size_is_refused() {
        let leaves = vec![chunk_hash(b"only one")];
        assert!(ChunkMap::from_leaves(leaves, CHUNK_BYTES * 4).is_err());
    }

    #[test]
    fn a_rebuilt_map_matches_the_one_that_was_built() {
        let bytes = body(CHUNK_BYTES_USIZE * 3 + 11, 3);
        let built = ChunkMap::build(&bytes);
        let rebuilt =
            ChunkMap::from_leaves(built.leaves().to_vec(), built.size()).expect("same row");
        assert_eq!(built, rebuilt);
        assert_eq!(built.root(), rebuilt.root());
    }

    /// The streaming builder is what an origin uses on a file it will not hold
    /// in memory, so it must agree with the all-at-once path exactly.
    #[test]
    fn the_streaming_builder_agrees_with_the_whole_file_path() {
        let bytes = body(CHUNK_BYTES_USIZE * 2 + 5, 21);
        let mut builder = ChunkMapBuilder::new();
        for chunk in bytes.chunks(CHUNK_BYTES_USIZE) {
            builder.push(chunk);
        }
        assert_eq!(builder.finish(), ChunkMap::build(&bytes));
    }

    #[test]
    fn an_empty_file_has_a_root_and_no_chunks() {
        let map = ChunkMap::build(b"");
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        assert_eq!(chunk_count(0), 0);
        // Complete, because there is nothing left to want.
        assert!(Coverage::empty(0).is_complete());
        assert!((Coverage::empty(0).fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_file_shorter_than_one_chunk_is_one_chunk() {
        let map = ChunkMap::build(b"short");
        assert_eq!(map.len(), 1);
        assert_eq!(map.range_of(0), 0..5);
        assert!(map.verify(0, b"short"));
        assert!(!map.verify(0, b"other"));
    }

    /// The last chunk's shortness is part of what it hashes, so a padded
    /// version must not verify.
    #[test]
    fn a_padded_last_chunk_does_not_verify() {
        let bytes = body(CHUNK_BYTES_USIZE + 10, 5);
        let map = ChunkMap::build(&bytes);
        let mut padded = bytes[CHUNK_BYTES_USIZE..].to_vec();
        padded.resize(CHUNK_BYTES_USIZE, 0);
        assert!(map.verify(1, &bytes[CHUNK_BYTES_USIZE..]));
        assert!(!map.verify(1, &padded));
    }

    #[test]
    fn exact_multiples_do_not_gain_an_empty_trailing_chunk() {
        let map = ChunkMap::build(&body(CHUNK_BYTES_USIZE * 2, 1));
        assert_eq!(map.len(), 2);
        assert_eq!(map.range_of(1), CHUNK_BYTES..CHUNK_BYTES * 2);
    }

    #[test]
    fn byte_ranges_map_onto_chunk_indices() {
        let map = ChunkMap::build(&body(CHUNK_BYTES_USIZE * 4, 2));
        assert_eq!(map.indices_for(0, CHUNK_BYTES), 0..1);
        // A window straddling a boundary needs both chunks.
        assert_eq!(map.indices_for(CHUNK_BYTES - 1, 2), 0..2);
        assert_eq!(map.indices_for(0, CHUNK_BYTES * 4), 0..4);
        // Past the end, and zero length, both want nothing.
        assert_eq!(map.indices_for(CHUNK_BYTES * 9, 10), 0..0);
        assert_eq!(map.indices_for(0, 0), 0..0);
        // A read running past the end is clamped rather than refused.
        assert_eq!(map.indices_for(CHUNK_BYTES * 3, CHUNK_BYTES * 99), 3..4);
    }

    /// The invariant a caller narrowing a full-row scan down to this range is
    /// relying on: nothing storable falls outside it.
    ///
    /// `agent-share`'s browser client walks these positions to decide which
    /// chunks of a read it can keep, and it keeps a chunk only when the chunk
    /// lies wholly inside the read. If this range ever missed one of those, the
    /// symptom would be a file that transfers in full and still never becomes
    /// seedable — silent, and only visible as coverage that stops short.
    #[test]
    fn byte_ranges_cover_every_chunk_a_read_could_hold_whole() {
        let map = ChunkMap::build(&body(CHUNK_BYTES_USIZE * 8 + 17, 3));
        for offset in [0, 1, 17, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES * 3 + 5] {
            for len in [1, 17, CHUNK_BYTES, CHUNK_BYTES * 4, CHUNK_BYTES * 99] {
                let end = offset + len;
                let narrowed = map.indices_for(offset, len);
                let whole = (0..map.len()).filter(|position| {
                    let range = map.range_of(*position);
                    range.start >= offset && range.end <= end
                });
                for position in whole {
                    assert!(
                        narrowed.contains(&position),
                        "chunk {position} fits wholly in {offset}..{end} but {narrowed:?} skips it"
                    );
                }
            }
        }
    }

    #[test]
    fn verifying_past_the_end_is_false_not_a_panic() {
        let map = ChunkMap::build(b"tiny");
        assert!(!map.verify(9, b"tiny"));
        assert_eq!(map.leaf(9), None);
    }

    #[test]
    fn coverage_tracks_what_is_held() {
        let mut coverage = Coverage::empty(10);
        assert!(!coverage.is_complete());
        assert_eq!(coverage.count(), 0);
        coverage.insert(0);
        coverage.insert(9);
        assert!(coverage.contains(0));
        assert!(coverage.contains(9));
        assert!(!coverage.contains(5));
        assert_eq!(coverage.count(), 2);
        assert_eq!(coverage.missing().count(), 8);
        coverage.remove(0);
        assert!(!coverage.contains(0));
        assert_eq!(Coverage::complete(10).count(), 10);
        assert!(Coverage::complete(10).is_complete());
    }

    /// Out-of-range writes are ignored rather than panicking or growing the
    /// map: a peer describing a different file must not be able to resize ours.
    #[test]
    fn out_of_range_coverage_is_ignored() {
        let mut coverage = Coverage::empty(4);
        coverage.insert(99);
        coverage.remove(99);
        assert!(!coverage.contains(99));
        assert_eq!(coverage.len(), 4);
        assert_eq!(coverage.count(), 0);
    }

    #[test]
    fn coverage_survives_a_round_trip_through_bits() {
        let mut coverage = Coverage::empty(20);
        for index in [0, 3, 7, 19] {
            coverage.insert(index);
        }
        let restored = Coverage::from_bits(coverage.as_bits(), 20).expect("round trip");
        assert_eq!(restored, coverage);
        assert!(Coverage::from_bits(&[0u8; 1], 20).is_err());
    }

    #[test]
    fn coverage_unions_across_peers() {
        let mut ours = Coverage::empty(8);
        ours.insert(1);
        let mut theirs = Coverage::empty(8);
        theirs.insert(6);
        ours.union(&theirs);
        assert!(ours.contains(1) && ours.contains(6));
        assert_eq!(ours.count(), 2);
    }

    #[test]
    fn a_version_change_unbinds_a_file() {
        let file = FileId {
            key: "a.txt".to_owned(),
            size: 10,
            mtime: 100,
        };
        assert!(file.same_version(&file.clone()));
        let touched = FileId {
            mtime: 101,
            ..file.clone()
        };
        let grown = FileId {
            size: 11,
            ..file.clone()
        };
        assert!(!file.same_version(&touched));
        assert!(!file.same_version(&grown));
    }

    #[test]
    fn digests_round_trip_through_hex() {
        let hash = chunk_hash(b"payload");
        assert_eq!(ChunkHash::from_hex(&hash.to_hex()).expect("hex"), hash);
        let root = ChunkMap::build(b"payload").root();
        assert_eq!(Root::from_hex(&root.to_hex()).expect("hex"), root);
        assert_eq!(hash.to_hex().len(), 64);
        assert!(ChunkHash::from_hex("nope").is_err());
        assert!(ChunkHash::from_hex(&"z".repeat(64)).is_err());
    }

    /// The length guard counts bytes but the old decoder sliced the `&str`,
    /// which panics at a char boundary. A store directory or a `binds.tsv`
    /// row is where such a name arrives from, and both are documented to
    /// degrade a row at a time rather than abort.
    #[test]
    fn non_ascii_hex_of_the_right_byte_length_errors_rather_than_panics() {
        let text = format!("{}a", "€".repeat(21));
        assert_eq!(text.len(), 64);
        assert!(ChunkHash::from_hex(&text).is_err());
        assert!(Root::from_hex(&text).is_err());
    }

    /// A root and a chunk hash are different types *and* different values, even
    /// for a one-chunk file whose row holds exactly one address.
    #[test]
    fn a_root_is_not_its_own_leaf() {
        let map = ChunkMap::build(b"single chunk");
        assert_ne!(map.root().as_bytes(), map.leaf(0).expect("one").as_bytes());
    }

    #[test]
    #[should_panic(expected = "only the last chunk")]
    fn a_short_chunk_mid_stream_is_a_caller_bug() {
        let mut builder = ChunkMapBuilder::new();
        builder.push(b"short");
        builder.push(b"another");
    }
}
