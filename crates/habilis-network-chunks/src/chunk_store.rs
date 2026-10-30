use std::future::Future;

use crate::{ChunkError, ChunkHash, ChunkMap, Coverage, FileId, Root};

/// The read half: everything needed to *answer* for chunks.
///
/// Split from [`ChunkStore`] because the most important implementor cannot
/// write at all. A native origin serves the user's own files **in place** — it
/// holds addresses beside them and reads through — so `put` would have to
/// either copy the bytes, which is the whole thing this crate avoids, or lie.
/// A source that only reads is the honest shape, and it means the conformance
/// suite can hold every backend to the same read contract without carving out
/// exceptions.
///
/// # Examples
///
/// A source that holds no chunk answers that it has none.
///
/// ```
/// use std::future::{Future, ready};
///
/// use habilis_network_chunks::{ChunkError, ChunkHash, ChunkMap, ChunkSource, Coverage, FileId, Root};
///
/// struct Empty;
///
/// impl ChunkSource for Empty {
///     fn get(&self, _hash: ChunkHash) -> impl Future<Output = Result<Option<Vec<u8>>, ChunkError>> {
///         ready(Ok(None))
///     }
///
///     fn has(&self, _hash: ChunkHash) -> impl Future<Output = Result<bool, ChunkError>> {
///         ready(Ok(false))
///     }
///
///     fn map(&self, _root: Root) -> impl Future<Output = Result<Option<ChunkMap>, ChunkError>> {
///         ready(Ok(None))
///     }
///
///     fn coverage(&self, _root: Root) -> impl Future<Output = Result<Coverage, ChunkError>> {
///         ready(Ok(Coverage::empty(0)))
///     }
///
///     fn bind(&self, _file: &FileId) -> impl Future<Output = Result<Option<Root>, ChunkError>> {
///         ready(Ok(None))
///     }
/// }
/// ```
pub trait ChunkSource {
    /// One chunk's bytes, by address.
    ///
    /// `None` means "not held", which is ordinary. A backend that does not own
    /// its bytes resolves the address through a reverse index to a file and an
    /// offset, and reads through — see the module docs.
    fn get(&self, hash: ChunkHash) -> impl Future<Output = Result<Option<Vec<u8>>, ChunkError>>;

    /// Whether this chunk can be answered for right now.
    fn has(&self, hash: ChunkHash) -> impl Future<Output = Result<bool, ChunkError>>;

    /// The leaf row for `root`, if this source knows it.
    fn map(&self, root: Root) -> impl Future<Output = Result<Option<ChunkMap>, ChunkError>>;

    /// Which chunks of `root` this source can answer for.
    ///
    /// Empty coverage for a root it has never seen. This is the answer to
    /// "what can I seed", and the source for both an availability view and a
    /// scheduler.
    ///
    /// **Partial is a first-class answer.** A source holding some of a file
    /// serves those chunks and says so; there is no notion of holding a file
    /// "in full" before it may be shared.
    fn coverage(&self, root: Root) -> impl Future<Output = Result<Coverage, ChunkError>>;

    /// Coverage for several roots, asked once.
    ///
    /// One `Coverage` per input root, in the same order, so a caller can zip the
    /// answers back onto whatever it asked about. An unknown root covers
    /// nothing, exactly as [`Self::coverage`] says.
    ///
    /// Exists because "what do I hold of *everything*" is a different question
    /// from "what do I hold of *this*", and a backend may answer them by
    /// different routes. The default is the obvious loop, which is right
    /// wherever a per-root answer already costs what the row costs; a backend
    /// where it does not overrides this. See `IdbStore`, where the single-root
    /// answer probes leaves and the batched one takes a single snapshot of the
    /// keyspace — the loop there would re-scan the whole store per root.
    ///
    /// # Errors
    /// Whatever the backend's [`Self::coverage`] would raise for one root.
    fn coverage_of(
        &self,
        roots: &[Root],
    ) -> impl Future<Output = Result<Vec<Coverage>, ChunkError>> {
        async move {
            let mut out = Vec::with_capacity(roots.len());
            for root in roots {
                out.push(self.coverage(*root).await?);
            }
            Ok(out)
        }
    }

    /// The root bound to this file *version*, if the file still matches it.
    ///
    /// `None` means *do not answer for this*: either nothing was ever bound, or
    /// the file moved underneath and the row describes content that is gone.
    /// Both are ordinary, neither is an error.
    fn bind(&self, file: &FileId) -> impl Future<Output = Result<Option<Root>, ChunkError>>;
}

/// The write half: a store that keeps chunks of its own.
///
/// # Ordering, which is a correctness rule and not a preference
///
/// Coverage that outlives its chunks is the dangerous direction: it makes this
/// peer advertise bytes it cannot serve, which to everyone else looks like a
/// peer that lies. **Write the chunk, then the coverage that claims it.** The
/// reverse — chunks present but coverage lost — costs a re-fetch and nothing
/// else.
///
/// # Examples
///
/// A store keeps chunks by their hash. The doc test compiles it but does not run it.
///
/// The native stores do their work when the call is made. `IdbStore` (wasm) starts its
/// `IndexedDB` request on first poll.
///
/// ```no_run
/// use habilis_network_chunks::{ChunkError, ChunkSource, ChunkStore, InMemoryStore, chunk_hash};
///
/// # async fn demo(store: &InMemoryStore) -> Result<(), ChunkError> {
/// let hash = chunk_hash(b"hello");
/// store.put(hash, b"hello").await?;
/// assert!(store.has(hash).await?);
/// # Ok(())
/// # }
/// ```
pub trait ChunkStore: ChunkSource {
    /// Store one chunk, verifying it addresses what the caller claims.
    ///
    /// # Errors
    /// `blake3(bytes) != hash`, or the backend could not write.
    fn put(&self, hash: ChunkHash, bytes: &[u8]) -> impl Future<Output = Result<(), ChunkError>>;

    /// Record a leaf row, so its chunks can be named and swept.
    fn put_map(&self, map: &ChunkMap) -> impl Future<Output = Result<(), ChunkError>>;

    /// Record that this file version hashes to `root`.
    fn set_bind(&self, file: &FileId, root: Root) -> impl Future<Output = Result<(), ChunkError>>;

    /// Begin a reclamation pass, clearing every previous mark.
    ///
    /// Reclamation is mark-and-sweep rather than reference counting: nothing is
    /// mutated in a content-addressed store, so there are no orphans to track —
    /// only garbage, collected when the caller decides.
    fn start_marking(&self) -> impl Future<Output = Result<(), ChunkError>>;

    /// Mark every chunk of `root` as live for the current pass.
    ///
    /// **Derive the set of roots from persisted maps, never from an in-memory
    /// held-set.** A set that lost an entry to a reload would make [`sweep`]
    /// delete live data.
    ///
    /// [`sweep`]: ChunkStore::sweep
    fn mark(&self, root: Root) -> impl Future<Output = Result<(), ChunkError>>;

    /// Delete every chunk not marked in the current pass, returning the count.
    fn sweep(&self) -> impl Future<Output = Result<u64, ChunkError>>;

    /// Drop specific chunks, keeping everything else.
    ///
    /// Local eviction, typically under storage pressure. **A caller that clears
    /// must re-advertise**, or readers keep being sent to a peer that no longer
    /// has what it claimed.
    fn clear(&self, hashes: &[ChunkHash]) -> impl Future<Output = Result<(), ChunkError>>;
}
