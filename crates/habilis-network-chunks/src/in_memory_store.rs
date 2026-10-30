//! An in-memory store: the reference implementation, and the one the
//! conformance suite drives first.
//!
//! This backend **does** own its bytes, unlike the origin that matters most in
//! production. It has nowhere else to put them, and that is the point of having
//! it: every rule the traits state can be checked here without a filesystem, a
//! browser, or a peer, so a conformance failure elsewhere is a backend bug
//! rather than an ambiguity in the contract.
//!
//! `Mutex` rather than `RefCell`, and that is the `?Send` bargain being settled
//! here rather than in the trait: futures are `?Send` so a browser can implement
//! one at all, and a caller that needs `Send` gets it from the backend. Every
//! lock below is taken and released without an await in between.

use std::collections::{HashMap, HashSet};
use std::iter::Enumerate;
use std::slice;
use std::sync::Mutex;

use crate::ChunkError;

use crate::{ChunkHash, ChunkMap, ChunkSource, ChunkStore, Coverage, FileId, Root, chunk_hash};

/// Poisoning is a panic in another thread, not a condition worth modelling
/// separately at every call site.
/// A store that keeps everything in memory and forgets it on drop.
///
/// # Examples
///
/// A new in-memory store holds no chunk.
///
/// ```
/// use habilis_network_chunks::InMemoryStore;
///
/// let store = InMemoryStore::new();
/// assert_eq!(store.stored_chunks(), 0);
/// ```
#[derive(Debug, Default)]
pub struct InMemoryStore {
    chunks: Mutex<HashMap<ChunkHash, Vec<u8>>>,
    maps: Mutex<HashMap<Root, ChunkMap>>,
    /// `key -> (size, mtime, root)`, the version gate.
    binds: Mutex<HashMap<String, (u64, i64, Root)>>,
    /// Live set for the current reclamation pass. `None` when no pass is open,
    /// which is what makes a sweep with no preceding `start_marking` clear
    /// everything rather than silently keeping it — marks are the only thing
    /// that keeps data alive, and a caller that forgot to mark should find that
    /// out immediately rather than months later.
    marks: Mutex<Option<HashSet<ChunkHash>>>,
}

impl InMemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many distinct chunks are stored.
    ///
    /// Distinct, so two files sharing content count once — which is the whole
    /// dedup claim, and worth being able to assert directly.
    ///
    /// # Panics
    /// The internal lock was poisoned by a panic in another thread.
    #[must_use]
    pub fn stored_chunks(&self) -> usize {
        self.chunks.lock().expect("chunk lock").len()
    }
}

impl ChunkSource for InMemoryStore {
    async fn get(&self, hash: ChunkHash) -> Result<Option<Vec<u8>>, ChunkError> {
        Ok(self
            .chunks
            .lock()
            .map_err(|_| ChunkError::Poisoned("chunk"))?
            .get(&hash)
            .cloned())
    }

    async fn has(&self, hash: ChunkHash) -> Result<bool, ChunkError> {
        Ok(self
            .chunks
            .lock()
            .map_err(|_| ChunkError::Poisoned("chunk"))?
            .contains_key(&hash))
    }

    async fn map(&self, root: Root) -> Result<Option<ChunkMap>, ChunkError> {
        Ok(self
            .maps
            .lock()
            .map_err(|_| ChunkError::Poisoned("map"))?
            .get(&root)
            .cloned())
    }

    async fn coverage(&self, root: Root) -> Result<Coverage, ChunkError> {
        let map = {
            let maps = self.maps.lock().map_err(|_| ChunkError::Poisoned("map"))?;
            maps.get(&root).cloned()
        };
        // A root this store has never seen covers nothing. Not an error: a peer
        // may ask about a file we have simply never been told about.
        let Some(map) = map else {
            return Ok(Coverage::empty(0));
        };
        let chunks = self
            .chunks
            .lock()
            .map_err(|_| ChunkError::Poisoned("chunk"))?;
        let mut coverage = Coverage::empty(map.len());
        let indexed_leaves: Enumerate<slice::Iter<'_, ChunkHash>> = map.leaves().iter().enumerate();
        for (index, leaf) in indexed_leaves {
            if chunks.contains_key(leaf) {
                coverage.insert(index);
            }
        }
        Ok(coverage)
    }

    async fn bind(&self, file: &FileId) -> Result<Option<Root>, ChunkError> {
        let binds = self
            .binds
            .lock()
            .map_err(|_| ChunkError::Poisoned("bind"))?;
        let Some((size, mtime, root)) = binds.get(&file.key) else {
            return Ok(None);
        };
        // The version gate. A file at this key with a different size or mtime is
        // different content, and answering for it under this root is exactly the
        // silent corruption the gate exists to prevent.
        if *size != file.size || *mtime != file.mtime {
            return Ok(None);
        }
        Ok(Some(*root))
    }
}

impl ChunkStore for InMemoryStore {
    async fn put(&self, hash: ChunkHash, bytes: &[u8]) -> Result<(), ChunkError> {
        // Verify before storing, always. A peer that sends bytes addressing
        // something else costs its own bandwidth and nothing of ours; storing
        // first and checking later would let it cost our disk too.
        let actual = chunk_hash(bytes);
        if actual != hash {
            return Err(ChunkError::Malformed(format!(
                "these bytes address {actual}, not {hash}"
            )));
        }
        self.chunks
            .lock()
            .map_err(|_| ChunkError::Poisoned("chunk"))?
            .insert(hash, bytes.to_vec());
        Ok(())
    }

    async fn put_map(&self, map: &ChunkMap) -> Result<(), ChunkError> {
        let mut maps = self.maps.lock().map_err(|_| ChunkError::Poisoned("map"))?;
        maps.insert(map.root(), map.clone());
        Ok(())
    }

    async fn set_bind(&self, file: &FileId, root: Root) -> Result<(), ChunkError> {
        self.binds
            .lock()
            .map_err(|_| ChunkError::Poisoned("bind"))?
            .insert(file.key.clone(), (file.size, file.mtime, root));
        Ok(())
    }

    async fn start_marking(&self) -> Result<(), ChunkError> {
        *self
            .marks
            .lock()
            .map_err(|_| ChunkError::Poisoned("mark"))? = Some(HashSet::new());
        Ok(())
    }

    async fn mark(&self, root: Root) -> Result<(), ChunkError> {
        let leaves = {
            let maps = self.maps.lock().map_err(|_| ChunkError::Poisoned("map"))?;
            maps.get(&root).map(|map| map.leaves().to_vec())
        };
        // Marking a root we hold no row for is a caller error worth naming: it
        // means the live set was derived from something other than the persisted
        // maps, which is precisely how a sweep eats live data.
        let leaves = leaves.ok_or_else(|| {
            ChunkError::Malformed(
                "cannot mark a root with no stored chunk map — derive the live set \
             from persisted maps, never from an in-memory held-set"
                    .to_owned(),
            )
        })?;
        let mut marks = self
            .marks
            .lock()
            .map_err(|_| ChunkError::Poisoned("mark"))?;
        marks.get_or_insert_with(HashSet::new).extend(leaves);
        Ok(())
    }

    async fn sweep(&self) -> Result<u64, ChunkError> {
        let mut marks = self
            .marks
            .lock()
            .map_err(|_| ChunkError::Poisoned("mark"))?;
        let live = marks.take().unwrap_or_default();
        let mut chunks = self
            .chunks
            .lock()
            .map_err(|_| ChunkError::Poisoned("chunk"))?;
        let before = chunks.len();
        chunks.retain(|hash, _| live.contains(hash));
        Ok(u64::try_from(before - chunks.len()).unwrap_or(u64::MAX))
    }

    async fn clear(&self, hashes: &[ChunkHash]) -> Result<(), ChunkError> {
        let mut chunks = self
            .chunks
            .lock()
            .map_err(|_| ChunkError::Poisoned("chunk"))?;
        for hash in hashes {
            chunks.remove(hash);
        }
        Ok(())
    }
}
