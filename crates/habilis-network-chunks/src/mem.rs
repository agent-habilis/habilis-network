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
use std::sync::Mutex;

use anyhow::{Context as _, Result, bail};

use crate::{ChunkHash, ChunkMap, ChunkSource, ChunkStore, Coverage, FileId, Root, chunk_hash};

/// Poisoning is a panic in another thread, not a condition worth modelling
/// separately at every call site.
fn poisoned(what: &str) -> anyhow::Error {
    anyhow::anyhow!("the {what} lock was poisoned by a panic in another thread")
}

/// A store that keeps everything in memory and forgets it on drop.
#[derive(Debug, Default)]
pub struct MemStore {
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

impl MemStore {
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

impl ChunkSource for MemStore {
    async fn get(&self, hash: ChunkHash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .chunks
            .lock()
            .map_err(|_| poisoned("chunk"))?
            .get(&hash)
            .cloned())
    }

    async fn has(&self, hash: ChunkHash) -> Result<bool> {
        Ok(self
            .chunks
            .lock()
            .map_err(|_| poisoned("chunk"))?
            .contains_key(&hash))
    }

    async fn map(&self, root: Root) -> Result<Option<ChunkMap>> {
        Ok(self
            .maps
            .lock()
            .map_err(|_| poisoned("map"))?
            .get(&root)
            .cloned())
    }

    async fn coverage(&self, root: Root) -> Result<Coverage> {
        let map = {
            let maps = self.maps.lock().map_err(|_| poisoned("map"))?;
            maps.get(&root).cloned()
        };
        // A root this store has never seen covers nothing. Not an error: a peer
        // may ask about a file we have simply never been told about.
        let Some(map) = map else {
            return Ok(Coverage::empty(0));
        };
        let chunks = self.chunks.lock().map_err(|_| poisoned("chunk"))?;
        let mut coverage = Coverage::empty(map.len());
        for (index, leaf) in map.leaves().iter().enumerate() {
            if chunks.contains_key(leaf) {
                coverage.insert(index);
            }
        }
        Ok(coverage)
    }

    async fn bind(&self, file: &FileId) -> Result<Option<Root>> {
        let binds = self.binds.lock().map_err(|_| poisoned("bind"))?;
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

impl ChunkStore for MemStore {
    async fn put(&self, hash: ChunkHash, bytes: &[u8]) -> Result<()> {
        // Verify before storing, always. A peer that sends bytes addressing
        // something else costs its own bandwidth and nothing of ours; storing
        // first and checking later would let it cost our disk too.
        let actual = chunk_hash(bytes);
        if actual != hash {
            bail!("these bytes address {actual}, not {hash}");
        }
        self.chunks
            .lock()
            .map_err(|_| poisoned("chunk"))?
            .insert(hash, bytes.to_vec());
        Ok(())
    }

    async fn put_map(&self, map: &ChunkMap) -> Result<()> {
        self.maps
            .lock()
            .map_err(|_| poisoned("map"))?
            .insert(map.root(), map.clone());
        Ok(())
    }

    async fn set_bind(&self, file: &FileId, root: Root) -> Result<()> {
        self.binds
            .lock()
            .map_err(|_| poisoned("bind"))?
            .insert(file.key.clone(), (file.size, file.mtime, root));
        Ok(())
    }

    async fn start_marking(&self) -> Result<()> {
        *self.marks.lock().map_err(|_| poisoned("mark"))? = Some(HashSet::new());
        Ok(())
    }

    async fn mark(&self, root: Root) -> Result<()> {
        let leaves = {
            let maps = self.maps.lock().map_err(|_| poisoned("map"))?;
            maps.get(&root).map(|map| map.leaves().to_vec())
        };
        // Marking a root we hold no row for is a caller error worth naming: it
        // means the live set was derived from something other than the persisted
        // maps, which is precisely how a sweep eats live data.
        let leaves = leaves.context(
            "cannot mark a root with no stored chunk map — derive the live set \
             from persisted maps, never from an in-memory held-set",
        )?;
        let mut marks = self.marks.lock().map_err(|_| poisoned("mark"))?;
        marks.get_or_insert_with(HashSet::new).extend(leaves);
        Ok(())
    }

    async fn sweep(&self) -> Result<u64> {
        let live = self
            .marks
            .lock()
            .map_err(|_| poisoned("mark"))?
            .take()
            .unwrap_or_default();
        let mut chunks = self.chunks.lock().map_err(|_| poisoned("chunk"))?;
        let before = chunks.len();
        chunks.retain(|hash, _| live.contains(hash));
        Ok(u64::try_from(before - chunks.len()).unwrap_or(u64::MAX))
    }

    async fn clear(&self, hashes: &[ChunkHash]) -> Result<()> {
        let mut chunks = self.chunks.lock().map_err(|_| poisoned("chunk"))?;
        for hash in hashes {
            chunks.remove(hash);
        }
        Ok(())
    }
}
