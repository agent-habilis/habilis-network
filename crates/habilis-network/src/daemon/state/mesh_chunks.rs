use std::borrow::Cow;
use std::collections::HashSet;
use std::ops::Range;
use std::path::Path;
use std::sync::Mutex;
#[cfg(not(target_arch = "wasm32"))]
use std::{fs, io::ErrorKind};

#[cfg(test)]
use habilis_network_chunks::ChunkHash;
use habilis_network_chunks::{ChunkError, ChunkMap, ChunkStore, InMemoryStore, Root};

use crate::protocol::{SymmetricKey, seal_error};

#[cfg(not(target_arch = "wasm32"))]
use habilis_network_chunks::DiskStore;

/// The chunk store of one run of a mesh. It holds the chunks of the own values that are too
/// large for a slice, and the chunks that were fetched for the slices of other peers. It starts
/// empty: a run never reads the chunks of an earlier run.
#[derive(Debug)]
pub(crate) struct MeshChunks {
    store: Store,
    /// The roots whose map this run put and has not dropped. A run starts with an empty store, so no
    /// other map can be there.
    mapped: Mutex<HashSet<Root>>,
    /// The key that seals a value before it is cut into chunks, on a passworded mesh. Without it the chunks are
    /// the bytes of the value, and the chunk store is as open as the `state` channel of a mesh with no password.
    key: Option<SymmetricKey>,
}

#[derive(Debug)]
enum Store {
    Memory(InMemoryStore),
    #[cfg(not(target_arch = "wasm32"))]
    Disk(DiskStore),
}

impl MeshChunks {
    /// Opens the store in `folder`, or in memory when there is no folder. A folder that an earlier
    /// run filled is cleared first.
    ///
    /// # Errors
    ///
    /// The folder cannot be made, or cannot be opened as a chunk store.
    #[cfg_attr(
        target_arch = "wasm32",
        expect(
            clippy::unnecessary_wraps,
            reason = "the same signature as the version for a target with files"
        )
    )]
    pub(crate) fn open(folder: Option<&Path>) -> Result<Self, ChunkError> {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(folder) = folder {
            match fs::remove_dir_all(folder) {
                Err(error) if error.kind() != ErrorKind::NotFound => {
                    return Err(ChunkError::Store {
                        step: format!("clearing {}", folder.display()),
                        source: error.into(),
                    });
                }
                Ok(()) | Err(_) => {}
            }
            return Ok(Self {
                store: Store::Disk(DiskStore::open(folder)?),
                mapped: Mutex::default(),
                key: None,
            });
        }
        #[cfg(target_arch = "wasm32")]
        let _ = folder;
        Ok(Self {
            store: Store::Memory(InMemoryStore::new()),
            mapped: Mutex::default(),
            key: None,
        })
    }

    /// Seals each value under `key` from now on. `None` keeps the chunks as the bytes of the value.
    pub(crate) fn key(mut self, key: Option<SymmetricKey>) -> Self {
        self.key = key;
        self
    }

    /// Cuts `bytes` into chunks, keeps them with their chunk map, and returns the root.
    ///
    /// # Errors
    ///
    /// The store cannot keep a chunk or the map.
    pub(crate) async fn put_value(&self, bytes: &[u8]) -> Result<Root, ChunkError> {
        let stored: Cow<'_, [u8]> = self.key.as_ref().map_or(Cow::Borrowed(bytes), |key| {
            Cow::Owned(seal_error::seal_symmetric(key, bytes))
        });
        let map = ChunkMap::build(&stored);
        for index in 0..map.len() {
            let chunk = chunk_at(&stored, map.range_of(index)).ok_or_else(|| {
                ChunkError::Malformed("a chunk range is past the value".to_owned())
            })?;
            let hash = map.leaf(index).ok_or_else(|| {
                ChunkError::Malformed("a chunk has no hash in its map".to_owned())
            })?;
            match &self.store {
                Store::Memory(store) => store.put(hash, chunk).await?,
                #[cfg(not(target_arch = "wasm32"))]
                Store::Disk(store) => store.put(hash, chunk).await?,
            }
        }
        match &self.store {
            Store::Memory(store) => store.put_map(&map).await?,
            #[cfg(not(target_arch = "wasm32"))]
            Store::Disk(store) => store.put_map(&map).await?,
        }
        self.mapped
            .lock()
            .map_err(|_| ChunkError::Poisoned("mapped"))?
            .insert(map.root());
        Ok(map.root())
    }

    /// Drops every chunk that no root of `roots` names, and the map of each root that this run put and
    /// `roots` does not name.
    ///
    /// # Errors
    ///
    /// A root has no stored map, or the store cannot sweep or drop a map.
    pub(crate) async fn keep_only(
        &self,
        roots: impl IntoIterator<Item = Root>,
    ) -> Result<(), ChunkError> {
        let kept: HashSet<Root> = roots.into_iter().collect();
        let stale: Vec<Root> = {
            let mapped = self
                .mapped
                .lock()
                .map_err(|_| ChunkError::Poisoned("mapped"))?;
            mapped.difference(&kept).copied().collect()
        };
        match &self.store {
            Store::Memory(store) => sweep_except(store, &kept, &stale).await?,
            #[cfg(not(target_arch = "wasm32"))]
            Store::Disk(store) => sweep_except(store, &kept, &stale).await?,
        }
        let mut mapped = self
            .mapped
            .lock()
            .map_err(|_| ChunkError::Poisoned("mapped"))?;
        for root in &stale {
            mapped.remove(root);
        }
        Ok(())
    }

    /// The chunk map of `root`, when the store holds it.
    ///
    /// # Errors
    ///
    /// The store cannot read the map.
    #[cfg(test)]
    pub(crate) async fn map(&self, root: Root) -> Result<Option<ChunkMap>, ChunkError> {
        use habilis_network_chunks::ChunkSource as _;

        match &self.store {
            Store::Memory(store) => store.map(root).await,
            #[cfg(not(target_arch = "wasm32"))]
            Store::Disk(store) => store.map(root).await,
        }
    }

    /// The bytes of the chunk with `hash`, when the store holds it.
    ///
    /// # Errors
    ///
    /// The store cannot read the chunk.
    #[cfg(test)]
    pub(crate) async fn chunk(&self, hash: ChunkHash) -> Result<Option<Vec<u8>>, ChunkError> {
        use habilis_network_chunks::ChunkSource as _;

        match &self.store {
            Store::Memory(store) => store.get(hash).await,
            #[cfg(not(target_arch = "wasm32"))]
            Store::Disk(store) => store.get(hash).await,
        }
    }

    /// Whether the store holds the chunk map of `root`.
    #[cfg(test)]
    pub(crate) async fn has_map(&self, root: Root) -> bool {
        use habilis_network_chunks::ChunkSource as _;

        let map = match &self.store {
            Store::Memory(store) => store.map(root).await,
            #[cfg(not(target_arch = "wasm32"))]
            Store::Disk(store) => store.map(root).await,
        };
        map.expect("a map lookup").is_some()
    }

    /// The bytes that the chunks of `root` hold, in order, when the store is in memory.
    #[cfg(test)]
    pub(crate) async fn stored_bytes(&self, root: Root) -> Vec<u8> {
        use habilis_network_chunks::ChunkSource as _;

        let Store::Memory(store) = &self.store else {
            panic!("the bytes can be read from a store in memory only");
        };
        let map = store
            .map(root)
            .await
            .expect("a map lookup")
            .expect("a stored map");
        let mut bytes = Vec::new();
        for index in 0..map.len() {
            let hash = map.leaf(index).expect("a leaf of the map");
            bytes.extend(
                store
                    .get(hash)
                    .await
                    .expect("a chunk lookup")
                    .expect("a stored chunk"),
            );
        }
        bytes
    }

    /// How many chunks the store holds, when it is in memory.
    #[cfg(test)]
    pub(crate) fn stored_chunks(&self) -> usize {
        match &self.store {
            Store::Memory(store) => store.stored_chunks(),
            #[cfg(not(target_arch = "wasm32"))]
            Store::Disk(_) => usize::MAX,
        }
    }
}

/// Sweeps every chunk that no root of `kept` names, then drops the map of each root of `stale`.
async fn sweep_except(
    store: &impl ChunkStore,
    kept: &HashSet<Root>,
    stale: &[Root],
) -> Result<(), ChunkError> {
    store.start_marking().await?;
    for root in kept {
        store.mark(*root).await?;
    }
    store.sweep().await?;
    for root in stale {
        store.drop_map(*root).await?;
    }
    Ok(())
}

/// The bytes of `bytes` in `range`, when the range lies inside them.
fn chunk_at(bytes: &[u8], range: Range<u64>) -> Option<&[u8]> {
    let start = usize::try_from(range.start).ok()?;
    let end = usize::try_from(range.end).ok()?;
    bytes.get(start..end)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::{env, fs, process};

    use habilis_network_chunks::{ChunkSource as _, ChunkStore as _, DiskStore, chunk_hash};

    use crate::protocol::SymmetricKey;
    use crate::protocol::seal_error::{SEAL_SYMMETRIC_OVERHEAD, open_symmetric};

    use super::{MeshChunks, Store};

    /// A temp dir that goes away when the test ends, also when an assert fails.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = env::temp_dir().join(format!("{name}-{}", process::id()));
            drop(fs::remove_dir_all(&dir));
            fs::create_dir_all(&dir).expect("a temp dir");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    #[test]
    fn a_store_with_no_folder_is_in_memory() {
        let chunks = MeshChunks::open(None).expect("an in-memory store");
        assert!(
            matches!(chunks.store, Store::Memory(_)),
            "no folder must give a store in memory"
        );
    }

    #[tokio::test]
    async fn keeping_only_some_roots_drops_the_map_of_each_other_root() {
        let chunks = MeshChunks::open(None).expect("an in-memory store");
        let old = chunks.put_value(b"the old value").await.expect("a value");
        let kept = chunks.put_value(b"the kept value").await.expect("a value");
        chunks.keep_only([kept]).await.expect("a sweep");
        assert!(
            !chunks.has_map(old).await,
            "the map of a root that is not kept must be dropped"
        );
        assert!(
            chunks.has_map(kept).await,
            "the map of a kept root must stay"
        );
        assert_eq!(
            chunks.stored_chunks(),
            1,
            "the chunk of the old value must be swept"
        );
    }

    #[tokio::test]
    async fn without_a_key_the_chunks_are_the_bytes_of_the_value() {
        let chunks = MeshChunks::open(None).expect("an in-memory store");
        let root = chunks
            .put_value(b"the value of a mesh with no password")
            .await
            .expect("a value");
        assert_eq!(
            chunks.stored_bytes(root).await,
            b"the value of a mesh with no password",
            "a mesh with no password must keep the value as it is"
        );
    }

    #[tokio::test]
    async fn with_a_key_the_chunks_are_sealed_and_open_to_the_value() {
        let key = SymmetricKey::from([5u8; 32]);
        let chunks = MeshChunks::open(None)
            .expect("an in-memory store")
            .key(Some(key.clone()));
        let value = b"the value of a passworded mesh".as_slice();
        let root = chunks.put_value(value).await.expect("a value");
        let stored = chunks.stored_bytes(root).await;
        assert_eq!(
            stored.len(),
            value.len() + SEAL_SYMMETRIC_OVERHEAD,
            "the chunks must hold the sealed value, which is the overhead longer"
        );
        assert!(
            !stored.windows(value.len()).any(|window| window == value),
            "the chunks of a passworded mesh must not hold the plaintext"
        );
        assert_eq!(
            open_symmetric(&key, &stored).expect("the key opens the chunks"),
            value,
            "the key of the mesh must open the stored bytes to the value"
        );
        assert!(
            open_symmetric(&SymmetricKey::from([6u8; 32]), &stored).is_err(),
            "another key must not open the stored bytes"
        );
    }

    #[tokio::test]
    async fn a_store_in_a_folder_starts_empty_whatever_an_earlier_run_left() {
        let dir = TempDir::new("habilis-mesh-chunks-clear");
        let folder = dir.0.join("run.chunks");
        let hash = chunk_hash(b"left by an earlier run");
        DiskStore::open(&folder)
            .expect("an earlier store")
            .put(hash, b"left by an earlier run")
            .await
            .expect("a chunk");
        let chunks = MeshChunks::open(Some(&folder)).expect("a store in the folder");
        let Store::Disk(store) = &chunks.store else {
            panic!("a folder must give a store on disk");
        };
        assert!(
            !store.has(hash).await.expect("a lookup"),
            "the chunk of an earlier run must be gone"
        );
    }
}
