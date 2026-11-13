use std::ops::Range;
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::{fs, io::ErrorKind};

use habilis_network_chunks::{ChunkError, ChunkMap, ChunkStore as _, InMemoryStore, Root};

#[cfg(not(target_arch = "wasm32"))]
use habilis_network_chunks::DiskStore;

/// The chunk store of one run of a mesh. It holds the chunks of the own values that are too
/// large for a slice, and the chunks that were fetched for the slices of other peers. It starts
/// empty: a run never reads the chunks of an earlier run.
#[derive(Debug)]
pub(crate) struct MeshChunks {
    store: Store,
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
            });
        }
        #[cfg(target_arch = "wasm32")]
        let _ = folder;
        Ok(Self {
            store: Store::Memory(InMemoryStore::new()),
        })
    }

    /// Cuts `bytes` into chunks, keeps them with their chunk map, and returns the root.
    ///
    /// # Errors
    ///
    /// The store cannot keep a chunk or the map.
    pub(crate) async fn put_value(&self, bytes: &[u8]) -> Result<Root, ChunkError> {
        let map = ChunkMap::build(bytes);
        for index in 0..map.len() {
            let chunk = chunk_at(bytes, map.range_of(index)).ok_or_else(|| {
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
        Ok(map.root())
    }

    /// Drops every chunk that no root of `roots` names.
    ///
    /// # Errors
    ///
    /// A root has no stored map, or the store cannot sweep.
    pub(crate) async fn keep_only(
        &self,
        roots: impl IntoIterator<Item = Root>,
    ) -> Result<(), ChunkError> {
        match &self.store {
            Store::Memory(store) => {
                store.start_marking().await?;
                for root in roots {
                    store.mark(root).await?;
                }
                store.sweep().await?;
            }
            #[cfg(not(target_arch = "wasm32"))]
            Store::Disk(store) => {
                store.start_marking().await?;
                for root in roots {
                    store.mark(root).await?;
                }
                store.sweep().await?;
            }
        }
        Ok(())
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
