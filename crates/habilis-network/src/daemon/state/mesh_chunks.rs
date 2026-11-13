use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::{fs, io::ErrorKind};

use habilis_network_chunks::{ChunkError, InMemoryStore};

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
