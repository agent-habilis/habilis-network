//! [`DiskOrigin`]: the backend that borrows the user's files where they sit.

use std::collections::HashMap;
use std::fs;
use std::io::{Read as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::disk_store::store;
use crate::ChunkError;

use crate::{
    CHUNK_BYTES, CHUNK_BYTES_USIZE, ChunkHash, ChunkMap, ChunkMapBuilder, ChunkSource, Coverage,
    FileId, Root, chunk_hash,
};

/// One file this origin serves, where it sits.
#[derive(Debug, Clone)]
struct Borrowed {
    path: PathBuf,
    file: FileId,
    map: ChunkMap,
}

/// A source that serves the user's own files in place, copying nothing.
///
/// This is what makes `serve ~/Movies` a `stat` walk. Addresses are computed
/// **lazily, per file, on first interest** — [`DiskOrigin::adopt`] reads one file
/// once and keeps its row — so publishing a tree costs nothing until somebody
/// actually asks for something in it.
///
/// # Examples
///
/// A disk origin serves the chunks of files on disk, and it forgets a file it no longer serves. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network_chunks::{ChunkError, DiskOrigin, FileId};
///
/// # fn demo(file: &FileId) -> Result<(), ChunkError> {
/// let origin = DiskOrigin::new();
/// let root = origin.adopt(file, "/path/to/a.txt")?;
/// origin.forget(root)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct DiskOrigin {
    files: Mutex<HashMap<Root, Borrowed>>,
    /// The reverse index that lets a bare `hash` find bytes it does not own.
    ///
    /// Load-bearing, and the reason this is not an ordinary content-addressed
    /// store: a peer asks for a chunk by address alone, with no file and no
    /// offset, so the source must be able to get from an address back to a
    /// place on disk.
    locations: Mutex<HashMap<ChunkHash, (Root, usize)>>,
    binds: Mutex<HashMap<String, (u64, i64, Root)>>,
}

impl DiskOrigin {
    /// A source serving nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read `path` once, build its leaf row, and serve it from where it is.
    ///
    /// Streaming: peak memory is one chunk plus the row, whatever the file's
    /// size. Returns the root, which is also what a caller publishes.
    ///
    /// # Errors
    /// # Errors
    /// [`ChunkError::Store`] when the file cannot be read, or
    /// [`ChunkError::Malformed`] when it changed while it was read.
    pub fn adopt(&self, file: &FileId, path: impl AsRef<Path>) -> Result<Root, ChunkError> {
        let path = path.as_ref().to_path_buf();
        let mut handle =
            fs::File::open(&path).map_err(store(|| format!("opening {}", path.display())))?;
        let mut builder = ChunkMapBuilder::new();
        let mut buffer = vec![0u8; CHUNK_BYTES_USIZE];
        loop {
            let mut filled = 0usize;
            // `read` may return short without being at EOF, and a short read
            // treated as a chunk boundary would produce addresses nobody else
            // computes. Fill the buffer before hashing.
            while filled < buffer.len() {
                let read = handle
                    .read(&mut buffer[filled..])
                    .map_err(store(|| "read a file for hashing"))?;
                if read == 0 {
                    break;
                }
                filled += read;
            }
            if filled == 0 {
                break;
            }
            builder.push(&buffer[..filled]);
            if filled < buffer.len() {
                break;
            }
        }
        let map = builder.finish();
        if map.size() != file.size {
            return Err(ChunkError::Malformed(format!(
                "{} is {} bytes but was described as {}; it changed while being read",
                path.display(),
                map.size(),
                file.size
            )));
        }
        let root = map.root();
        {
            let mut locations = self
                .locations
                .lock()
                .map_err(|_| ChunkError::Poisoned("location"))?;
            for (index, leaf) in map.leaves().iter().enumerate() {
                // First writer wins. Two files sharing a chunk both resolve to
                // whichever was adopted first, and either answers correctly —
                // the bytes are the same bytes, which is the whole point.
                locations.entry(*leaf).or_insert((root, index));
            }
        }
        self.files
            .lock()
            .map_err(|_| ChunkError::Poisoned("file"))?
            .insert(
                root,
                Borrowed {
                    path,
                    file: file.clone(),
                    map,
                },
            );
        self.binds
            .lock()
            .map_err(|_| ChunkError::Poisoned("bind"))?
            .insert(file.key.clone(), (file.size, file.mtime, root));
        Ok(root)
    }

    /// Stop serving `root`, dropping its row and every address that pointed
    /// into it. Called when the file underneath changed.
    ///
    /// # Errors
    /// # Errors
    /// [`ChunkError::Store`] when the forget cannot be written, or
    /// [`ChunkError::Poisoned`] when a lock was poisoned.
    pub fn forget(&self, root: Root) -> Result<(), ChunkError> {
        self.files
            .lock()
            .map_err(|_| ChunkError::Poisoned("file"))?
            .remove(&root);
        self.locations
            .lock()
            .map_err(|_| ChunkError::Poisoned("location"))?
            .retain(|_, (owner, _)| *owner != root);
        Ok(())
    }

    /// Whether the file behind `root` still matches the version we hashed.
    ///
    /// The version gate, applied on **every** read rather than at adopt time. A
    /// file an editor saved over is a different file, and answering for it under
    /// the old root is the silent corruption this exists to prevent.
    fn still_current(borrowed: &Borrowed) -> bool {
        let Ok(meta) = fs::metadata(&borrowed.path) else {
            return false;
        };
        let modified = meta.modified().ok();
        let since = modified.and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok());
        let mtime: i64 = since
            .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
            .unwrap_or(0);
        // The recorded mtime is what the caller supplied at adopt time, which
        // may be 0 for "unknown"; size alone still catches the common case.
        meta.len() == borrowed.file.size
            && (borrowed.file.mtime == 0 || mtime == borrowed.file.mtime)
    }

    fn borrowed(&self, root: Root) -> Result<Option<Borrowed>, ChunkError> {
        Ok(self
            .files
            .lock()
            .map_err(|_| ChunkError::Poisoned("file"))?
            .get(&root)
            .cloned())
    }
}

impl ChunkSource for DiskOrigin {
    async fn get(&self, hash: ChunkHash) -> Result<Option<Vec<u8>>, ChunkError> {
        use std::io::Seek as _;
        let located = {
            let locations = self
                .locations
                .lock()
                .map_err(|_| ChunkError::Poisoned("location"))?;
            locations.get(&hash).copied()
        };
        let Some((root, index)) = located else {
            return Ok(None);
        };
        let Some(borrowed) = self.borrowed(root)? else {
            return Ok(None);
        };
        if !Self::still_current(&borrowed) {
            // Unbound: the bytes this address named are gone. Refusing is the
            // only honest answer; the caller will find the chunk elsewhere or
            // re-fetch the row.
            return Ok(None);
        }
        let range = borrowed.map.range_of(index);
        let len = usize::try_from(range.end - range.start)
            .map_err(|_| ChunkError::Malformed("a chunk fits in memory".to_owned()))?;
        let mut handle =
            fs::File::open(&borrowed.path).map_err(store(|| "open the file of a chunk"))?;
        handle
            .seek(SeekFrom::Start(range.start))
            .map_err(store(|| "seek in the file of a chunk"))?;
        let mut bytes = vec![0u8; len];
        handle
            .read_exact(&mut bytes)
            .map_err(store(|| "read a chunk from its file"))?;
        // Re-verify against the row before answering. Reading through to a file
        // we do not own means the bytes can move under us between the `stat`
        // and the read, and serving unverified bytes is how a peer becomes the
        // thing everyone else has to defend against.
        if chunk_hash(&bytes) != hash {
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    async fn has(&self, hash: ChunkHash) -> Result<bool, ChunkError> {
        Ok(self.get(hash).await?.is_some())
    }

    async fn map(&self, root: Root) -> Result<Option<ChunkMap>, ChunkError> {
        Ok(self.borrowed(root)?.map(|borrowed| borrowed.map))
    }

    async fn coverage(&self, root: Root) -> Result<Coverage, ChunkError> {
        let Some(borrowed) = self.borrowed(root)? else {
            return Ok(Coverage::empty(0));
        };
        // All or nothing, and that is not a simplification: an origin either
        // still has the file it hashed, in which case it holds every chunk, or
        // the file moved and it holds none of them.
        if Self::still_current(&borrowed) {
            Ok(Coverage::complete(borrowed.map.len()))
        } else {
            Ok(Coverage::empty(borrowed.map.len()))
        }
    }

    async fn bind(&self, file: &FileId) -> Result<Option<Root>, ChunkError> {
        let binds = self
            .binds
            .lock()
            .map_err(|_| ChunkError::Poisoned("bind"))?;
        let Some((size, mtime, root)) = binds.get(&file.key) else {
            return Ok(None);
        };
        if *size != file.size || *mtime != file.mtime {
            return Ok(None);
        }
        Ok(Some(*root))
    }
}

/// The largest window a single read should ask an origin for.
///
/// Exposed so a caller sizing its own buffers agrees with the chunking without
/// restating the constant.
///
/// # Examples
///
/// The read window is never zero.
///
/// ```
/// use habilis_network_chunks::fs::max_read_window;
///
/// assert!(max_read_window() > 0);
/// ```
#[must_use]
pub fn max_read_window() -> u64 {
    CHUNK_BYTES
}
