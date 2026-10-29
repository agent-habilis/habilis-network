//! [`DiskStore`]: the backend that owns its chunks.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::ChunkError;

use crate::{ChunkHash, ChunkMap, ChunkSource, ChunkStore, Coverage, FileId, Root, chunk_hash};

/// Wraps a backend's error as a store failure. The step is built only when the
/// call fails, so a `format!` in it costs nothing on the success path.
pub(super) fn store<E, S>(step: impl FnOnce() -> S) -> impl FnOnce(E) -> ChunkError
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
    S: Into<String>,
{
    move |source| ChunkError::Store {
        step: step().into(),
        source: source.into(),
    }
}

/// Write `bytes` to `path` so a reader sees all of it or none of it.
///
/// Temp file, flush, rename. Rename is atomic within a filesystem, so a crash
/// leaves either the old content or the new, never a torn chunk under a name
/// that claims to address it.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ChunkError> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .ok_or_else(|| ChunkError::Malformed("a chunk path has a parent".to_owned()))?;
    fs::create_dir_all(parent).map_err(store(|| format!("creating {}", parent.display())))?;
    let temp: PathBuf = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("chunk")
    ));
    {
        let mut handle =
            fs::File::create(&temp).map_err(store(|| format!("creating {}", temp.display())))?;
        handle.write_all(bytes).map_err(store(|| "write a chunk"))?;
        handle.sync_all().map_err(store(|| "sync a chunk"))?;
    }
    fs::rename(&temp, path).map_err(store(|| format!("renaming into {}", path.display())))?;
    Ok(())
}

/// A store that keeps chunks under one directory.
///
/// Layout:
///
/// ```text
/// <root>/
///   chunks/<first-two-hex>/<full-hex>    one file per chunk
///   maps/<root-hex>                      a leaf row
///   binds.tsv                            key -> (size, mtime, root)
/// ```
///
/// Chunks are sharded by their first byte because a flat directory of hundreds
/// of thousands of entries is slow to enumerate on every filesystem that
/// matters.
#[derive(Debug)]
pub struct DiskStore {
    root: PathBuf,
    binds: Mutex<HashMap<String, (u64, i64, Root)>>,
    /// Live set for the current reclamation pass; see [`InMemoryStore`]'s note on
    /// why `None` means "nothing is protected".
    ///
    /// [`InMemoryStore`]: crate::InMemoryStore
    marks: Mutex<Option<HashSet<ChunkHash>>>,
}

impl DiskStore {
    /// Open or create a store under `root`.
    ///
    /// # Errors
    /// # Errors
    /// [`ChunkError::Store`] when the directories cannot be created or the binds file
    /// cannot be read.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ChunkError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("chunks")).map_err(store(|| {
            format!("creating {}", root.join("chunks").display())
        }))?;
        fs::create_dir_all(root.join("maps")).map_err(store(|| {
            format!("creating {}", root.join("maps").display())
        }))?;
        let binds = load_binds(&root.join("binds.tsv"));
        Ok(Self {
            root,
            binds: Mutex::new(binds),
            marks: Mutex::new(None),
        })
    }

    fn chunk_path(&self, hash: ChunkHash) -> PathBuf {
        let hex = hash.to_hex();
        self.root.join("chunks").join(&hex[..2]).join(&hex)
    }

    fn map_path(&self, root: Root) -> PathBuf {
        self.root.join("maps").join(root.to_hex())
    }

    /// Every chunk currently on disk.
    ///
    /// Walks the shard directories. Only the sweep needs this, which is why
    /// nothing keeps an in-memory index that could drift from the truth.
    fn stored_chunks(&self) -> Vec<ChunkHash> {
        let mut found = Vec::new();
        let chunks = self.root.join("chunks");
        let Ok(shards) = fs::read_dir(&chunks) else {
            return found;
        };
        for shard in shards.flatten() {
            let Ok(entries) = fs::read_dir(shard.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                // Skip the temp files `write_atomic` leaves if it is interrupted.
                if let Ok(hash) = ChunkHash::from_hex(name) {
                    found.push(hash);
                }
            }
        }
        found
    }

    fn flush_binds(&self, binds: &HashMap<String, (u64, i64, Root)>) -> Result<(), ChunkError> {
        let mut text = String::new();
        for (key, (size, mtime, root)) in binds {
            // A key with a tab or newline in it would corrupt the table; paths
            // can contain both, so they are escaped rather than trusted.
            use std::fmt::Write as _;
            let _ = writeln!(
                text,
                "{}\t{size}\t{mtime}\t{}",
                key.replace('\\', "\\\\")
                    .replace('\t', "\\t")
                    .replace('\n', "\\n"),
                root.to_hex()
            );
        }
        write_atomic(&self.root.join("binds.tsv"), text.as_bytes())
    }
}

fn unescape(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut chars = key.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            // An unknown escape passes through as itself rather than being
            // guessed at: this table is ours, so a sequence we did not write is
            // corruption, and inventing a meaning for it would hide that.
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

fn load_binds(path: &Path) -> HashMap<String, (u64, i64, Root)> {
    let mut binds = HashMap::new();
    let Ok(text) = fs::read_to_string(path) else {
        return binds;
    };
    for line in text.lines() {
        let mut fields = line.split('\t');
        let (Some(key), Some(size), Some(mtime), Some(root)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        // A malformed row costs that row, not the whole table: losing one
        // binding means re-hashing one file, losing the table means re-hashing
        // the tree.
        let parsed_size: Result<u64, _> = size.parse();
        let parsed_mtime: Result<i64, _> = mtime.parse();
        let (Ok(bytes), Ok(modified), Ok(root)) = (parsed_size, parsed_mtime, Root::from_hex(root))
        else {
            continue;
        };
        binds.insert(unescape(key), (bytes, modified, root));
    }
    binds
}

/// Serialize a leaf row: `size(u64 LE) ‖ count(u32 LE) ‖ leaves(32 × count)`.
fn encode_map(map: &ChunkMap) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + map.len() * 32);
    out.extend_from_slice(&map.size().to_le_bytes());
    out.extend_from_slice(&u32::try_from(map.len()).unwrap_or(u32::MAX).to_le_bytes());
    for leaf in map.leaves() {
        out.extend_from_slice(leaf.as_bytes());
    }
    out
}

fn decode_map(bytes: &[u8]) -> Result<ChunkMap, ChunkError> {
    if bytes.len() < 12 {
        return Err(ChunkError::Malformed(format!(
            "a stored chunk map is at least 12 bytes, got {}",
            bytes.len()
        )));
    }
    let size = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    let count = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")) as usize;
    let expected = 12 + count * 32;
    if bytes.len() < expected {
        return Err(ChunkError::Malformed(format!(
            "a {count}-leaf row needs {expected} bytes, got {}",
            bytes.len()
        )));
    }
    let mut leaves = Vec::with_capacity(count);
    for index in 0..count {
        let start = 12 + index * 32;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[start..start + 32]);
        leaves.push(ChunkHash::from_bytes(digest));
    }
    // `from_leaves` recomputes the root, so a row that was corrupted on disk
    // simply names a different file rather than impersonating this one.
    ChunkMap::from_leaves(leaves, size)
}

impl ChunkSource for DiskStore {
    async fn get(&self, hash: ChunkHash) -> Result<Option<Vec<u8>>, ChunkError> {
        match fs::read(self.chunk_path(hash)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).map_err(store(|| "reading a chunk")),
        }
    }

    async fn has(&self, hash: ChunkHash) -> Result<bool, ChunkError> {
        Ok(self.chunk_path(hash).is_file())
    }

    async fn map(&self, root: Root) -> Result<Option<ChunkMap>, ChunkError> {
        match fs::read(self.map_path(root)) {
            Ok(bytes) => Ok(Some(decode_map(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).map_err(store(|| "reading a chunk map")),
        }
    }

    async fn coverage(&self, root: Root) -> Result<Coverage, ChunkError> {
        let Some(map) = self.map(root).await? else {
            return Ok(Coverage::empty(0));
        };
        // One `stat` per chunk. Derived rather than cached on purpose: an index
        // of what we hold is a second source of truth, and the moment it drifts
        // this peer starts advertising bytes it cannot serve.
        let mut coverage = Coverage::empty(map.len());
        for (index, leaf) in map.leaves().iter().enumerate() {
            if self.chunk_path(*leaf).is_file() {
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
        if *size != file.size || *mtime != file.mtime {
            return Ok(None);
        }
        Ok(Some(*root))
    }
}

impl ChunkStore for DiskStore {
    async fn put(&self, hash: ChunkHash, bytes: &[u8]) -> Result<(), ChunkError> {
        let actual = chunk_hash(bytes);
        if actual != hash {
            return Err(ChunkError::Malformed(format!(
                "these bytes address {actual}, not {hash}"
            )));
        }
        write_atomic(&self.chunk_path(hash), bytes)
    }

    async fn put_map(&self, map: &ChunkMap) -> Result<(), ChunkError> {
        write_atomic(&self.map_path(map.root()), &encode_map(map))
    }

    async fn set_bind(&self, file: &FileId, root: Root) -> Result<(), ChunkError> {
        let snapshot = {
            let mut binds = self
                .binds
                .lock()
                .map_err(|_| ChunkError::Poisoned("bind"))?;
            binds.insert(file.key.clone(), (file.size, file.mtime, root));
            binds.clone()
        };
        self.flush_binds(&snapshot)
    }

    async fn start_marking(&self) -> Result<(), ChunkError> {
        *self
            .marks
            .lock()
            .map_err(|_| ChunkError::Poisoned("mark"))? = Some(HashSet::new());
        Ok(())
    }

    async fn mark(&self, root: Root) -> Result<(), ChunkError> {
        let map = self.map(root).await?.ok_or_else(|| {
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
        marks
            .get_or_insert_with(HashSet::new)
            .extend(map.leaves().iter().copied());
        Ok(())
    }

    async fn sweep(&self) -> Result<u64, ChunkError> {
        let live = self
            .marks
            .lock()
            .map_err(|_| ChunkError::Poisoned("mark"))?
            .take()
            .unwrap_or_default();
        let mut dropped = 0u64;
        for hash in self.stored_chunks() {
            if live.contains(&hash) {
                continue;
            }
            if fs::remove_file(self.chunk_path(hash)).is_ok() {
                dropped += 1;
            }
        }
        Ok(dropped)
    }

    async fn clear(&self, hashes: &[ChunkHash]) -> Result<(), ChunkError> {
        for hash in hashes {
            // Absent is fine: eviction races a sweep, and both removing the same
            // chunk is ordinary rather than an error.
            let _ = fs::remove_file(self.chunk_path(*hash));
        }
        Ok(())
    }
}
