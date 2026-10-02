//! Filesystem backends: one that keeps chunks, one that borrows them.
//!
//! The split is the crate's central asymmetry made concrete.
//!
//! - [`FsStore`] **owns** its chunks. A mirror, a seeder, anyone who fetched
//!   bytes from the network and has nowhere else to put them.
//! - [`FsOrigin`] **borrows** them. It serves the user's own files where they
//!   already sit, holding nothing but addresses and offsets, so publishing a
//!   500 GB tree costs a `stat` walk rather than a copy of it.
//!
//! `FsOrigin` implements [`ChunkSource`] and not [`ChunkStore`], and that is
//! the honest shape rather than a missing feature: `put` on an origin would
//! have to copy the caller's bytes into a store — the one thing this design
//! exists to avoid — or silently do nothing.
//!
//! # Crash consistency
//!
//! Coverage is **derived, never stored**: a chunk is held exactly when its file
//! is on disk. That deletes the failure the rule below usually guards against —
//! there is no separate range set that can outlive the data it describes and
//! leave this peer advertising bytes it cannot serve. What remains is making a
//! chunk file appear whole or not at all, which is what the temp-file-then-
//! rename in [`FsStore::put`] is for. A half-written chunk under its final name
//! would be a peer that lies.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context as _, Result, bail};

use crate::{
    CHUNK_BYTES, CHUNK_BYTES_USIZE, ChunkHash, ChunkMap, ChunkMapBuilder, ChunkSource, ChunkStore,
    Coverage, FileId, Root, chunk_hash,
};

fn poisoned(what: &str) -> anyhow::Error {
    anyhow::anyhow!("the {what} lock was poisoned by a panic in another thread")
}

/// Write `bytes` to `path` so a reader sees all of it or none of it.
///
/// Temp file, flush, rename. Rename is atomic within a filesystem, so a crash
/// leaves either the old content or the new, never a torn chunk under a name
/// that claims to address it.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("a chunk path has a parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let temp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("chunk")
    ));
    {
        let mut handle =
            fs::File::create(&temp).with_context(|| format!("creating {}", temp.display()))?;
        handle.write_all(bytes)?;
        handle.sync_all()?;
    }
    fs::rename(&temp, path).with_context(|| format!("renaming into {}", path.display()))?;
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
pub struct FsStore {
    root: PathBuf,
    binds: Mutex<HashMap<String, (u64, i64, Root)>>,
    /// Live set for the current reclamation pass; see [`MemStore`]'s note on
    /// why `None` means "nothing is protected".
    ///
    /// [`MemStore`]: crate::MemStore
    marks: Mutex<Option<HashSet<ChunkHash>>>,
}

impl FsStore {
    /// Open or create a store under `root`.
    ///
    /// # Errors
    /// The directory cannot be created, or an existing bind table is unreadable.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("chunks"))
            .with_context(|| format!("creating {}", root.join("chunks").display()))?;
        fs::create_dir_all(root.join("maps"))
            .with_context(|| format!("creating {}", root.join("maps").display()))?;
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

    fn flush_binds(&self, binds: &HashMap<String, (u64, i64, Root)>) -> Result<()> {
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
        let (Ok(size), Ok(mtime), Ok(root)) = (
            size.parse::<u64>(),
            mtime.parse::<i64>(),
            Root::from_hex(root),
        ) else {
            continue;
        };
        binds.insert(unescape(key), (size, mtime, root));
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

fn decode_map(bytes: &[u8]) -> Result<ChunkMap> {
    if bytes.len() < 12 {
        bail!(
            "a stored chunk map is at least 12 bytes, got {}",
            bytes.len()
        );
    }
    let size = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    let count = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")) as usize;
    let expected = 12 + count * 32;
    if bytes.len() < expected {
        bail!(
            "a {count}-leaf row needs {expected} bytes, got {}",
            bytes.len()
        );
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

impl ChunkSource for FsStore {
    async fn get(&self, hash: ChunkHash) -> Result<Option<Vec<u8>>> {
        match fs::read(self.chunk_path(hash)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("reading a chunk"),
        }
    }

    async fn has(&self, hash: ChunkHash) -> Result<bool> {
        Ok(self.chunk_path(hash).is_file())
    }

    async fn map(&self, root: Root) -> Result<Option<ChunkMap>> {
        match fs::read(self.map_path(root)) {
            Ok(bytes) => Ok(Some(decode_map(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("reading a chunk map"),
        }
    }

    async fn coverage(&self, root: Root) -> Result<Coverage> {
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

    async fn bind(&self, file: &FileId) -> Result<Option<Root>> {
        let binds = self.binds.lock().map_err(|_| poisoned("bind"))?;
        let Some((size, mtime, root)) = binds.get(&file.key) else {
            return Ok(None);
        };
        if *size != file.size || *mtime != file.mtime {
            return Ok(None);
        }
        Ok(Some(*root))
    }
}

impl ChunkStore for FsStore {
    async fn put(&self, hash: ChunkHash, bytes: &[u8]) -> Result<()> {
        let actual = chunk_hash(bytes);
        if actual != hash {
            bail!("these bytes address {actual}, not {hash}");
        }
        write_atomic(&self.chunk_path(hash), bytes)
    }

    async fn put_map(&self, map: &ChunkMap) -> Result<()> {
        write_atomic(&self.map_path(map.root()), &encode_map(map))
    }

    async fn set_bind(&self, file: &FileId, root: Root) -> Result<()> {
        let snapshot = {
            let mut binds = self.binds.lock().map_err(|_| poisoned("bind"))?;
            binds.insert(file.key.clone(), (file.size, file.mtime, root));
            binds.clone()
        };
        self.flush_binds(&snapshot)
    }

    async fn start_marking(&self) -> Result<()> {
        *self.marks.lock().map_err(|_| poisoned("mark"))? = Some(HashSet::new());
        Ok(())
    }

    async fn mark(&self, root: Root) -> Result<()> {
        let map = self.map(root).await?.context(
            "cannot mark a root with no stored chunk map — derive the live set \
             from persisted maps, never from an in-memory held-set",
        )?;
        let mut marks = self.marks.lock().map_err(|_| poisoned("mark"))?;
        marks
            .get_or_insert_with(HashSet::new)
            .extend(map.leaves().iter().copied());
        Ok(())
    }

    async fn sweep(&self) -> Result<u64> {
        let live = self
            .marks
            .lock()
            .map_err(|_| poisoned("mark"))?
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

    async fn clear(&self, hashes: &[ChunkHash]) -> Result<()> {
        for hash in hashes {
            // Absent is fine: eviction races a sweep, and both removing the same
            // chunk is ordinary rather than an error.
            let _ = fs::remove_file(self.chunk_path(*hash));
        }
        Ok(())
    }
}

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
/// **lazily, per file, on first interest** — [`FsOrigin::adopt`] reads one file
/// once and keeps its row — so publishing a tree costs nothing until somebody
/// actually asks for something in it.
#[derive(Debug, Default)]
pub struct FsOrigin {
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

impl FsOrigin {
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
    /// The file cannot be opened or read, or its size changed while being read.
    pub fn adopt(&self, file: &FileId, path: impl AsRef<Path>) -> Result<Root> {
        let path = path.as_ref().to_path_buf();
        let mut handle =
            fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let mut builder = ChunkMapBuilder::new();
        let mut buffer = vec![0u8; CHUNK_BYTES_USIZE];
        loop {
            let mut filled = 0usize;
            // `read` may return short without being at EOF, and a short read
            // treated as a chunk boundary would produce addresses nobody else
            // computes. Fill the buffer before hashing.
            while filled < buffer.len() {
                let read = handle.read(&mut buffer[filled..])?;
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
            bail!(
                "{} is {} bytes but was described as {}; it changed while being read",
                path.display(),
                map.size(),
                file.size
            );
        }
        let root = map.root();
        {
            let mut locations = self.locations.lock().map_err(|_| poisoned("location"))?;
            for (index, leaf) in map.leaves().iter().enumerate() {
                // First writer wins. Two files sharing a chunk both resolve to
                // whichever was adopted first, and either answers correctly —
                // the bytes are the same bytes, which is the whole point.
                locations.entry(*leaf).or_insert((root, index));
            }
        }
        self.files.lock().map_err(|_| poisoned("file"))?.insert(
            root,
            Borrowed {
                path,
                file: file.clone(),
                map,
            },
        );
        self.binds
            .lock()
            .map_err(|_| poisoned("bind"))?
            .insert(file.key.clone(), (file.size, file.mtime, root));
        Ok(root)
    }

    /// Stop serving `root`, dropping its row and every address that pointed
    /// into it. Called when the file underneath changed.
    ///
    /// # Errors
    /// A lock was poisoned by a panic in another thread.
    pub fn forget(&self, root: Root) -> Result<()> {
        self.files
            .lock()
            .map_err(|_| poisoned("file"))?
            .remove(&root);
        self.locations
            .lock()
            .map_err(|_| poisoned("location"))?
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
        let mtime = meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|since| i64::try_from(since.as_secs()).ok())
            .unwrap_or(0);
        // The recorded mtime is what the caller supplied at adopt time, which
        // may be 0 for "unknown"; size alone still catches the common case.
        meta.len() == borrowed.file.size
            && (borrowed.file.mtime == 0 || mtime == borrowed.file.mtime)
    }

    fn borrowed(&self, root: Root) -> Result<Option<Borrowed>> {
        Ok(self
            .files
            .lock()
            .map_err(|_| poisoned("file"))?
            .get(&root)
            .cloned())
    }
}

impl ChunkSource for FsOrigin {
    async fn get(&self, hash: ChunkHash) -> Result<Option<Vec<u8>>> {
        let located = {
            let locations = self.locations.lock().map_err(|_| poisoned("location"))?;
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
        let len = usize::try_from(range.end - range.start).context("a chunk fits in memory")?;
        let mut handle = fs::File::open(&borrowed.path)?;
        handle.seek(SeekFrom::Start(range.start))?;
        let mut bytes = vec![0u8; len];
        handle.read_exact(&mut bytes)?;
        // Re-verify against the row before answering. Reading through to a file
        // we do not own means the bytes can move under us between the `stat`
        // and the read, and serving unverified bytes is how a peer becomes the
        // thing everyone else has to defend against.
        if chunk_hash(&bytes) != hash {
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    async fn has(&self, hash: ChunkHash) -> Result<bool> {
        Ok(self.get(hash).await?.is_some())
    }

    async fn map(&self, root: Root) -> Result<Option<ChunkMap>> {
        Ok(self.borrowed(root)?.map(|borrowed| borrowed.map))
    }

    async fn coverage(&self, root: Root) -> Result<Coverage> {
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

    async fn bind(&self, file: &FileId) -> Result<Option<Root>> {
        let binds = self.binds.lock().map_err(|_| poisoned("bind"))?;
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
#[must_use]
pub const fn max_read_window() -> u64 {
    CHUNK_BYTES
}
