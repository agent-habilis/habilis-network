//! The per-peer blob store: a content-addressed map of **spool-file paths**
//! (never the bytes — serving streams from disk, so memory stays constant
//! regardless of blob size). On offload a file is snapshotted into the spool by
//! hardlink (same filesystem, ≈free) or copy (cross-fs fallback), so the
//! producing agent deleting or overwriting the original can't disturb the served
//! bytes. Spool files are named by hex SHA-256 — traversal-safe and idempotent.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::util::consts::MAX_BLOB_STORE_BYTES;

use crate::protocol::crypto::TicketSecret;

use super::{BlobDigest, ContentId};

/// One spooled blob: the metadata the fetch path needs, plus the spool path to
/// stream from. No bytes are held.
pub(crate) struct BlobEntry {
    pub path: PathBuf,
    pub size: u64,
    /// The value the producer compares a presented token against
    /// (constant-time): the raw bearer secret, or — when the blob is
    /// password-protected — the Argon2id stretch of the ticket's public salt.
    pub secret: TicketSecret,
    /// The public salt the ticket carries (equal to `secret` when not
    /// passworded). Retained so a deduped re-registration mints a ticket that
    /// still matches this entry's compare `secret`.
    ticket_secret: TicketSecret,
    /// Whether the minted ticket is password-protected.
    password: bool,
    /// Every content group that offloaded these bytes. The spool file goes
    /// only when the last of them is evicted.
    owners: HashSet<ContentId>,
    /// Monotonic order of the last registration or claim, for oldest-first
    /// eviction under disk pressure.
    seq: u64,
}

/// The capability inputs for a fresh registration: the public salt the ticket
/// carries, the value the fetch handshake is compared against (equal to the salt
/// when not passworded, its Argon2id stretch otherwise), and the password flag.
pub(crate) struct NewSecret {
    pub ticket_secret: TicketSecret,
    pub compare_secret: TicketSecret,
    pub password: bool,
}

/// What a registration hands back for building the ticket: the public salt the
/// ticket carries and whether it is password-protected.
pub(crate) struct Registered {
    pub ticket_secret: TicketSecret,
    pub password: bool,
}

/// The content identity of a file being snapshotted into the store —
/// [`BlobStore::snapshot`]'s content-addressing key plus the content group it
/// is offloaded under, which becomes one of the blob's owners.
pub(crate) struct ContentMeta {
    pub(crate) sha256: BlobDigest,
    pub(crate) size: u64,
    pub(crate) content_id: ContentId,
}

/// One store per peer (per daemon). Holds the blobs this peer offloaded — its
/// outbound inputs and produced outputs — content-addressed, never replicated.
pub(crate) struct BlobStore {
    spool_dir: PathBuf,
    map: HashMap<BlobDigest, BlobEntry>,
    total_bytes: u64,
    next_seq: u64,
}

impl BlobStore {
    /// Create the store, ensuring its spool directory exists.
    ///
    /// # Errors
    /// The spool directory cannot be created.
    pub(crate) fn new(spool_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&spool_dir).with_context(|| {
            format!("creating the blob spool dir {} failed", spool_dir.display())
        })?;
        Ok(Self {
            spool_dir,
            map: HashMap::new(),
            total_bytes: 0,
            next_seq: 0,
        })
    }

    /// Snapshot `src` into the spool under `sha256`, owned by `content_id`.
    /// `ticket_secret` is the public salt the ticket will carry; `compare_secret`
    /// is what the fetch handshake is checked against (equal to `ticket_secret`
    /// when not passworded, its Argon2id stretch otherwise). Returns the salt +
    /// password flag to mint the ticket — the existing entry's when this content
    /// is already spooled (content-addressed dedup — first registration wins,
    /// `content_id` joins its owners), so a fresh ticket still matches the
    /// stored compare secret.
    ///
    /// # Errors
    /// Snapshotting the file into the spool fails.
    pub(crate) fn snapshot(
        &mut self,
        src: &Path,
        meta: ContentMeta,
        secret: &NewSecret,
    ) -> Result<Registered> {
        let ContentMeta {
            sha256,
            size,
            content_id,
        } = meta;
        if let Some(registered) = self.claim(&sha256, &content_id) {
            return Ok(registered);
        }
        let dest = self.spool_dir.join(sha256.to_string());
        snapshot_file(src, &dest)?;
        let seq = self.next_seq;
        self.next_seq += 1;
        self.total_bytes += size;
        self.map.insert(
            sha256,
            BlobEntry {
                path: dest,
                size,
                secret: secret.compare_secret.clone(),
                ticket_secret: secret.ticket_secret.clone(),
                password: secret.password,
                owners: HashSet::from([content_id]),
                seq,
            },
        );
        self.evict_to_budget();
        Ok(Registered {
            ticket_secret: secret.ticket_secret.clone(),
            password: secret.password,
        })
    }

    /// The entry for `hash`, if spooled.
    pub(crate) fn get(&self, hash: &BlobDigest) -> Option<&BlobEntry> {
        self.map.get(hash)
    }

    /// For an already-spooled blob (a content-addressed dedup hit), add
    /// `content_id` to its owners, make it the newest blob for disk-pressure
    /// eviction, and return its ticket fields; `None` when the blob is not
    /// spooled. Lets the producer skip the ~100ms password stretch
    /// when re-offloading content it already holds.
    pub(crate) fn claim(
        &mut self,
        hash: &BlobDigest,
        content_id: &ContentId,
    ) -> Option<Registered> {
        let entry = self.map.get_mut(hash)?;
        entry.owners.insert(content_id.clone());
        entry.seq = self.next_seq;
        self.next_seq += 1;
        Some(Registered {
            ticket_secret: entry.ticket_secret.clone(),
            password: entry.password,
        })
    }

    /// Release `content_id`'s hold on every blob (called from the task
    /// idle-timeout sweep), unlinking each spool file no group owns any more.
    pub(crate) fn evict_content(&mut self, content_id: &ContentId) {
        let doomed: Vec<BlobDigest> = self
            .map
            .iter_mut()
            .filter_map(|(hash, entry)| {
                (entry.owners.remove(content_id) && entry.owners.is_empty()).then_some(*hash)
            })
            .collect();
        for hash in doomed {
            self.remove(&hash);
        }
    }

    /// Unlink the least recently registered or claimed blob first, until the
    /// store is within `MAX_BLOB_STORE_BYTES`.
    fn evict_to_budget(&mut self) {
        while self.total_bytes > MAX_BLOB_STORE_BYTES {
            let Some(oldest) = self
                .map
                .iter()
                .min_by_key(|(_, entry)| entry.seq)
                .map(|(hash, _)| *hash)
            else {
                break;
            };
            self.remove(&oldest);
        }
    }

    fn remove(&mut self, hash: &BlobDigest) {
        if let Some(entry) = self.map.remove(hash) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.size);
            let _ = fs::remove_file(&entry.path);
        }
    }
}

impl Drop for BlobStore {
    fn drop(&mut self) {
        // Best-effort: on daemon shutdown/leave the whole spool dir goes.
        let _ = fs::remove_dir_all(&self.spool_dir);
    }
}

/// Hardlink `src` into the spool at `dest`, falling back to a copy when the two
/// are on different filesystems (hardlinks can't cross a mount). Idempotent — a
/// pre-existing `dest` of the source's size (same content, since it's
/// hash-named) is left as is. A `dest` of another size is what a copy cut short
/// leaves, and is replaced.
fn snapshot_file(src: &Path, dest: &Path) -> Result<()> {
    if let Ok(existing) = fs::metadata(dest) {
        let src_len = fs::metadata(src)
            .with_context(|| format!("reading {} failed", src.display()))?
            .len();
        if existing.len() == src_len {
            return Ok(());
        }
        let _ = fs::remove_file(dest);
    }
    if fs::hard_link(src, dest).is_ok() {
        return Ok(());
    }
    fs::copy(src, dest)
        .inspect_err(|_| {
            let _ = fs::remove_file(dest);
        })
        .with_context(|| format!("snapshotting {} into the blob spool failed", src.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BlobStore, ContentMeta};
    use crate::blob::{BlobDigest, ContentId, HASH_LEN, SECRET_LEN};
    use crate::protocol::crypto::TicketSecret;
    use rand::RngCore;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn temp_dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "habilis-network-blob-{tag}-{}",
            rand::rng().next_u64()
        ));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    /// A passwordless capability: the ticket secret is also the compare secret.
    fn plain_secret(secret: [u8; SECRET_LEN]) -> super::NewSecret {
        super::NewSecret {
            ticket_secret: TicketSecret::from_bytes(secret),
            compare_secret: TicketSecret::from_bytes(secret),
            password: false,
        }
    }

    #[test]
    fn snapshot_then_get_streams_from_spool() {
        let src_dir = temp_dir("src");
        let src = src_dir.join("payload.bin");
        fs::write(&src, vec![7u8; 4096]).unwrap();

        let mut store = BlobStore::new(temp_dir("spool")).unwrap();
        let hash = BlobDigest::from_bytes([1u8; HASH_LEN]);
        let registered = store
            .snapshot(
                &src,
                ContentMeta {
                    sha256: hash,
                    size: 4096,
                    content_id: ContentId::new("blob-test-content"),
                },
                &plain_secret([9u8; SECRET_LEN]),
            )
            .unwrap();
        assert_eq!(registered.ticket_secret.as_bytes(), &[9u8; SECRET_LEN]);
        assert!(!registered.password);

        let entry = store.get(&hash).expect("entry present");
        assert_eq!(entry.size, 4096);
        assert_eq!(fs::read(&entry.path).unwrap(), vec![7u8; 4096]);

        fs::remove_dir_all(&src_dir).ok();
    }

    #[test]
    fn dedup_keeps_the_first_secret() {
        let src_dir = temp_dir("src");
        let src = src_dir.join("payload.bin");
        fs::write(&src, b"same content").unwrap();

        let mut store = BlobStore::new(temp_dir("spool")).unwrap();
        let hash = BlobDigest::from_bytes([2u8; HASH_LEN]);
        let first = store
            .snapshot(
                &src,
                ContentMeta {
                    sha256: hash,
                    size: 12,
                    content_id: ContentId::new("blob-test-content"),
                },
                &plain_secret([1u8; SECRET_LEN]),
            )
            .unwrap();
        let second = store
            .snapshot(
                &src,
                ContentMeta {
                    sha256: hash,
                    size: 12,
                    content_id: ContentId::new("blob-test-content"),
                },
                &plain_secret([2u8; SECRET_LEN]),
            )
            .unwrap();
        assert_eq!(first.ticket_secret.as_bytes(), &[1u8; SECRET_LEN]);
        assert_eq!(
            second.ticket_secret.as_bytes(),
            first.ticket_secret.as_bytes(),
            "dedup must return the first registration's secret"
        );

        fs::remove_dir_all(&src_dir).ok();
    }

    #[test]
    fn snapshot_replaces_a_partial_dest() {
        let dir = temp_dir("partial");
        let src = dir.join("src");
        let dest = dir.join("dest");
        fs::write(&src, b"whole content").unwrap();
        // What a copy cut short by a full disk leaves behind.
        fs::write(&dest, b"whole").unwrap();
        super::snapshot_file(&src, &dest).expect("snapshot");
        let got = fs::read(&dest).unwrap();
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(got, b"whole content");
    }

    fn snapshot_as(store: &mut BlobStore, src: &Path, hash: BlobDigest, group: &ContentId) {
        store
            .snapshot(
                src,
                ContentMeta {
                    sha256: hash,
                    size: fs::metadata(src).unwrap().len(),
                    content_id: group.clone(),
                },
                &plain_secret([0u8; SECRET_LEN]),
            )
            .unwrap();
    }

    /// Two offloads of the same bytes that both miss the producer's dedup
    /// check land in `snapshot` together; the second must still own the blob.
    #[test]
    fn a_snapshot_race_adds_the_second_group() {
        let src_dir = temp_dir("src");
        let src = src_dir.join("payload.bin");
        fs::write(&src, b"shared").unwrap();

        let mut store = BlobStore::new(temp_dir("spool")).unwrap();
        let hash = BlobDigest::from_bytes([4u8; HASH_LEN]);
        let group_a = ContentId::new("blob-test-group-a");
        let group_b = ContentId::new("blob-test-group-b");
        snapshot_as(&mut store, &src, hash, &group_a);
        snapshot_as(&mut store, &src, hash, &group_b);
        let path = store.get(&hash).unwrap().path.clone();

        store.evict_content(&group_a);
        assert!(store.get(&hash).is_some(), "group B still owns the blob");
        assert!(path.exists());

        store.evict_content(&group_b);
        assert!(store.get(&hash).is_none());
        assert!(
            !path.exists(),
            "the last owner's evict unlinks the spool file"
        );

        fs::remove_dir_all(&src_dir).ok();
    }

    #[test]
    fn the_same_group_twice_is_one_owner() {
        let src_dir = temp_dir("src");
        let src = src_dir.join("payload.bin");
        fs::write(&src, b"twice").unwrap();

        let mut store = BlobStore::new(temp_dir("spool")).unwrap();
        let hash = BlobDigest::from_bytes([5u8; HASH_LEN]);
        let group = ContentId::new("blob-test-group");
        snapshot_as(&mut store, &src, hash, &group);
        snapshot_as(&mut store, &src, hash, &group);
        assert!(store.claim(&hash, &group).is_some());
        assert_eq!(store.total_bytes, 5, "a dedup hit adds no bytes");
        let path = store.get(&hash).unwrap().path.clone();

        store.evict_content(&group);
        assert!(store.get(&hash).is_none());
        assert!(!path.exists());

        fs::remove_dir_all(&src_dir).ok();
    }

    /// A blob a new group claimed a moment ago is the newest, whatever its
    /// first registration said: under disk pressure the next-oldest goes.
    #[test]
    fn a_claim_makes_the_blob_the_newest_under_disk_pressure() {
        let src_dir = temp_dir("src");
        let src = src_dir.join("payload.bin");
        fs::write(&src, b"x").unwrap();

        let mut store = BlobStore::new(temp_dir("spool")).unwrap();
        let (oldest, next_oldest, filler) = (
            BlobDigest::from_bytes([6u8; HASH_LEN]),
            BlobDigest::from_bytes([7u8; HASH_LEN]),
            BlobDigest::from_bytes([8u8; HASH_LEN]),
        );
        let group_a = ContentId::new("blob-test-group-a");
        let group_b = ContentId::new("blob-test-group-b");
        // `size` is the accounted size, so a one-byte file stands in for a
        // blob of any weight.
        for (hash, size) in [(oldest, 1), (next_oldest, 1)] {
            let meta = ContentMeta {
                sha256: hash,
                size,
                content_id: group_a.clone(),
            };
            store
                .snapshot(&src, meta, &plain_secret([0u8; SECRET_LEN]))
                .unwrap();
        }
        assert!(store.claim(&oldest, &group_b).is_some());

        // One byte over the budget: exactly one blob has to go.
        let meta = ContentMeta {
            sha256: filler,
            size: super::MAX_BLOB_STORE_BYTES - 1,
            content_id: group_a.clone(),
        };
        store
            .snapshot(&src, meta, &plain_secret([0u8; SECRET_LEN]))
            .unwrap();

        assert!(store.get(&oldest).is_some(), "the claimed blob stays");
        assert!(store.get(&next_oldest).is_none(), "the next oldest goes");

        fs::remove_dir_all(&src_dir).ok();
    }

    #[test]
    fn evict_task_unlinks_the_spool_file() {
        let src_dir = temp_dir("src");
        let src = src_dir.join("payload.bin");
        fs::write(&src, b"bye").unwrap();

        let mut store = BlobStore::new(temp_dir("spool")).unwrap();
        let hash = BlobDigest::from_bytes([3u8; HASH_LEN]);
        let task = ContentId::new("blob-test-content");
        store
            .snapshot(
                &src,
                ContentMeta {
                    sha256: hash,
                    size: 3,
                    content_id: task.clone(),
                },
                &plain_secret([0u8; SECRET_LEN]),
            )
            .unwrap();
        let path = store.get(&hash).unwrap().path.clone();
        assert!(path.exists());

        store.evict_content(&task);
        assert!(store.get(&hash).is_none());
        assert!(!path.exists(), "spool file must be unlinked on evict");

        fs::remove_dir_all(&src_dir).ok();
    }
}
