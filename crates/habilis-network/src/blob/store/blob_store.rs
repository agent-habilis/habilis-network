use super::{BlobEntry, ContentMeta, NewSecret, Registered};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::util::consts::{MAX_BLOB_OWNERS, MAX_BLOB_STORE_BYTES, MAX_BLOB_STORE_ENTRIES};

use crate::blob::{BlobDigest, ContentId};

/// One store per peer (per daemon). Holds the blobs this peer offloaded — its
/// outbound inputs and produced outputs — content-addressed, never replicated.
#[derive(Debug, Clone)]
#[must_use]
pub(crate) struct BlobStore {
    pub(super) spool_dir: PathBuf,
    pub(super) map: HashMap<BlobDigest, BlobEntry>,
    pub(super) total_bytes: u64,
    pub(super) next_seq: u64,
}

impl BlobStore {
    /// Create the store, ensuring its spool directory exists.
    ///
    /// # Errors
    /// The spool directory cannot be created.
    pub(crate) fn try_new(spool_dir: PathBuf) -> Result<Self> {
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
        super::snapshot_file(src, &dest)?;
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
                overflowed: false,
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
    /// `content_id` to its owners (up to `MAX_BLOB_OWNERS`), make it the newest blob for disk-pressure
    /// eviction, and return its ticket fields; `None` when the blob is not
    /// spooled. Lets the producer skip the ~100ms password stretch
    /// when re-offloading content it already holds.
    ///
    /// An entry records at most `MAX_BLOB_OWNERS` owners. A group past the cap is not recorded and
    /// marks the entry `overflowed`, so the blob stays when the recorded owners are released. The
    /// claim never fails for want of room.
    pub(crate) fn claim(
        &mut self,
        hash: &BlobDigest,
        content_id: &ContentId,
    ) -> Option<Registered> {
        let entry = self.map.get_mut(hash)?;
        if entry.owners.len() < MAX_BLOB_OWNERS {
            entry.owners.insert(content_id.clone());
        } else if !entry.owners.contains(content_id) {
            entry.overflowed = true;
        }
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
                (entry.owners.remove(content_id) && entry.owners.is_empty() && !entry.overflowed)
                    .then_some(*hash)
            })
            .collect();
        for hash in doomed {
            self.remove(&hash);
        }
    }

    /// Unlink the least recently registered or claimed blob first, until the
    /// store is within `MAX_BLOB_STORE_BYTES` and `MAX_BLOB_STORE_ENTRIES`.
    fn evict_to_budget(&mut self) {
        while self.total_bytes > MAX_BLOB_STORE_BYTES || self.map.len() > MAX_BLOB_STORE_ENTRIES {
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
