//! The per-peer blob store: a content-addressed map of **spool-file paths**
//! (never the bytes — serving streams from disk, so memory stays constant
//! regardless of blob size). On offload a file is snapshotted into the spool by
//! hardlink (same filesystem, ≈free) or copy (cross-fs fallback), so the
//! producing agent deleting or overwriting the original can't disturb the served
//! bytes. Spool files are named by hex SHA-256 — traversal-safe and idempotent.

mod blob_entry;
mod blob_store;
mod content_meta;
mod new_secret;
mod registered;

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

#[cfg(test)]
use crate::util::consts::MAX_BLOB_STORE_BYTES;

pub(crate) use blob_entry::BlobEntry;
pub(crate) use blob_store::BlobStore;
pub(crate) use content_meta::ContentMeta;
pub(crate) use new_secret::NewSecret;
pub(crate) use registered::Registered;

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
    use habilis_network_test_tracing::test;
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

        let mut store = BlobStore::try_new(temp_dir("spool")).unwrap();
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
        assert_eq!(
            registered.ticket_secret.as_bytes(),
            &[9u8; SECRET_LEN],
            "the snapshot keeps the ticket secret"
        );
        assert!(
            !registered.password,
            "the snapshot is not password protected"
        );

        let entry = store.get(&hash).expect("entry present");
        assert_eq!(entry.size, 4096, "the spool entry has the snapshot size");
        assert_eq!(
            fs::read(&entry.path).unwrap(),
            vec![7u8; 4096],
            "the spool file holds the snapshot bytes"
        );

        fs::remove_dir_all(&src_dir).ok();
    }

    #[test]
    fn dedup_keeps_the_first_secret() {
        let src_dir = temp_dir("src");
        let src = src_dir.join("payload.bin");
        fs::write(&src, b"same content").unwrap();

        let mut store = BlobStore::try_new(temp_dir("spool")).unwrap();
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
        assert_eq!(
            first.ticket_secret.as_bytes(),
            &[1u8; SECRET_LEN],
            "dedup keeps the first ticket secret"
        );
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
        assert_eq!(
            got, b"whole content",
            "a partial destination is replaced by the whole content"
        );
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

        let mut store = BlobStore::try_new(temp_dir("spool")).unwrap();
        let hash = BlobDigest::from_bytes([4u8; HASH_LEN]);
        let group_a = ContentId::new("blob-test-group-a");
        let group_b = ContentId::new("blob-test-group-b");
        snapshot_as(&mut store, &src, hash, &group_a);
        snapshot_as(&mut store, &src, hash, &group_b);
        let path = store.get(&hash).unwrap().path.clone();

        store.evict_content(&group_a);
        assert!(store.get(&hash).is_some(), "group B still owns the blob");
        assert!(path.exists(), "the spool file exists after a snapshot race");

        store.evict_content(&group_b);
        assert!(
            store.get(&hash).is_none(),
            "the racing group is not yet in the store"
        );
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

        let mut store = BlobStore::try_new(temp_dir("spool")).unwrap();
        let hash = BlobDigest::from_bytes([5u8; HASH_LEN]);
        let group = ContentId::new("blob-test-group");
        snapshot_as(&mut store, &src, hash, &group);
        snapshot_as(&mut store, &src, hash, &group);
        assert!(
            store.claim(&hash, &group).is_some(),
            "the same group claimed twice is one owner"
        );
        assert_eq!(store.total_bytes, 5, "a dedup hit adds no bytes");
        let path = store.get(&hash).unwrap().path.clone();

        store.evict_content(&group);
        assert!(
            store.get(&hash).is_none(),
            "the store drops the blob for the claimed group"
        );
        assert!(!path.exists(), "the spool file is removed with the blob");

        fs::remove_dir_all(&src_dir).ok();
    }

    /// A blob a new group claimed a moment ago is the newest, whatever its
    /// first registration said: under disk pressure the next-oldest goes.
    #[test]
    fn a_claim_makes_the_blob_the_newest_under_disk_pressure() {
        let src_dir = temp_dir("src");
        let src = src_dir.join("payload.bin");
        fs::write(&src, b"x").unwrap();

        let mut store = BlobStore::try_new(temp_dir("spool")).unwrap();
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
        assert!(
            store.claim(&oldest, &group_b).is_some(),
            "a claim makes the blob the newest under disk pressure"
        );

        // One byte over the budget: exactly one blob has to go.
        let meta = ContentMeta {
            sha256: filler,
            size: super::MAX_BLOB_STORE_BYTES - 1,
            content_id: group_a,
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

        let mut store = BlobStore::try_new(temp_dir("spool")).unwrap();
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
        assert!(
            path.exists(),
            "the spool file exists before the evict task runs"
        );

        store.evict_content(&task);
        assert!(
            store.get(&hash).is_none(),
            "the evict task removes the blob from the store"
        );
        assert!(!path.exists(), "spool file must be unlinked on evict");

        fs::remove_dir_all(&src_dir).ok();
    }
}
