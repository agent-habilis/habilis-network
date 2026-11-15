use crate::blob::{BlobDigest, ContentId};

/// The content identity of a file being snapshotted into the store —
/// `BlobStore::snapshot`'s content-addressing key plus the content group it
/// is offloaded under, which becomes one of the blob's owners.
#[derive(Debug, Clone)]
pub(crate) struct ContentMeta {
    pub(crate) sha256: BlobDigest,
    pub(crate) size: u64,
    pub(crate) content_id: ContentId,
}
