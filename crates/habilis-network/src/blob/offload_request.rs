use std::path::PathBuf;

use anyhow::Result;

use crate::protocol::crypto;
use crate::protocol::mesh::LookupOpts;
use crate::transport::PayloadPath;

use super::{BlobError, BlobServer, BlobTicket, ContentId};

/// One offload: which file, where to spool it, which content group it belongs to,
/// and the mesh password it inherits (so a scraped ticket cannot be redeemed
/// without it).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OffloadRequest {
    /// The file to offload.
    pub path: PathBuf,
    /// The directory where the blob is spooled.
    pub spool_dir: PathBuf,
    /// The content group that the blob belongs to.
    pub content_id: ContentId,
    /// The mesh password that the ticket inherits, so a scraped ticket cannot be redeemed without it.
    pub password: Option<crypto::Password>,
}

/// Offload a file over the blob channel and return the [`BlobTicket`] that
/// fetches it back. Lazily binds `server` on the first call (into
/// `request.spool_dir`), reusing it thereafter — so a caller holds one
/// `Option<BlobServer>` for its lifetime and passes it here each time.
///
/// The ticket is the whole result: `encode()` it into whatever reference the
/// application uses, ship that string over gossip, and the peer calls
/// [`fetch`](super::fetch). Content-addressed dedup means offloading identical bytes twice
/// returns the first ticket without re-paying the hash or the Argon2 stretch.
///
/// `relay_transport` must be the mesh's `transport.relay_transport`
/// (`mesh.transport().relay_transport`): the ticket carries it so the fetcher
/// applies the same rule, and a per-node value would let one member serve over
/// the relay for everyone.
///
/// # Errors
/// Binding the blob server, hashing, or snapshotting the file fails (e.g. the
/// file is unreadable or exceeds `MAX_BLOB_BYTES`).
///
/// # Panics
/// Panics if an internal invariant is violated.
pub async fn offload(
    server: &mut Option<BlobServer>,
    lookups: &LookupOpts,
    relay_transport: PayloadPath,
    request: OffloadRequest,
) -> Result<BlobTicket, BlobError> {
    offload_checked(server, lookups, relay_transport, request)
        .await
        .map_err(BlobError::internal)
}

async fn offload_checked(
    server: &mut Option<BlobServer>,
    lookups: &LookupOpts,
    relay_transport: PayloadPath,
    request: OffloadRequest,
) -> Result<BlobTicket> {
    let OffloadRequest {
        path,
        spool_dir,
        content_id,
        password,
    } = request;
    if server.is_none() {
        *server =
            Some(BlobServer::start(lookups.clone(), spool_dir, password, relay_transport).await?);
    }
    server
        .as_ref()
        .expect("server set above")
        .register(&path, content_id)
        .await
        .map_err(anyhow::Error::from)
}
