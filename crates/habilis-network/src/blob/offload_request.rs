use std::path::PathBuf;

use crate::protocol::crypto;
use crate::protocol::meshes::LookupOpts;
use crate::transport::PayloadPath;

use super::{BlobError, BlobServer, BlobTicket, ContentId};

/// One offload: which file, where to spool it, which content group it belongs to,
/// and the mesh password it inherits (so a scraped ticket cannot be redeemed
/// without it).
///
/// # Examples
///
/// An offload request names the file to serve, its content id, and the spool directory. The doc test compiles it but does not run it.
///
/// ```no_run
/// use std::path::PathBuf;
///
/// use habilis_network::ops::blob::{ContentId, OffloadRequest};
///
/// # fn demo(path: PathBuf, id: ContentId, spool: PathBuf) -> OffloadRequest {
/// OffloadRequest::new(path, id, spool).password(None)
/// # }
/// ```
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

impl OffloadRequest {
    /// An offload of the file at `path` into the content group `content_id`, spooled in
    /// `spool_dir`, with no mesh password. The two paths are not next to each other, so a swap
    /// of the file and the directory shows.
    #[must_use]
    pub fn new(path: PathBuf, content_id: ContentId, spool_dir: PathBuf) -> Self {
        Self {
            path,
            spool_dir,
            content_id,
            password: None,
        }
    }

    /// Set the mesh password that the ticket inherits.
    #[must_use]
    pub fn password(mut self, password: Option<crypto::Password>) -> Self {
        self.password = password;
        self
    }
}

/// Offload a file over the blob channel and return the [`BlobTicket`] that
/// fetches it back. Lazily binds `server` on the first call (into
/// `request.spool_dir`), reusing it thereafter — so a caller holds one
/// `Option<BlobServer>` for its lifetime and passes it here each time.
///
/// The ticket is the whole result: `encode()` it into whatever reference the
/// application uses, ship that string over gossip, and the peer calls
/// [`fetch`](super::fetch). Content-addressed dedup means offloading identical bytes twice
/// returns the first ticket without re-paying the Argon2 stretch.
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
/// # Examples
///
/// It serves a file as a blob and returns the ticket that a peer uses to fetch it. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::net::direct::PayloadPath;
/// use habilis_network::ops::blob::{BlobError, BlobServer, BlobTicket, OffloadRequest, offload};
/// use habilis_network::protocol::meshes::LookupOpts;
///
/// # async fn demo(server: &mut Option<BlobServer>, lookups: &LookupOpts, relay: PayloadPath, request: OffloadRequest) -> Result<BlobTicket, BlobError> {
/// offload(server, lookups, relay, request).await
/// # }
/// ```
pub async fn offload(
    server: &mut Option<BlobServer>,
    lookups: &LookupOpts,
    relay_transport: PayloadPath,
    request: OffloadRequest,
) -> Result<BlobTicket, BlobError> {
    let OffloadRequest {
        path,
        spool_dir,
        content_id,
        password,
    } = request;
    let server = match server {
        Some(server) => server,
        None => server.insert(
            BlobServer::start(lookups.clone(), spool_dir, password, relay_transport).await?,
        ),
    };
    server.register(&path, content_id).await
}
