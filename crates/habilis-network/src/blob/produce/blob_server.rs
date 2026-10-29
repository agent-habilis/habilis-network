use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use iroh::Endpoint;
use tokio::sync::Mutex;

use crate::protocol::crypto::Password;
use crate::protocol::mesh::LookupOpts;
use crate::transport::PayloadPath;

use crate::blob::store::BlobStore;

/// The producer side of the blob channel. Owns the serving endpoint and the
/// content-addressed store; both live for the daemon's process lifetime.
///
/// # Examples
///
/// A blob server serves the blobs that a node offers, from its spool. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::ops::blob::BlobServer;
///
/// # fn demo(server: BlobServer) {
/// drop(server);
/// # }
/// ```
pub struct BlobServer {
    pub(super) endpoint: Endpoint,
    // the server and the accept loop share the store
    pub(super) store: Arc<Mutex<BlobStore>>,
    pub(super) lookups: LookupOpts,
    /// The mesh password, when the mesh is password-protected. Every minted
    /// ticket inherits it, so a scraped ticket can't be redeemed without the
    /// password. `None` ⇒ bare bearer-secret tickets (status quo).
    pub(super) password: Option<Password>,
    /// `TransportPolicy::relay`. Off, a fetch whose selected path is the
    /// relay is refused before any byte.
    pub(super) relay_transport: PayloadPath,
    /// Serves currently in flight. The accept loop holds the counter it
    /// actually reads; this handle exists so a test can observe that a peer
    /// which connects and then goes quiet cannot accumulate them.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "observed only by the serve-ceiling test")
    )]
    // the server and the accept loop share the in-flight count, which a test reads
    pub(super) inflight: Arc<AtomicUsize>,
}

impl std::fmt::Debug for BlobServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobServer").finish_non_exhaustive()
    }
}
