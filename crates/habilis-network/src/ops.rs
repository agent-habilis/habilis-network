//! What a consumer *does* from inside a hook: send, merge a shared document,
//! advertise into a directory, mint an invite.
//!
//! Every entry point here takes the state and context the engine already handed
//! the hook, so none of it can be called out of band.

pub use crate::gossip::{
    Farewell, MergeCtx, StateMergeParams, app_frame, broadcast_msg, broadcast_state_merge,
    send_app, start_ping_round, unicast_farewell,
};
pub use crate::transport::{
    Delivered, MeshSender, PendingSend, deliver, deliver_in_background, deliver_to,
    deliver_to_in_background,
};

/// Handing a peer a payload too large for a gossip frame: offload it to a
/// local store, send the ticket, let the peer fetch it over the blob ALPN.
#[cfg(feature = "blob")]
pub mod blob {
    pub use crate::blob::{
        BlobDigest, BlobError, BlobServer, BlobTicket, ContentId, HASH_LEN, OffloadRequest,
        SECRET_LEN, fetch, offload,
    };
}

/// The directory: a well-known mesh whose traffic is other meshes' ids.
pub mod directory {
    pub use crate::directory::{Ad, Listing, ListingChange, Listings, directory_mesh};
}

/// Creator-minted invites to an invite-only mesh.
pub mod invite {
    pub use crate::invite::mint;
}
