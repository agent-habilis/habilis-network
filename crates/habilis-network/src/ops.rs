//! What a consumer *does* from inside a hook: send, merge a shared document,
//! advertise into a directory, mint an invite.
//!
//! Every entry point here takes the state and context the engine already handed
//! the hook, so none of it can be called out of band.

pub use crate::gossip::{
    StateMergeParams, broadcast_msg, broadcast_state_merge, send_app, unicast_farewell,
};
pub use crate::transport::{MeshSender, deliver, deliver_in_background};

/// The CRDT-backed `state` / `meta` channels.
pub mod doc {
    pub use crate::doc::MeshDoc;
    /// Only the adversarial suite builds a bare merge frame; production writes
    /// go through [`change_body`]. Gated on the feature alone: `doc` is its own
    /// crate now, so this crate being under `cfg(test)` says nothing about
    /// whether the item exists over there.
    #[cfg(feature = "adversarial")]
    pub use crate::doc::wire::merge_body;
    pub use crate::doc::wire::{change_body, encrypt_body};
}

/// Handing a peer a payload too large for a gossip frame: offload it to a
/// local store, send the ticket, let the peer fetch it over the blob ALPN.
#[cfg(feature = "blob")]
pub mod blob {
    pub use crate::blob::{
        BlobServer, BlobTicket, ContentId, HASH_LEN, OffloadRequest, SECRET_LEN, fetch, offload,
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
