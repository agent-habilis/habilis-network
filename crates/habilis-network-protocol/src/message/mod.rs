//! The `Message` envelope + its value types.
//!
//! - [`MessageBody`] (`body`) and [`MessageId`] (`id`) — the
//!   validated newtypes the envelope carries.
//! - [`Message`] (`message`) — the JSON wire envelope, its
//!   [`MessageKind`] / [`PresenceSubtype`] tags, the constructors, and
//!   (de)serialization.

#[cfg(any(test, feature = "test-fixtures"))]
#[cfg(test)]
use super::identity;
#[cfg(any(test, feature = "test-fixtures"))]
#[cfg(any(test, feature = "test-fixtures"))]
mod chain_ctx;
#[cfg(any(test, feature = "test-fixtures"))]
pub use chain_ctx::ChainCtx;
#[cfg(any(test, feature = "test-fixtures"))]
mod build_msg_params;
#[cfg(any(test, feature = "test-fixtures"))]
pub use build_msg_params::BuildMsgParams;
#[expect(
    clippy::module_inception,
    reason = "the file is named for its type, Message, as O9 asks"
)]
mod message;
pub use message::Message;
mod message_kind;
pub use message_kind::MessageKind;
mod channel;
#[cfg(test)]
use super::mesh::MeshId;
#[cfg(test)]
use super::nickname::Nickname;
pub use channel::Channel;
mod app_tag;
use version::VERSION;
mod version;
pub use app_tag::AppTag;
mod corr_id;
pub use corr_id::CorrId;
mod sole_addressee;
pub use sole_addressee::sole_addressee;
#[cfg(any(test, feature = "test-fixtures"))]
mod build_msg_bytes;
#[cfg(any(test, feature = "test-fixtures"))]
pub use build_msg_bytes::build_msg_bytes;
mod resend;
pub use resend::RESEND_TRAILER_LEN;
use resend::{split_resend_trailer, wire_with_resend_nonce};
mod presence_subtype;
pub use presence_subtype::PresenceSubtype;
mod app_frame_params;
pub use app_frame_params::AppFrameParams;
mod wire_in;
use wire_in::WireIn;
mod wire_out;
use wire_out::Wire;
mod signer;
pub use signer::Signer;
mod body_error;

use body_error as body;
mod error;
mod id_error;
use id_error as id;
mod shard;
mod verified;
mod wire_frame;
use wire_frame as wire;

pub use verified::{Authored, Proof, Verified};
pub use wire::WireFrame;

pub use body::{BodyError, MessageBody};
pub use error::{AppTagError, CorrIdError, MessageError};
pub use id::{IdError, MessageId};
pub use shard::{Shard, ShardGroup, shard_fits_log};

/// Maximum serialized message size — a network-wide wire contract kept
/// under iroh-gossip's payload budget so a message we accept always fits
/// one gossip message (see `habilis_network_util::consts::MAX_MESSAGE_SIZE` for why). Lives
/// in the shared crate; the compile-time assertion below guards the
/// relationship against the live gossip constant.
pub(crate) use habilis_network_util::consts::MAX_MESSAGE_SIZE;

// The compile-time tripwire that guards `MAX_MESSAGE_SIZE` against
// iroh-gossip's `DEFAULT_MAX_MESSAGE_SIZE` lives in `habilis-network`
// (`gossip/mod.rs`): this crate is deliberately off iroh-gossip, so it cannot
// name the constant it checks against.

pub(super) fn default_ext() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

pub(super) fn empty_body() -> MessageBody {
    MessageBody::try_new("").expect("empty string is always a valid MessageBody")
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
