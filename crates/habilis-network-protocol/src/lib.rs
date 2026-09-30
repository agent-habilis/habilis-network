//! Wire types and seed-derived identities — the vocabulary every consumer
//! speaks.
//!
//! **Flat by design.** The implementation is split across submodules (message
//! envelope, mesh identifier, nickname, crypto, sealing, address codec), but
//! they are crate-private and everything lands here: a consumer that needed a
//! `Message` and a `MeshName` and a `Password` used to write three import paths
//! into the engine's file layout, which then could not be rearranged without
//! churning every one of them.

pub mod base58check;
pub mod crypto;
pub mod directory;
mod ident;
mod newtype;
mod topic;

pub mod identity;
/// Creator-minted invites to an invite-only mesh. Lives here rather than in
/// the engine because `InviteTicket` is part of the join vocabulary a
/// consumer speaks, and `resolver::JoinTarget` is defined in terms of it.
pub mod invite;
pub mod mesh;
pub mod message;
pub mod nickname;
pub mod peer_addr;
pub mod reassembly;
/// A join token: a literal mesh id, or a creator-minted invite ticket.
pub mod resolver;
pub mod seal;
mod wordlist;

/// The forked `iroh-base` this crate's types are built on, re-exported whole.
///
/// **Take it from here, never as your own dependency.** `EndpointAddr`,
/// `RelayUrl` and the key types appear in this crate's public signatures, so a
/// consumer that declares `iroh-base` itself gets the published crate and its
/// values stop being the ones our functions accept — an `E0308` between two
/// types with the same name and version.
///
/// This is the door a consumer with no `habilis-network` dependency uses: the wire
/// vocabulary needs `iroh-base` alone (no QUIC, no TLS, no DNS, no tokio), so
/// depending on this crate is far cheaper than depending on the engine, and it
/// still avoids a `[patch.crates-io]` — which cargo honours only in a workspace
/// root and never inherits.
pub use iroh_base;

pub use crypto::{Password, TicketAuth, ct_eq};
pub use identity::{Identity, encode_pubkey};
pub use mesh::{
    AdvertiseRequiresReachable, ChoiceError, DEFAULT_DIRECTORY, DirectorySelection, Lookup,
    LookupOpts, LookupSet, Mesh, MeshConfig, MeshId, MeshIdError, MeshName, NameError, OptFlag,
    PkarrChoice, RelayChoice, RelayLadder, RelayLadderError, RelaySelection, Transport,
    TransportPolicy, parse_pkarr_urls, resolve_lookups, validate_advertise, validate_pkarr_urls,
};
pub use message::{
    AppFrameParams, AppTag, BodyError, Channel, CorrId, IdError, Message, MessageBody, MessageId,
    MessageKind, PresenceSubtype, Shard, ShardGroup, sole_addressee,
};
pub use nickname::{Nickname, NicknameError};
pub use seal::seal_to_body;
pub use topic::TopicId;
/// The pkarr relay URL type, re-exported so a caller of [`MeshConfig::resolve`]
/// names the same `url` version.
pub use url::Url;

/// The invite token itself. Minting lives in
/// `habilis_network::ops::invite`; decoding is part of the join vocabulary.
pub use crate::invite::InviteTicket;
/// A join token: a literal mesh id, or a creator-minted invite.
pub use crate::resolver::{JoinTarget, JoinTargetError};

// Gate matches the definitions' (`any(test, feature)`): a narrower gate here
// leaves them `pub` but unreachable under a plain `cargo test`.
#[cfg(any(test, feature = "test-fixtures"))]
pub use message::{BuildMsgParams, ChainCtx, build_msg_bytes};

// Shared config for this crate's `proptest!` blocks: regression seeds land in
// `tests/proptest-regressions` rather than at the crate root. Every block opts
// in with `#![proptest_config(crate::proptest_support::config())]`.
#[cfg(test)]
pub(crate) mod proptest_support {
    use proptest::test_runner::{Config, FileFailurePersistence};

    pub(crate) fn config() -> Config {
        Config {
            failure_persistence: Some(Box::new(FileFailurePersistence::SourceParallel(
                "tests/proptest-regressions",
            ))),
            ..Config::default()
        }
    }
}
