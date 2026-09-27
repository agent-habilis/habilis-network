//! `fofoca` — the serverless gossip-network engine.
//!
//! This workspace-internal crate holds the transport-and-protocol engine
//! decoupled from any one application (its data model, its
//! CLI/MCP bindings, the library `api`). It is never published
//! (`publish = false`); a consumer crate depends on it and re-exports
//! the curated public surface.

// ── Role-based public facade ──────────────────────────────────────────────
//
// The modules below are grouped by what a consumer needs, not by the engine's
// internal topology: `protocol` (value types), `embed` (the seams you
// implement), `runtime` (start/stop a node), `ops` (what a hook may do), `net`
// (the quarantined iroh corner), `util` (host helpers). The implementation
// modules they re-export from are crate-private.
pub mod embed;
pub mod net;
pub mod ops;
// Portable. The node runtime — `setup_mesh` → `Node::spawn` → the event loop —
// is the same on a CLI and in a browser; only the host-shaped *inputs* to it
// (the control socket, the session state file) are gated, inside the module.
// Before this, a wasm build of the crate exposed the protocol types and no way
// whatsoever to run a node, which made the wasm CI leg a compile check of code
// nobody could call.
pub mod runtime;
// One embedded membership of a mesh, over `runtime`: what the C ABI, the
// browser peer and the chat example share, so they resolve a mesh one way.
pub mod membership;

pub(crate) mod beacon;
// The blob-offload side-channel, re-exported through [`ops::blob`]. Its own
// feature because it is the one part of the engine a consumer can genuinely not
// want: it spools to disk and stands up a second iroh endpoint on its own ALPN.
#[cfg(feature = "blob")]
pub(crate) mod blob;
pub(crate) mod daemon;
pub(crate) mod gossip;
pub(crate) mod lifecycle;
pub(crate) mod lookup;

// Extracted leaf crates. Each owns one dependency the engine would otherwise
// carry unconditionally — automerge, tracing-subscriber — and each depends only
// on `fofoca-protocol`/`-util`, never back on this crate. Aliased so
// engine code keeps its `crate::doc::…` paths.
pub(crate) use fofoca_doc as doc;
pub(crate) use fofoca_logging as logging;

/// The wire vocabulary, re-exported from the leaf crate
/// `fofoca-protocol`. That crate builds on `iroh-base` alone — no
/// iroh, no iroh-gossip, no tokio — so a consumer that only needs to speak
/// the protocol does not pull in a network stack.
pub mod protocol {
    // Listed rather than `pub use fofoca_protocol::*`. A glob makes every
    // future `pub` item in the leaf crate part of *this* crate's API the
    // moment it is written, with no edit here and nothing to review — which
    // is how a surface nobody chose ends up needing a cross-repo grep to
    // shrink. Adding a name below is now a deliberate line.
    pub use fofoca_protocol::{
        AdvertiseRequiresReachable, AppFrameParams, AppTag, BodyError, Channel, ChoiceError,
        CorrId, DEFAULT_DIRECTORY, DirectorySelection, IdError, Identity, InviteTicket, JoinTarget,
        JoinTargetError, Lookup, LookupOpts, LookupSet, Mesh, MeshConfig, MeshId, MeshIdError,
        MeshName, Message, MessageBody, MessageId, MessageKind, NameError, Nickname, NicknameError,
        OptFlag, Password, PresenceSubtype, RelayChoice, RelayLadder, RelayLadderError,
        RelaySelection, Shard, ShardGroup, TicketAuth, TopicId, Transport, TransportPolicy,
        base58check, crypto, ct_eq, directory, encode_pubkey, identity, invite, iroh_base, mesh,
        message, nickname, peer_addr, reassembly, resolve_lookups, resolver, seal, seal_to_body,
        sole_addressee, validate_advertise,
    };
    #[cfg(any(test, feature = "test-fixtures"))]
    pub use fofoca_protocol::{BuildMsgParams, ChainCtx, build_msg_bytes};
}

/// Creator-minted invites. The redeem + decode primitives back
/// `resolver::JoinTarget::Invite`; `mint` is re-exported for consumers
/// through [`ops::invite`](crate::ops::invite).
pub(crate) use fofoca_protocol::directory;
pub(crate) use fofoca_protocol::invite;
pub(crate) use fofoca_protocol::resolver;

pub(crate) use fofoca_protocol::reassembly;

pub(crate) mod transport;

/// Shared unit-test fixtures. `#[cfg(test)]` so it costs a normal build
/// nothing; the modules that used to each carry their own copies reach it as
/// `crate::testing::…`.
#[cfg(test)]
pub(crate) mod testing;

/// Host helpers. The bulk lives in the leaf crate `fofoca-util`, which
/// has no engine or iroh dependency; it is re-exported here so both consumers
/// and engine code keep reaching it as `util::…`. The `logging` facade stays
/// on this side because it fronts the engine's own log sink.
pub mod util {
    // Listed rather than a glob, for the reason given on [`protocol`].
    pub use fofoca_util::{
        bounded_fifo_set, bounded_queue, clock, consts, cooldown, logs, mesh_prefix,
        resident_memory, tuning, version,
    };
    // The runtime-directory helpers are `host`-gated in the leaf crate: they
    // are filesystem and uid work a browser has no equivalent of. The glob
    // this replaced forwarded them without saying so.
    #[cfg(feature = "host")]
    pub use fofoca_util::{
        ensure_mesh_runtime_dir, ensure_parent_private, ensure_runtime_base, is_under_runtime_base,
        mesh_runtime_dir, runtime_base,
    };
    // `bounded_read` is gated on `fofoca-util`'s `async-io`, which this crate
    // turns on unconditionally in its manifest — so it is always here, and a
    // `#[cfg(feature = "async-io")]` would be checking a feature *this* crate
    // does not have and silently never fire. `process` is gated on `host`,
    // which both crates do have, and this one forwards.
    pub use fofoca_util::bounded_read;
    #[cfg(feature = "host")]
    pub use fofoca_util::process;

    /// Deferred `tracing` sink and the pinned directive filter.
    pub mod logging {
        pub use crate::logging::messages::log_out;
        /// The file sink and the filter that feeds it. `host`-only: a browser
        /// has no log file to defer writes to, and logs to the console
        /// instead. `log_out` above stays portable — the per-message logger is
        /// how a peer reports what it sent and received, on either target.
        #[cfg(feature = "host")]
        pub use crate::logging::{LogSink, attach, flush_pending_to_stderr, install, log_filter};
    }
}

// Re-exported at the crate root so engine code (and the app's re-export) can
// reach the build version stamp as `crate::VERSION`.
pub use util::version::VERSION;

/// The relay ladder, re-exported so consumers resolve `Pinned` to the **same**
/// rungs this crate's gossip does.
///
/// `lookup` is `pub(crate)`, so without this agent-share had to keep its own
/// copy of the list — two constants that must agree, with nothing to make them.
/// A share and the mesh derived from it should home on one relay, not two.
pub use lookup::RENDEZVOUS_RELAY_LADDER;

// The `NodeApp` / `NodeDriver` seams are `#[async_trait]`, so any consumer
// implementing them needs the same macro. Re-export it so a downstream crate
// annotates its impls with `#[fofoca::async_trait]` instead of
// taking its own (version-matched) `async-trait` dependency.
pub use async_trait::async_trait;

/// The forked `iroh` this engine is built against, re-exported whole.
///
/// **Take iroh from here, never as your own dependency.** The engine needs a
/// forked iroh (relay teardown, mapped-addrs eviction), and a consumer that
/// declares `iroh` itself gets the published one — two `iroh` crates in one
/// graph, at which point an `Endpoint` from one will not satisfy a signature
/// expecting the other. That failure is an `E0308` on types that look
/// identical, pointing nowhere near the manifest at fault.
///
/// Reaching it through this re-export is what lets a consumer carry **no**
/// `[patch.crates-io]` at all: cargo honours a patch only in a workspace root
/// and never inherits one, so every alternative means restating our pins by
/// hand in every consumer, silently wrong the moment one drifts.
///
/// This does not contradict "iroh stays an internal detail" — it enforces it.
/// The detail is now reached through one door instead of copied into every
/// consumer's manifest.
pub use iroh;

/// The mainline-DHT address-lookup provider, re-exported for the same reason as
/// [`iroh`]: it is forked to pin iroh, so a consumer naming the published crate
/// would put a second iroh in the graph. Gated on the feature that pulls it.
#[cfg(feature = "dht")]
pub use iroh_mainline_address_lookup;
/// The mDNS address-lookup provider — same reasoning as
/// [`iroh_mainline_address_lookup`], gated on `mdns`.
#[cfg(feature = "mdns")]
pub use iroh_mdns_address_lookup;

// Shared config for the crate's `proptest!` blocks. Overrides the default
// failure-persistence path so regression seeds land in
// `tests/proptest-regressions` rather than a `proptest-regressions` folder
// at the crate root. Every `proptest!` block opts in with
// `#![proptest_config(crate::proptest_support::config())]`. Kept last so it
// does not trip `clippy::items_after_test_module`.
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
