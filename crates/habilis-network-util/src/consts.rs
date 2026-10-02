//! The wire contracts: values every member of a mesh must agree on
//! bit-for-bit, plus the local caps derived from them.
//!
//! **The split with [`crate::tuning`] is by who may change a value.** Nothing
//! here is tunable — changing one changes what this build can interoperate
//! with, so it changes for everyone or for no one. A knob that only affects
//! this process's timing, capacity or policy belongs in `tuning` instead,
//! next to the accessor that reads it.
//!
//! The rule used to be invisible: a constant lived here if it happened to have
//! a hidden CLI flag, and its doc was restated on the accessor in `tuning` that
//! read it. The two copies had already drifted.

// The runtime base for per-mesh files is per-user and computed at runtime —
// see [`crate::runtime_base`] / [`crate::ensure_runtime_base`].
// It used to be a hardcoded shared product-named const; that let other
// local users traverse it and read per-member logs, so it moved to a
// uid-scoped, `0700` directory.

// Mesh ids and tickets carry no sigil and no `://` separator: both are bare
// Base58Check, told apart by the kind byte inside the payload (see
// `protocol::mesh`, `blob::ticket`, `invite::ticket`). They used to be branded
// with an emoji glyph, which cost a percent-encode in every URL, a non-ASCII
// component in every runtime path, and a variation-selector workaround in both
// ticket decoders. Being pure ASCII, an id now drops into a path, a URL, or a
// shell word verbatim.

/// Default lifetime of a minted invite ticket when `--ttl` is omitted (24h).
/// A finite window by default so a forgotten invite stops admitting; the
/// creator can override, and `--ttl none`/`0` mints a no-expiry invite.
pub const INVITE_DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

/// Maximum size in bytes of a serialized mesh message. A network-wide
/// wire contract (must be uniform across members), so it lives here.
///
/// Kept below iroh-gossip's `DEFAULT_MAX_MESSAGE_SIZE` (4096) minus its
/// ~39-byte wire header: a message larger than gossip's payload budget
/// is silently dropped by the gossip layer (it never propagates and the
/// sender gets no error), so our cap must stay under it. A compile-time
/// assertion in the binary guards that relationship against the live
/// gossip constant; the value is hardcoded here rather than derived from
/// iroh-gossip's (so this module pulls in no dependency).
pub const MAX_MESSAGE_SIZE: usize = 3840;

/// Sanity ceiling on a shard header's advertised `total`. **Not** a memory
/// guard — the reassembly store never allocates by `total` and is bounded by
/// its byte budgets — just a tripwire that rejects an absurd header at
/// `Message::parse`. Sized with ~2x headroom over the most shards a
/// budget-respecting body can need ([`REASSEMBLY_GROUP_MAX_BYTES`] divided by
/// a worst-case per-shard body budget; pinned by a unit test in
/// `protocol::message::shard`).
pub const MAX_SHARD_TOTAL: u32 = 65_536;

/// Largest shard group whose frames still enter the message log (and thus
/// heal via anti-entropy) — exactly the old 16-shard behavior. A bigger
/// group's shards skip the log so one huge body can't evict the mesh's whole
/// anti-entropy history; those transfers are transport-reliable instead
/// (QUIC streams on the unicast connection).
pub const LOGGED_SHARD_GROUP_MAX_TOTAL: u32 = 16;

/// Upper bound on a logical (possibly multipart) body the daemon will accept
/// from a caller — a **local input + surfacing bound, not a wire bound** (the
/// wire is bounded by the reassembly byte budgets below). Enforced by the
/// stdin/IPC readers and the send path; anything larger belongs on the blob
/// channel ([`MAX_BLOB_BYTES`], disk-streamed). Generous, but a bound: the
/// daemon buffers a full input line and every peer's surfaced ring holds full
/// bodies, and a gossip-fallback of one such body already floods
/// `MAX_LOGICAL_BODY_BYTES / MAX_MESSAGE_SIZE` (~18k) frames to every peer.
pub const MAX_LOGICAL_BODY_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Ceiling applied to an already-**sealed** directed body (task legs, RPC).
/// Sealing base58-encodes the payload (~1.37× inflation), so checking a
/// sealed body against the raw input ceiling would silently shrink the
/// documented limit to ~46 `MiB` for directed sends only; 1.5× headroom keeps
/// the caller-facing ceiling uniform at [`MAX_LOGICAL_BODY_BYTES`].
pub const MAX_SEALED_BODY_BYTES: usize = MAX_LOGICAL_BODY_BYTES + MAX_LOGICAL_BODY_BYTES / 2;

// ── Shard reassembly budgets ──────────────────────────────────────
//
// The reassembly store buffers *partial* multipart bodies until every shard
// arrives. Its bounds are byte budgets (not shard counts), expressed as
// multiples of [`MAX_LOGICAL_BODY_BYTES`] so they scale with the input
// ceiling: sealing (base58) + JSON escaping inflate a body ~1.5×, hence the
// 2× per-group headroom.

/// Ceiling for one partial group's buffered bytes — a sealed max-size body
/// fits; anything claiming more is a crafted stream and the group is dropped.
pub const REASSEMBLY_GROUP_MAX_BYTES: usize = 2 * MAX_LOGICAL_BODY_BYTES;

/// Per-author (pubkey) budget across that author's partial groups. A hostile
/// peer exhausts only its own budget; breaching it evicts that author's
/// stalest incomplete group rather than anyone else's.
pub const REASSEMBLY_AUTHOR_BUDGET_BYTES: usize = 3 * MAX_LOGICAL_BODY_BYTES;

/// Global backstop across all authors — pubkeys are free (Sybil), so the
/// per-author budget alone is not a bound. Breaching it drops the incoming
/// shard's group (fail closed, never balloon).
pub const REASSEMBLY_TOTAL_BUDGET_BYTES: usize = 6 * MAX_LOGICAL_BODY_BYTES;

/// A partial group that gained no **new** shard for this long is reaped
/// (swept on the 1-minute prune tick). Only progress refreshes the clock —
/// a duplicate slot does not, so an attacker can't keepalive a dead group
/// with resends — and a slow-but-live transfer is never reaped mid-flight.
pub const REASSEMBLY_STALE_SECS: u64 = 300;

/// Per-author (pubkey) ceiling on orphan channel changes buffered awaiting
/// their dependencies. Counted rather than weighed because
/// [`MAX_MESSAGE_SIZE`] already bounds one frame, so a count *is* a byte
/// bound and states the limit in the unit the attack is measured in.
///
/// Generous against honest backfill: a holder answers one anti-entropy digest
/// with at most [`crate::tuning::ANTIENTROPY_MAX_RESEND`] frames, and those are spread across
/// whichever authors wrote them.
pub const DOC_PENDING_AUTHOR_MAX: usize = 128;

/// Global backstop across all authors — pubkeys are free (Sybil), so the
/// per-author ceiling alone is not a bound. Breaching it refuses the incoming
/// orphan rather than evicting across authors, which would let one hostile
/// stream flush a joiner's honest backfill.
pub const DOC_PENDING_TOTAL_MAX: usize = 512;

/// Hard ceiling on a partial group's lifetime regardless of activity. The
/// idle TTL alone lets a hostile stream pin its buffered bytes forever by
/// trickling one shard per window; this bounds any single group's pin to an
/// hour (generous — a budget-respecting transfer completes in seconds to
/// minutes).
pub const REASSEMBLY_MAX_GROUP_LIFETIME_SECS: u64 = 3600;

/// Fixed overhead one buffered shard charges on top of its body bytes — the
/// map nodes, cloned keys, and (for shard 0) the retained envelope clone.
/// Charging body bytes alone undercounts a tiny-shard flood by an order of
/// magnitude, letting real memory blow past the budgets the store enforces.
pub const REASSEMBLY_SLOT_OVERHEAD_BYTES: usize = 512;

/// Minimum total charge for one buffered shard, so a flood of 1-byte crafted
/// shards across millions of groups still pays for the ~KB of real state each
/// one occupies (envelope clone + map/key overhead).
pub const REASSEMBLY_SLOT_MIN_CHARGE_BYTES: usize = 2048;

/// How long a big (unlogged) partial group may sit without progress before
/// the receiver asks the author to re-send its missing shards (`shard/repair`
/// over the gossip RPC). Checked on the 1-minute prune tick; with the 300s
/// idle TTL this yields several repair rounds before the group is reaped.
pub const REASSEMBLY_REPAIR_IDLE_SECS: u64 = 60;

/// Max missing indexes one repair request names (and the serve side honors) —
/// bounds both the request body and the resend burst; a wider gap heals over
/// successive rounds.
pub const REASSEMBLY_REPAIR_MAX_IDXS: usize = 64;

/// Byte budget of the sender-side shard cache — the serialized frames of
/// recent big (unlogged) outbound groups, kept so a receiver's
/// `shard/repair` request can be served. Big groups skip the message log
/// (they must not evict the anti-entropy history), so this cache is their
/// only re-serve source. Whole-group FIFO eviction; sized to hold one
/// max-size group.
pub const SHARD_CACHE_BUDGET_BYTES: usize = REASSEMBLY_GROUP_MAX_BYTES;

/// Largest single file the blob channel will offload. Streamed from disk on
/// both ends (never buffered whole), so this is a disk-bound per-blob ceiling,
/// not a memory cap — a generous limit that stops a hostile ticket from
/// claiming an absurd `size`.
pub const MAX_BLOB_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Spool-disk budget for one peer's blob store (`<nick>.blobs/`). Snapshotting a
/// new blob that would push the store past this unlinks the oldest spooled
/// blobs to make room — a hard cap, so it can drop a still-referenced blob under
/// pressure (the fetch then fails cleanly rather than corrupting).
///
/// `host`-only with the spool itself: only a producer writes blobs to disk.
#[cfg(feature = "host")]
pub const MAX_BLOB_STORE_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

/// Capacity of the unicast inbound channel — frames the `UNICAST_ALPN` acceptor
/// forwards to the event loop for `gossip::ingest`. Bounded so a peer flooding a
/// unicast stream can't back-pressure the loop; over the cap a frame is dropped
/// (non-blocking `try_send`) and recovered via anti-entropy.
pub const UNICAST_INBOX_CAP: usize = 256;

/// Max bytes for one IPC command line: a full logical body in a JSON envelope
/// (mesh id, nickname, keys). The body travels JSON-escaped inside the line
/// — worst case every char doubles (quotes/backslashes/newlines) — so budget
/// **2×** the raw ceiling plus envelope headroom, or an escape-heavy body
/// within the documented limit is refused at the socket.
///
/// `host`-only with the IPC listener — a browser binds no socket.
#[cfg(feature = "host")]
pub const MAX_IPC_COMMAND_BYTES: usize = 2 * MAX_LOGICAL_BODY_BYTES + 2 * MAX_MESSAGE_SIZE;

/// Max bytes for one IPC response line. A rendered event carries the body
/// **twice** (the raw field plus the `display` re-render), each JSON-escaped
/// (worst case 2× the raw bytes), so one event can render to ~**4×** its raw
/// body plus envelope — the response cap must clear that for a max-size body
/// or the event could never be polled and the client's cursor would wedge on
/// it forever. `poll` batches byte-aware against this bound
/// (`EventLoopState::poll_since`), returning the oldest prefix that fits;
/// the client re-polls for the rest.
#[cfg(feature = "host")]
pub const MAX_IPC_RESPONSE_BYTES: usize = 5 * MAX_LOGICAL_BODY_BYTES;

// ── Password KDF (wire contract) ──────────────────────────────────
//
// Argon2id cost parameters for `--password` stretching. A NETWORK-WIDE WIRE
// CONTRACT: every member derives the stretched key with these exact params
// (the derivation feeds the mesh topic/rendezvous and the ticket handshake
// token), so changing any value strands every existing passworded mesh and
// ticket. 19 MiB / t=2 / p=1 is the OWASP Argon2id recommendation — ~50-100ms
// per stretch, paid once at create/join/handshake, never per message.

/// Argon2id memory cost in `KiB` (19 `MiB`).
pub const PASSWORD_KDF_M_COST_KIB: u32 = 19_456;

/// Argon2id iteration count.
pub const PASSWORD_KDF_T_COST: u32 = 2;

/// Argon2id lane count.
pub const PASSWORD_KDF_P_COST: u32 = 1;

// ── Daemon tuning defaults ────────────────────────────────────────
//
// Behavioural knobs that used to be environment-overridable. They now live
// here as constants: an experiment is an *edit + commit* (under version
// control, with history), never an ephemeral shell var. Each is the default
// for the matching hidden CLI flag (`--alive-timeout-secs`, …) that the
// subprocess test suite passes to run with short timings; production reads the
// const. See `habilis_network::util::tuning`.

// A public `EagerProbed` beacon holder (topic joiner, directory advertiser)
// periodically *sheds* its beacon and re-runs probe-before-claim, because two
// members that claimed inside each other's probe window both hold the same
// `rendezvous_id` and each captures its own bootstrap dial — a split that
// nothing else repairs (see `daemon::event_loop::shed_rival_beacon_if_due`).

// QUIC keep-alive / idle timeout are intentionally left at iroh's
// holepunch-tuned transport defaults (~1s keep-alive, 15s direct / 30s relay
// idle); see `lookup::build_endpoint`. A prior override (5s keep-alive, 10s
// idle) fought iroh's QUIC-multipath tuning and drove connection-churn — a
// per-connection memory leak. The sleep-wake reliability tests therefore freeze
// a peer past iroh's 15s direct-path idle to force a link death.
