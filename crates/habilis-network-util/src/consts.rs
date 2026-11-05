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

use std::time::Duration;

// The runtime base for per-mesh files is per-user and computed at runtime —
// see [`crate::runtime_base`] / [`crate::ensure_runtime_base`].
// It used to be a hardcoded shared product-named const; that let other
// local users traverse it and read per-member logs, so it moved to a
// uid-scoped, `0700` directory.

// Mesh ids and tickets carry no sigil and no `://` separator: both are bare
// Base58Check, told apart by the kind byte inside the payload (see
// `protocol::meshes`, `blob::ticket`, `invite::ticket`). They used to be branded
// with an emoji glyph, which cost a percent-encode in every URL, a non-ASCII
// component in every runtime path, and a variation-selector workaround in both
// ticket decoders. Being pure ASCII, an id now drops into a path, a URL, or a
// shell word verbatim.

/// Default lifetime of a minted invite ticket when `--ttl` is omitted (24h).
/// A finite window by default so a forgotten invite stops admitting; the
/// creator can override, and `--ttl none`/`0` mints a no-expiry invite.
pub const INVITE_DEFAULT_TTL: Duration = Duration::from_hours(24);

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
/// `protocol::messages::shard`).
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
pub const REASSEMBLY_STALE: Duration = Duration::from_mins(5);

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

/// The bytes that a frame that writes an entry again after a reset leaves free under a message. The
/// frame is measured when the cut is made, and a later write carries more dependencies, so the
/// margin keeps it inside the message. It must be at most the margin of the application that
/// publishes the entry (128 bytes in agent-gossip): with a larger margin the engine would refuse
/// after a reset a value that the application writes.
pub const DOC_EPOCH_FRAME_MARGIN: usize = 128;

/// How many sweep ticks a node tries to write its entry again after a reset when a send fails. At
/// the last one it gives up, so a send that never works does not make the slot wait for ever.
pub const DOC_EPOCH_WRITE_ATTEMPTS: u8 = 6;

/// The frame bytes a gated channel keeps in one epoch before the node starts a new one (a tunable).
/// A reset drops every frame of the epoch, then each owner writes its own entry again. The real
/// threshold is the larger of this value and twice the frame bytes that the epoch held when it
/// settled, so a mesh whose live entries fill the cap does not reset in a loop. The check runs once
/// per minute, so the bound is the threshold plus one minute of writes.
pub const DOC_EPOCH_FRAME_CAP_BYTES: usize = 1024 * 1024;

/// The frame bytes that the state channel keeps in one epoch before the node starts a new one
/// (provisional, a tunable). The real threshold is the larger of this value and twice the bytes
/// that the epoch held when it settled, as for meta. A reset costs one broadcast of the live
/// state, so a cap above the usual live size keeps resets rare.
pub const DOC_STATE_EPOCH_FRAME_CAP_BYTES: usize = 4 * 1024 * 1024;

/// The most frames that the root of a state seed can name. Before the epoch settles the threshold
/// is twice the cap, and a seed holds the live state, which is below that. A frame holds at least
/// half of the bytes of a message, so the count is twice the threshold over the usable frame
/// bytes. A root that names more is refused, so a forged mark cannot make a node hold more than
/// this many frames as a candidate, which is 4519 frames of at most 3840 bytes.
pub const DOC_SEED_FRAMES_MAX: usize =
    4 * DOC_STATE_EPOCH_FRAME_CAP_BYTES / (MAX_MESSAGE_SIZE - DOC_EPOCH_FRAME_MARGIN);

/// The most paths that one frame of a seed or a replay can write, and so the most stamps that its
/// `o` can carry. A frame holds 3840 bytes, so this bounds the work of a node that reads the stamps
/// of one frame. The sender splits a longer replay into frames of at most this many paths, and a
/// node refuses a frame that carries more.
pub const DOC_REPLAY_ENTRIES_MAX: usize = 128;

/// The most tombstones that a state document keeps, and that a seed carries: one for each path that
/// was deleted, with the stamp of the delete. The one with the lowest stamp leaves first. A node
/// that was away until the tombstone of a leaf left can bring back a value that others deleted.
/// 1024 entries of at most `DOC_TOMBSTONE_PATH_BYTES_MAX` bytes of path are under 300 kibibytes.
pub const DOC_SEED_TOMBSTONES_MAX: usize = 1024;

/// The most values that a state document keeps to write again after a replay (restores). A restore
/// holds a value that the node held, so the restores of a node are at most its live leaves. Nothing
/// bounds the live leaves to the epoch budget of `DOC_STATE_EPOCH_FRAME_CAP_BYTES`: the live state
/// can be as large as a seed of `DOC_SEED_FRAMES_MAX` frames carries, about 17 mebibytes. A leaf of
/// 100 bytes gives about 170000 leaves, and a leaf of 10 bytes gives more. This cap holds 65536
/// restores, which cost about 10 to 16 mebibytes of heap (150 to 250 bytes of overhead for each,
/// and the path and the value). A replay that hides more leaves than that loses the restores
/// beyond the cap: the newer writes of this node are not written again. They are counted and
/// warned, never silent.
pub const DOC_RESTORES_MAX: usize = 65_536;

/// The bytes that the stamp of one path adds to a frame of a seed, besides the digits of its time:
/// the index of the tag, the syntax, and a share of the table of tags. The stamp costs the digits
/// of the clock plus this number (`Limits::stamp_bytes`): 16 bytes for times of 7 digits, which is
/// what `tests/seed_cost.rs` measured (13 to 16), and 25 at the bound of the clock.
pub const DOC_STATE_STAMP_BYTES_BASE: usize = 9;

/// The most bytes that the stamp of one path can take in a frame of a seed: a time of 16 digits (the
/// bound `2^53` of the Lamport time), 3 digits of tag index, 4 of syntax and a new tag of 19 bytes.
/// A writer that sends such stamps can make a cut fail: it is a flood, not a case that the lines
/// cover.
pub const DOC_STATE_STAMP_BYTES_MAX: usize = 46;

/// The bytes of the content of a seed (its changes, with no stamp) for 100 bytes of the history that
/// made it. Measured at 83 to 95; 105 holds the margin of 10 percent.
pub const DOC_STATE_SEED_RATIO_PERCENT: usize = 105;

/// The deepest merge that a local write adds to a state document, counting the key of the leaf. A
/// seed frame repeats the keys above its first leaf, so the depth bounds how many leaves a seed
/// frame holds (`130 - 2 x depth` new paths).
pub const DOC_STATE_DEPTH_MAX: usize = 12;

/// The break-even of the paths of a state document: the cut ceiling is 0.75 of it (20 000 paths).
/// Every ingest reads the whole document, so a frame at this size costs about 130 ms; the largest
/// real document that was measured has 1 204 paths.
pub const DOC_STATE_PATHS_BREAK_EVEN: usize = 26_667;

/// The longest path (the bytes of its keys) that gets a tombstone. A delete of a longer path is
/// written and counted, and has no tombstone.
pub const DOC_TOMBSTONE_PATH_BYTES_MAX: usize = 256;

/// The bytes that the tombstones of one frame of a seed can take: the bytes of the paths and 32
/// for each entry (the time, the tag index and the punctuation). A frame holds 3840 bytes, so the
/// tombstones of a seed spread over its frames, and over carrier changes when there are more than
/// its frames can hold. Each tombstone counts against `DOC_REPLAY_ENTRIES_MAX` with the stamps.
pub const DOC_SEED_TOMBSTONE_FRAME_BYTES: usize = 1024;

/// How far above its own epoch a node adopts one (a tunable). A larger jump is refused, so a forged
/// epoch number cannot lock the channel: the forger raises the epoch by this much per adoption.
pub const DOC_EPOCH_JUMP_MAX: u64 = 131_072;

/// How many 1-minute ticks a node that holds the frames of others waits before it adopts a higher
/// epoch (a tunable). At the end it jumps to the highest epoch that it saw. A forger can force
/// at most 1 reset per wait on a node. A node that holds nothing from others adopts at once.
pub const DOC_EPOCH_ADOPT_WAIT_TICKS: u32 = 5;

/// Hard ceiling on a partial group's lifetime regardless of activity. The
/// idle TTL alone lets a hostile stream pin its buffered bytes forever by
/// trickling one shard per window; this bounds any single group's pin to an
/// hour (generous — a budget-respecting transfer completes in seconds to
/// minutes).
pub const REASSEMBLY_MAX_GROUP_LIFETIME: Duration = Duration::from_hours(1);

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
pub const REASSEMBLY_REPAIR_IDLE: Duration = Duration::from_mins(1);

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
