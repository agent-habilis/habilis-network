# Forked from agent-habilis/agent-gossip

This workspace began as a verbatim vendoring of a subset of
`agent-habilis/agent-gossip` (see `VENDORED.md` for that original contract). It
is now a **fork**: the engine has been split into separate crates, so the
"re-copy the crate directories" update procedure no longer applies.

- **Upstream URL**: https://github.com/agent-habilis/agent-gossip
- **Divergence commit**: `f81b0529ee1b66725295998f15292df1e1ca191c`

Taking an upstream change now means porting it by hand into whichever crate
owns that code. The table under "Where things moved" maps upstream paths to
their new homes.

## Why

A cost measurement in the original host repo (`docs/ffi-cost.md`) measured the engine at **39.4 MiB of
a 40.7 MiB release binary**, with the engine's own code accounting for
0.75 MiB of `__text` and the rest being its dependency closure. Cargo features
cannot be selected per-consumer across a dependency edge, so making that closure
optional required crate boundaries.

## Crate layout

Dependencies point strictly downward.

```
habilis-network-util          no deps of consequence          (13 crates resolved)
  └── habilis-network-protocol    + iroh-base                 (138 crates)
        ├── habilis-network-doc          + automerge
        ├── habilis-network-logging      + tracing-subscriber
        ├── habilis-network-reassembly
        ├── habilis-network-directory
        └── habilis-network         + iroh, iroh-gossip  (436 crates)
              └── habilis-network-ffi

habilis-network-blobs                      + bao-tree, blake3   (standalone)
habilis-network-iroh-webrtc-transport      + iroh, str0m        (standalone)
habilis-network-iroh-multihop-transport    + iroh               (standalone)
```

The bottom three are off the tree: none depends on anything in this workspace.
The engine takes the multihop transport; the other two are a consumer's
business. See carried changes 18, 19 and 20.

The load-bearing property: **only `habilis-network` names `iroh`**. `habilis-network-protocol`
builds on `iroh-base` alone and pulls no tokio, QUIC, TLS or DNS; `-doc` and
`-logging` inherit that.

## Where things moved

The left column is the path upstream still uses; the right is ours. The whole
workspace was also renamed from `agent-habilis-mesh/` to `habilis-network/`.

| upstream path | now |
|---|---|
| `agent-habilis-mesh/src/util/` | `habilis-network-util/src/` |
| `agent-habilis-mesh/src/protocol/` | `habilis-network-protocol/src/` |
| `agent-habilis-mesh/src/{invite,resolver}/` | `habilis-network-protocol/src/{invite,resolver}/` |
| `agent-habilis-mesh/src/doc/` | `habilis-network-doc/src/` |
| `agent-habilis-mesh/src/logging/` | `habilis-network-logging/src/` |
| `agent-habilis-mesh/src/reassembly/` | `habilis-network-reassembly/src/` |
| `agent-habilis-mesh/src/directory/` | `habilis-network-directory/src/` |
| `agent-habilis-mesh/src/blob/` | deleted — see carried change 18 |
| `agent-habilis-mesh-ffi` | `habilis-network-ffi` |
| everything else | unchanged in `habilis-network` (was `agent-habilis-mesh`) |

`habilis-network` re-exports `util`, `protocol`, `doc`, `logging`,
`reassembly` and `directory` under their old module paths, so engine-internal
code and the `embed`/`net`/`ops`/`runtime` facades read as before.

## Carried changes

Divergences from upstream, in the order they were made.

**From the original vendoring** (all still in force):

1. Virtual workspace root `Cargo.toml` (upstream has a root package). `resolver
   = "3"` is load-bearing: it stops the `test-fixtures` dev-dep feature folding
   into the shipped binary.
2. `[profile.release]` uses `lto = "thin"`, `codegen-units = 16`,
   `strip = "debuginfo"` rather than upstream's fat-LTO / 1-CGU, for dev-loop
   speed.
3. Upstream's `panic = "abort"` deliberately **not** carried: `ffi.rs` relies on
   `catch_unwind` at the C boundary.
4. FFI extension: a `name` field alongside `nick`, plus `mesh_name()`, across
   `pipe.rs` / `ffi.rs` / `include/mesh.h` / `tests/ffi_smoke.rs`; and the
   `staticlib` crate-type.
5. `tests/c_suite.rs` dropped (it hardcodes paths into upstream `examples/`).

**From the split:**

6. The crate split above, with `pub(crate)` items promoted to `pub` where a
   crate boundary now sits between definition and use.
7. `protocol` no longer depends on `iroh-gossip`. Its `TopicId` is a local
   32-byte newtype (`habilis-network-protocol/src/topic.rs`) with a hex `Debug`
   matching iroh-gossip's; `daemon::setup` converts at the two `gossip.subscribe`
   call sites. The `MAX_MESSAGE_SIZE` compile-time tripwire moved to
   `habilis-network/src/gossip/mod.rs`, which can still name
   `DEFAULT_MAX_MESSAGE_SIZE`.
8. New cargo features: `mdns` and `dht` on `habilis-network` (default on,
   forwarded by `habilis-network-ffi`), and `async-io` on
   `habilis-network-util` gating `bounded_read`, which is the only tokio user
   below the engine.
9. Dropped the unused `anstyle` / `anstream` dependencies (zero references).
10. `ops::blob` removed — the blob-transfer crate depended on the engine, so
    the engine could not re-export it. Superseded by carried change 18, which
    deleted that crate.
11. `public-surface.txt` moved to the workspace root and regenerated, since it
    now spans eight crates.

**From the rename:**

12. Everything named for the upstream org was renamed to **habilis-network**: the
    directory, all eight crates (`agent-habilis-mesh` → `habilis-network`,
    `agent-habilis-mesh-ffi` → `habilis-network-ffi`, `agent-habilis-<x>` →
    `habilis-network-<x>`), their lib names, the 89 `tracing` targets and the matching
    `log_filter` directives, the C ABI (`mesh_*` → `habilis_network_*`, types
    `mesh_{pipe,opts,frame}` → `habilis_network_*`), the header (`include/mesh.h` →
    `include/habilis_network.h`, guard `HABILIS_NETWORK_H`), the staticlib
    (`libhabilis_network_ffi.a`), the blob ALPN (`habilis-mesh/blob/1` →
    `habilis-network/blob/1`) and the default mesh name (`"mesh-ffi"` → `"habilis-network"`).
    The `github.com/agent-habilis/*` URLs above are upstream repositories and
    are deliberately untouched.

**From the extraction** (moving out of the original host repo into its own):

13. `iroh-multihop-transport` left the workspace for
    [its own repo](https://github.com/agent-habilis/iroh-multihop-transport).
    It has no habilis-network dependency and its audience is any iroh user. It is now a
    git dependency pinned by rev in `[workspace.dependencies]`. Note that
    `[patch.crates-io]` below still governs it — patch applies from the
    top-level workspace root across the whole graph, git dependencies included.

    **Reversed by carried change 20**, which brought it back as a member.
14. The `iroh` / `iroh-gossip` forks were re-homed from `agent-habilis` to
    `fofoca-network` so this workspace owns its entire pin surface. The commits
    were pushed unchanged, so **the rev SHAs are identical** — only the URLs in
    `[patch.crates-io]` moved.

    **Reversed on 2026-10-02**, with the rename to habilis-network: all five
    forks moved back to `agent-habilis`. This time the revs changed, because
    each fork's own pins had to name the `agent-habilis` URLs too.
15. `public-surface.txt` was **deleted**. Nothing in the tree ever generated or
    checked it, so it silently rotted: by the time of the extraction it was
    ~530 entries behind and still listed `iroh-multihop-transport`, which no
    longer lives here. It cannot be faithfully regenerated by grepping for
    `pub` — it tracked the *reachable* API, so `pub` items inside private
    modules were correctly absent. Reinstating it means a real API-extraction
    tool (`cargo public-api`) plus a CI diff, not a shell script.
16. Added the things a standalone repo needs and the vendored copy lacked:
    `LICENSE` (every crate already declared MIT), a root `README.md`, and CI.
    `crates/*/version` moved to `version.workspace = true` — `habilis-network-ffi` had
    drifted to `0.0.0` while the rest sat at `0.5.0`.
17. `docs/ffi-cost.md` and `scripts/measure-ffi-cost.sh` stayed behind in
    the host repo — they measure its binary, not this workspace.

**From reclaiming the `habilis-network-blobs` name:**

18. The blob-transfer crate — upstream's `agent-habilis-mesh/src/blob/`, carved
    out by change 6 — was **deleted**, and the name reassigned to an unrelated
    crate brought in from `agent-habilis/agent-share`.

    It was dead code here: no `use habilis_network_blobs::` anywhere in the workspace, no
    reverse edge in `Cargo.lock`, and `habilis-network-ffi` — the host's only entry point
    — never depended on it. It is recoverable from history if a consumer ever
    wants it back; upstream `agent-gossip` still carries it under `src/blob/`.

    What took the name is a BLAKE3/bao verified-byte-range store: outboards,
    chunk availability, and a `BlobStore` seam over bytes the caller already
    owns, with in-memory, filesystem, OPFS and `IndexedDB` backends. It shares
    no code, no wire format and no dependency with what it replaced — the two
    crates only ever shared a name.

    Two invariants got stronger as a result. "Only `habilis-network` and `-blobs` name
    `iroh`" became **only `habilis-network` names `iroh`**, and the dependency graph lost
    its one upward edge: the new crate depends on nothing in this workspace, so
    it sits beside the tree rather than above the engine. Its own
    `tests/isolation.rs` is what keeps that true.

19. `habilis-network-iroh-webrtc-transport` arrived from the same repo. It is an iroh
    custom transport carrying QUIC datagrams over a WebRTC data channel, and it
    is what lets a browser reach a peer at all — a tab has no UDP socket, so
    iroh's own paths do not exist there. Like `habilis-network-blobs` it depends on
    nothing else here, so it sits beside the tree.

    Its two backends were renamed on the way in: `host` → **`native`** and
    `web` stayed, along with `src/host/` → `src/native/`. `host` collided with
    the engine's own `host` feature, which means something related but not the
    same, and the pair now says plainly which of two mutually exclusive
    implementations gets compiled.

    The `iroh` requirement stays at `1.0.1` rather than moving to this
    workspace's `1.0.2`. The crate is still consumed from `agent-share`, whose
    patch table supplies 1.0.1; a `1.0.2` floor would be unsatisfiable there.
    Raise it once both sides pin the same fork.

    CI grew four steps for it. Neither backend is on by default, so every
    existing job built neither, and the `web` half had never been linted at all
    — `agent-share` only ever ran `cargo check` against wasm32, never clippy.
    Its first clippy pass produced 18 findings, all fixed here.

20. `iroh-multihop-transport` came back as a member, reversing change 13, and
    `agent-share`'s vendored copy of it was deleted in favour of this one. There
    were three copies of this crate in circulation; now there is one.

    The reasoning in 13 still holds — it has no habilis-network dependency and its
    audience is any iroh user — but a separate repo bought nothing and cost a
    rev pin to bump on every change. What it was protecting is a property of the
    *manifest*, not of the repository: the crate still names only crates.io
    `iroh`/`iroh-base`, and nothing here may leak into it.

    Its `iroh` requirement was lowered from `1.0.2` to `1.0.1` on the way in.
    `agent-share` patches `iroh` to a 1.0.1 fork, and a `1.0.2` requirement is
    not satisfied by 1.0.1 — so cargo would ignore that patch, resolve unpatched
    crates.io alongside it, and put two `iroh_base` crates in the graph, at
    which point `CustomAddr` stops unifying (E0308). `agent-share`'s vendored
    copy had already been lowered for exactly this reason; the split to a
    separate repo had silently undone it, and consuming that version would have
    reintroduced the bug. `1.0.1` is satisfied by both forks.

    The now-unused [standalone repo](https://github.com/agent-habilis/iroh-multihop-transport)
    is superseded, not deleted.

21. Every dependency named by more than one crate now lives in
    `[workspace.dependencies]` and nowhere else. Members opt in with
    `dep.workspace = true` and may union in extra features, but no member
    restates a version.

    This started as tidiness and is not: `iroh` sat at `1.0.2` in the workspace
    while both transports named `1.0.1` locally. Nothing had broken yet, but two
    versions of `iroh`/`iroh-base` in one graph is precisely how a
    `CustomTransport` impl stops satisfying the trait iroh hands back, and the
    E0308 it produces points nowhere near the manifests that caused it.

    `iroh` and `iroh-base` also moved to `default-features = false`. A member
    cannot turn off default features that the workspace entry turns on, and the
    WebRTC transport's browser backend must have them off — iroh's defaults drag
    `tokio/net` → `mio`, which refuses to build for wasm32. So the off position
    lives at the root and `habilis-network` re-adds `metrics`, `portmapper` and
    `fast-apple-datapath` by name, `habilis-network-protocol` re-adds `relay`.

    `noq-udp`, `n0-watcher`, `wasm-bindgen`, `wasm-bindgen-futures`, `js-sys`
    and `web-sys` moved up at the same time, each having been named by two
    crates.

22. **The engine builds for the browser.** `agent-habilis/agent-share` had been
    carrying a vendored fork of the engine since it needed a wasm32 peer, and
    that fork's changes came back here — the last and largest of the moves.

    The two histories were one commit apart: agent-share vendored
    `agent-gossip@8914557`, this workspace forked at `f81b0529`. So this was a
    real three-way merge rather than a hand-reconciliation. 54 of 83 files
    merged clean; the 86 conflicts were almost all the same shape — the split
    and rename on one side, a `host` gate or a de-glyphed doc line on the
    other — and resolving them meant taking both.

    What arrived:

    - A **`host` feature**, on by default, in every crate. Off, what is left is
      the portable engine: gossip, the CRDT documents, the protocol and
      identity types, address lookup, the whole node runtime. `interprocess`,
      `libc`, signals, processes and the filesystem have no wasm32 equivalent
      and are gone with it. It has to exist in six places because the split put
      the host-only code in six crates, so `habilis-network/host` forwards to each leaf.
    - **A portable clock.** `habilis-network-util::clock` is now `web-time`, which off
      wasm32 *is* `std::time` and pulls in nothing. Without it every
      `Instant::now()` in the portable core panics in a browser — and
      `unix_secs` stamps every `Message`, so a browser peer could not author a
      single frame. The failure is invisible to `cargo check`, which is what
      `tests/wasm_runtime.rs` exists to catch.
    - **The WebRTC lane**, `transport/webrtc.rs` and `transport/admission.rs`,
      wiring the transport crate into the engine. `TransportHandles` and
      `TransportOpts` in `lookup` replace a growing positional argument list,
      and `TransportOpts` is deliberately *not* part of the mesh id: a browser
      only ever has relay and WebRTC, so baking transports into mesh identity
      would mean a browser could never join a mesh a CLI created.
    - Fixes that were never wasm-related and are worth having on their own: the
      beacon sheds on every release path instead of being dropped, its
      probe-before-claim runs off the event loop, a peer retains its own
      broadcasts so anti-entropy can converge, and native peers stay off the
      WebRTC lane.

    Two knock-on manifest changes: `tokio` and `iroh-gossip` in
    `[workspace.dependencies]` dropped to a portable floor with
    `default-features = false`, since a member cannot turn off defaults the
    workspace turns on; and `.cargo/config.toml` now carries the
    `getrandom_backend` rustflag, which `getrandom` 0.3+ requires and says so
    in a `compile_error!`.

23. A `clippy.toml`, aligned with agent-share's. Most of this workspace is now
    code written under that configuration, and without the file the two repos
    disagree on every configurable lint even though their `[workspace.lints]`
    match. One deliberate divergence, documented in the file:
    `warn-on-all-wildcard-imports` cannot hold here, because the `protocol` and
    `util` facades are `pub use habilis_network_protocol::*` — the mechanism by which
    the split crates keep their old module paths.

24. **The upstream app's remaining engine delta, merged back in.** `agent-gossip`
    kept developing the engine after the divergence commit; this repo took the
    three things it was ahead on and the app then dropped its copy entirely
    (`crates/agent-habilis-mesh` and its satellites are gone from that repo, and
    it now consumes this one as a sibling path dependency). What came across:

    - The **directed-frame confinement fix** (upstream `0b9f438`).
      `MessageLog::missing_in_window` takes a `MissingQuery` carrying *who is
      asking*, and `resendable_to` refuses to offer a frame with a sole
      addressee to anyone but that addressee; anti-entropy resends now route
      through `transport::deliver` instead of straight onto gossip. Before this,
      a directed message between two peers reached the whole mesh during
      backfill. Hand-ported, not cherry-picked — `event_loop.rs` and `recv.rs`
      had moved ~200 and ~105 lines ahead here for the wasm and admission work.
    - **`IdleCounters`** (`daemon/state.rs`): one counter per `select!` arm,
      drained onto the `mesh census` line each `state_refresh` tick as a delta.
      Plain `u64` behind `&mut EventLoopState`, because the arms measured fire up
      to 150×/min and a `debug!` per wakeup would price its own instrumentation
      into the measurement. This repo's two extra beacon arms (`rung_rx.changed`,
      `probe_verdict`) count as `external`, which keeps `wakeups` equal to the
      column sum while still reading 0 on a settled daemon.
    - The **`netwatch` RTM_MISS pin** — see below. It was the one patch upstream
      had that this repo did not, and it is worth 2.01% → 0.06% of a core idle.

25. **`ops::blob` restored, behind a default-off `blob` feature.** Change 5
    deleted the blob crate wholesale on the grounds that `habilis-network-blobs` replaced
    it. It does not: `habilis-network-blobs` is a verified-range *metadata store* that
    states in its own module docs that it has no transport, no ALPN and no
    framing, while `ops::blob` is the transport — a `habilis-mesh/blob/1` server,
    a ticket, and fetch/offload over QUIC. They are complements. agent-share is
    the proof: it uses `habilis-network-blobs` *and* hand-built ~6,850 LOC of `MOUNT_ALPN`
    transfer on top. agent-gossip needs the transport for A2A payload offload, so
    `crates/habilis-network/src/blob/` came back unchanged (same wire format, same ALPN)
    behind a feature that implies `host`. Consumers that don't enable it —
    C hosts, agent-share — pay neither the code size nor the spool directory.

    The one test that could not come back as-is is the invite↔blob cross-parse
    assertion: `invite` now lives in `habilis-network-protocol`, which cannot see `blob`.
    It moved to `blob/ticket.rs`, which can see both.

26. **`SetupBuild::protocols` is a `Mutex`, not a `RefCell`.** `RefCell` is not
    `Sync`, which made `SetupBuild` not `Send`, which made the whole `setup_mesh`
    future not `Send` — so a consumer could not `tokio::spawn` a mesh setup at
    all. agent-gossip does, in two places (its directory advertiser and
    `api::Session`). Nothing is contended and no guard is held across an `.await`;
    the `Mutex` is bought purely for the `Sync`.

27. **`iroh-multihop-transport` is now `habilis-network-iroh-multihop-transport`.** It was
    the last member without the namespace prefix, while its sibling custom
    transport `habilis-network-iroh-webrtc-transport` — equally iroh-generic, equally
    `publish = false` — has carried it since it arrived in change 19. The prefix
    marks who maintains a crate, not what it depends on, so it says nothing that
    contradicts the invariant from change 20: the crate still has no habilis-network
    dependency, still names only crates.io `iroh`/`iroh-base`, and nothing here
    may leak into it.

    The `[lib]` target moved with the package, so the import path is
    `habilis_network_iroh_multihop_transport`. Keeping the old lib name would have left a
    package and its import path disagreeing for no gain — and would have been the
    one asymmetry with the webrtc transport that the rename exists to remove.

    Changes 13 and 20 are left as written. They record a repository that really
    was named `iroh-multihop-transport`, and the
    [standalone repo](https://github.com/agent-habilis/iroh-multihop-transport)
    they point at still is.

## Fork pins — where each one lives, and why

Three forks are in play: `agent-habilis/{iroh, iroh-gossip, net-tools}`. They do
**not** all live in the same place, and the placement is a rule rather than an
accident.

> **The rule.** `[patch.crates-io]` redirects *someone else's* dependency edge; a
> direct `git` dependency only redirects *your own*. So a fork belongs on a
> dependency edge — where it needs no restating — exactly when **no crate we do
> not control names it from crates.io**. Otherwise it has to be a `[patch]`, and
> a `[patch]` is honoured only in a workspace root and is **not** inherited, so
> every consumer must carry a copy.

The one-line test when adding a fork: `cargo tree -i <crate>`. If everything
listed is ours, it goes on a dependency edge; if a third party appears, it is a
patch.

| fork | lives as | why |
|---|---|---|
| `iroh-gossip` | a **direct git dep** in this workspace's `[workspace.dependencies]` | `habilis-network` is the only crate in the graph that names it, so consumers inherit it and restate nothing |
| `netwatch` + `portmapper` | **git deps inside the `iroh` fork's own `iroh/Cargo.toml`** | `iroh` and `portmapper` both name netwatch from crates.io, so no dep edge *here* could redirect them — but the fork's own edges can. They move as a pair: the fork's `portmapper` takes `netwatch` by path, so splitting them puts two netwatch crates in one graph and the types cross the boundary |
| `iroh`, `iroh-base`, `iroh-dns` | `[patch.crates-io]`, **restated by every consumer** | `iroh-relay`, the mdns/mainline address-lookup crates, `iroh-gossip` and the consumers themselves all name these from crates.io. Nothing we declare can redirect a third party's edge |

So a consumer carries **three** patch lines, not five, and the two that left are
the two it had no business knowing about.

`iroh-base` must stay pinned to the **same repo and rev as `iroh`**: the forked
`iroh` uses its workspace-local copy, and mixing that with the crates.io release
puts two `iroh_base` versions in the graph, which makes types from
iroh-gossip and the address-lookup crates fail to unify (E0308).

Current revs: `iroh`/`iroh-base`/`iroh-dns` →
`agent-habilis/iroh` `0e7cdb4cd73952c49699cd7ae971a1fc2982b866` (mapped_addrs
eviction + relay teardown, **plus** the netwatch/portmapper repoint, **plus**
PR #1: a custom-transport path that is learned while another custom path is
selected is opened too, and a pair selected on IP skips it until it leaves IP, so a `WebRTC`
session that comes up after multihop was selected can be selected over it,
**plus** PR #2: a path open that failed for lack of a free path id is queued
once, not once per connection at every retry; the queue doubled at each 333 ms
retry and took gigabytes in a mesh of 24, **plus** a custom address learned while IP is
selected is queued again when the selected path leaves IP, so a `WebRTC` session that
attached while the pair was on IP can be opened after the IP path is lost, **plus** the `selector-test-utils` feature (a test-only API: public `for_test` constructors and `PathSelection::selected_for_test`, so that a path selector outside iroh can be unit-tested; no change of behaviour). Cost: once a
pair has left IP, its custom path stays open on every connection of the pair, also after IP
returns; each custom address keeps one more path id and its keep-alive while the connections live, **plus** `Endpoint::add_endpoint_addr`, a public call that gives a remote an address without a dial, and a relay that is learned after a connection exists becomes a path of that connection, as the custom address does. Cost: one `Backup` relay path on each client connection of a pair that learns its relay late, with its keep-alive, also while IP is selected. That keep-alive is one PING per idle path per 5 s (`HEARTBEAT_INTERVAL`, `iroh/src/socket.rs:109`, applied as `default_path_keep_alive_interval` in `iroh/src/endpoint/quic.rs:157`), not about one packet per second. Both sides arm it, because the same transport config reaches the client config (`iroh/src/endpoint.rs:1165`) and the server config (`iroh/src/endpoint.rs:1791`), so 2 PINGs per 5 s is the upper bound; each side also resets its timer on an authenticated packet from the other side (noq-proto `connection/mod.rs:3764`, and on send at `connection/packet_builder.rs:305`), so the steady state is about one PING and its ACK per 5 s. Read from the code, not measured on the wire. A relay that moved gets a path of its own (the old one stays until it closes). This makes a learned relay a path; it does not make the relay learned: the caller gives it with `add_endpoint_addr`, **plus** `relay_url` and `ip_addresses` on the `iroh::_events::conn::connecting` event);
`iroh-gossip` → `6178808d02120f186e8b7ebd02caa8522a29c44a` (branch `feat/neighbor-peers`, PR #5 in the fork, not merged: `NeighborPeers`, a low priority request for a link, and a fix for a stuck pending Neighbor request, and a fix for two dials that cross: both sides keep the connection that the lower endpoint id dialed (each side kept the one that the other closed, and both reported the peer down), where a replaced connection and the loser keep reading for 2 s before they close, so that a Neighbor request on them is not lost, the rule holds only for 5 s after a connection became active, and a request made with `RequestNeighbors` stops being pending after 20 s, and a node remembers the peers it answered (`answered_neighbors`), so that one extra Neighbor request, such as the second one that a failed dial leaves, cannot start a ping-pong of Neighbor messages between two nodes (cost: a renew sent for a peer that is already active no longer holds a pending entry, and the first renew after an answered request is read as an answer), and the renew arm of a ForwardJoin, a ForwardJoin for a peer that is already active, goes on with the walk while its ttl lasts, so that the joiner of a swarm of three nodes gets a link to a real peer and not to the contact node only (cost: up to ttl more ForwardJoin hops per join in a dense swarm, and one Neighbor to the joiner from each holder that renews), and an answer to a Neighbor request is forgotten after 20 s, so that a peer that shed its side and asks again is answered and not read as an answer (cost: a second answer to the same peer inside 20 s can be dropped by the first timer), and the drain of a closing connection is timed with n0_future (tokio::time panics in a browser), and a wasm32 clippy row forbids the Tokio calls that panic in a browser (`clippy.toml`, run by the wasm32 job of the CI), and a `Join` from a peer that is already active starts no walk (a joiner re-sends its `Join` every 400 ms while its link is not up, and each copy started a walk; the `Neighbor{High}` lines of a 4-node cell went from 20 to 152), and a new connection that replaces an active one (a re-dial: the peer restarted or lost the link on its side; a crossing, won or lost, is no re-dial) tells the protocol that the link is gone, before the first message of the new connection (cost: a re-dial shows `NeighborDown` and `NeighborUp` to the application, and through `refill_active_from_passive` the contact may send one `Neighbor` request to a passive peer before the `Join` of the re-dialed peer adds it back, and a high priority `Join` evicts a random slot if the view is full by then), on top of `b379de6`, branch `chore/iroh-51e891c`, PR #4 in the fork, not merged: the `iroh` pin above on top of `eca06e4`, branch `leave-peers`, PR #2 in the fork, not merged, with its own `iroh` and `iroh-base` at the rev above: `leave_peers`, a tombstone for a peer that left on purpose, and the TimeBoundCache expiry-heap fix on top of fork main `5d57f94`; the workspace uses `GossipSender::leave_peers` to let go of the rendezvous; two fixes in the gossip actor: it never waits for a full connection queue (`e12580e`), and it splits the overflow rule by message kind, so data is dropped and counted while any other message disconnects the peer (`eca06e4`)); `iroh-mdns-address-lookup` and `iroh-mainline-address-lookup` →
`agent-habilis/iroh-address-lookups` `8a5fb2e9970b6419fa784512252fb353a3675088` (branch `chore/iroh-51e891c`, PR #4 in the fork, not
merged: its `iroh`, `iroh-base` and `iroh-dns` at the rev above, on top of `69c8102`, PR #3); `net-tools` →
`e02960255ef2f5b2ba4aa3d4cf195e0b8673f370`.

## Verifying a change

```
cargo check --workspace            # also: --no-default-features, --all-features
cargo test --workspace             # 19 suites, 411 tests
```

From a host application checkout that links the staticlib, build it against this
repo — the real check that the C ABI is unchanged. The host pins this repo by rev,
so the loop is: edit here, rebuild there, then bump the pinned rev once the change
is pushed.
