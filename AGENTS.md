# AGENTS.md — Guide for AI agents

habilis-network is a serverless gossip-network engine. It moves, signs, routes, and heals bytes between peers. It does not know what the bytes mean.

This file guides work on the code. The README of each crate describes what that crate does. `docs/architecture.md` describes the whole system.

## Concept Glossary

One concept has one word. Each layer of the code owns some words and never lends them to another layer. Keep the words apart when you read or change code.

### endpoint / link

Layer: transport. Keyed by node id.

An iroh `EndpointId`, and the gossip neighbor link to it. The node id is plumbing. An operator or an agent never sees it.

State: `linked_endpoints` in `daemon/state.rs`.

### peer

Layer: membership. Keyed by nickname.

A member of the mesh other than yourself. The roster is the set of peers. The live count includes you, so it is `peers.len() + 1`.

State: `peers`. Code: `lifecycle/membership.rs`.

### mesh

Layer: identity. Keyed by seed.

A mesh is a `Mesh` value: a seed, a name, and a config. The mesh id is its Base58Check text. The config is mixed into the gossip topic, so every member shares it.

Code: `protocol::mesh` (`Mesh`, `MeshId`, `MeshConfig`).

### topic mesh

Layer: identity. Keyed by seed.

A mesh whose seed is derived from a string, not minted at random. The string alone fixes the mesh, so every peer that uses the same string meets.

Code: `crypto::topic_seed`, `Mesh::from_topic`.

### password

Layer: identity. Optional, per mesh or per ticket.

A password adds a knowledge factor to the bearer secret. For a mesh, the password is stretched with Argon2id into a `SymmetricKey` that replaces the seed in every derivation. The mesh id carries a one-way verifier of that key, so `join` checks a password before any network call. For a ticket, the consumer presents the stretch of the password in place of the raw secret.

Code: `crypto::stretch_mesh_password`, `crypto::password_verifier`, `TicketAuth`, `LockedMesh::unlock`.

### invite

Layer: identity. Optional, per mesh.

An invite-only mesh keeps its derivation secret out of the mesh id. A bare id reaches nothing. Joining needs an invite that the creator minted. The invite carries the root key, an expiry, and the creator's signature. Only the creating session holds the issuer key, so only that session mints invites.

Code: `invite::mint`, `InviteTicket`, `Mesh::set_invite`.

### rendezvous

Layer: identity. Keyed by seed.

The bootstrap identity that every joiner computes from the mesh: an endpoint keypair and a ladder of ports. No peer address is stored. The rendezvous is computed again each time.

Code: `protocol::crypto`, `Mesh::rendezvous_id`.

### beacon

Layer: role.

The live member that binds and serves the rendezvous endpoint. The rendezvous is the identity. The beacon is the role of a member that serves it. The role moves to another member when the holder dies.

Code: `habilis-network/src/beacon`.

### lookup

Layer: lookup.

A way to resolve the rendezvous id into a reachable address: mDNS on the LAN, the mainline DHT, or a relay. Each lookup is complete on its own. The others add reliability and are never a dependency.

Code: `habilis-network/src/lookup`.

### ladder

Layer: transport.

An ordered set of rendezvous rungs that every member computes in the same order. A beacon takes the first rung it can claim. There is a loopback-port ladder for private meshes and a relay ladder for public ones.

Code: `crypto::rendezvous_ports`, `RelayLadder`.

### identity key

Layer: identity. Keyed by public key.

The Ed25519 key that a process makes when it creates or joins a mesh. The public key is the identity of an author. The nickname is a display label and no claim. Every message is signed with this key, and a receiver verifies it.

Code: `protocol::identity`, `AuthorKey`.

### surfaced

Layer: presentation. Keyed by nickname.

A peer whose arrival was shown to the operator or the agent. `surfaced` is a subset of `peers`. It gates what is shown. The roster stays complete for anti-entropy.

State: `surfaced`.

### quiet

Layer: heartbeat. Keyed by nickname.

A peer that went silent past `ALIVE_TIMEOUT`. A quiet peer can still return.

State: `quiet`. Code: `lifecycle/heartbeat.rs`.

### directory

Layer: discovery. Keyed by directory name.

A named, well-known mesh that other meshes advertise their ids into. A directory is itself a mesh, with its own rendezvous, reached through the lookups.

Code: `protocol::directory`.

### shard

Layer: protocol. A header on a message.

One slice of a body that is too large for one gossip message. Each shard is a signed message. The receiver puts the shards back together, and only the whole message is surfaced.

Code: `protocol::message::shard`, `protocol::reassembly`.

### seal

Layer: protocol. A property of a message body.

The encryption of a body. A directed frame is sealed to the x25519 public key of the addressee. On a passworded mesh, state, meta, and broadcast bodies are sealed with a `SymmetricKey` that every member holds. Encryption comes before signing, so the signature covers the ciphertext.

Code: `protocol::seal`.

### blob

Layer: blob transport. A direct QUIC channel beside gossip.

A large file that travels outside gossip. The producer serves the bytes from a spool by SHA-256 hash. A ticket carries the address, a bearer secret, the hash, and the size. The consumer checks the hash while it receives the bytes.

Code: `habilis-network/src/blob`.

### shared state

Layer: state. Two channels per mesh: `state` and `meta`.

A JSON document that the whole mesh shares. It is an automerge replica on each member. Members exchange signed changes. The same set of changes gives the same document on every member.

Code: `habilis-network-doc`, `protocol::Channel`.

## Layering

Keep three layers apart. The rendezvous and the beacon bootstrap a mesh that you already hold. A directory finds meshes that you do not hold. A directory is itself a mesh, and it is reached through the lookups.

## Invariants

### Join horizon

A message is surfaced if and only if its timestamp is not before `joined_at`. One cutoff is computed once, in `lifecycle::observe`, and it applies to every surfaced event. A node still relays and logs older traffic for anti-entropy. It never shows it.

### Lifecycle is one vocabulary

Arrival and departure are surfaced once each, as `joined` and `left`, keyed by nickname. The heartbeat adds `peer_timeout` and `peer_return`. All of them obey the join horizon. A raw link to a node id is not peer lifecycle, so it has no event of its own.

### Lookups are independently sufficient

Each lookup bootstraps a mesh and runs it with no other lookup present. An added lookup adds reliability and never a feature.

## Logging

Developer logs use `tracing`. Message bodies are redacted by default.

Write `target: "habilis_network::<subsystem>"` on every new `tracing` call in the engine. The subsystems that carry a pin are `gossip`, `lookup`, `beacon`, `lifecycle`, `directory`, and `messages`.

`habilis_network_logging::log_filter` pins those targets to `info`. A release build has a base level of `error`. A line with an unpinned target works in a debug build and is dropped from a release build.

The `transport` target has no pin. Its lines appear only when `RUST_LOG` names them.

## Rust style

The Google Rust Style Guide is the reference for Rust style in this repository: https://google.github.io/styleguide/rustguide.html

This file wins over the guide. If the two conflict, follow this file. Issue #29 records each decision.

### What each gate refuses

- `cargo fmt --check` runs in CI. It refuses unformatted code. `rustfmt.toml` sets `imports_granularity = "Module"`, which only a nightly `rustfmt` enforces. `rust-toolchain.toml` pins one toolchain for the whole project, for build, lint and format: `nightly-2026-06-05`. To move the date, rerun the clippy rows of `ci.yml` on both dates first and make it a named commit.
- `cargo clippy` runs in CI with `-D warnings`. Its lints come from `[workspace.lints]` in `Cargo.toml` and from `clippy.toml`. The `pedantic` group is on. These lints are on by name: `unwrap_used`, `wildcard_enum_match_arm`, `await_holding_lock`, `allow_attributes`, `string_add`, `undocumented_unsafe_blocks`, `excessive_nesting`, `shadow_unrelated`, `min_ident_chars` and `semicolon_inside_block`. The rustc lint `missing_docs` and the clippy lints `exhaustive_enums` and `exhaustive_structs` are on by name too, so an undocumented public item, or a public enum or struct that is not `#[non_exhaustive]`, fails the gate. The rustc lints `unsafe_code` and `non_ascii_idents` are denied. The `pedantic` lint `must_use_candidate` refuses a public fn that returns a value without `#[must_use]`; its three `#[expect]` sites in `habilis-network-iroh-multihop-transport/src/lib.rs` each give a reason. `Result` is `#[must_use]` in std, so an error is never ignored by accident, and `double_must_use` refuses a second attribute on it.
- `scripts/style-check/style-check.ts` checks seven rules that no compiler lint covers: `poison`, `feature`, `catch_unwind`, `ctor`, `block_doc`, `lifetime` and `anyhow_pub` (its own bullet below). Each exception is a line in `style-check.allow`, with a count and a reason. A new violation fails the check. An exception whose count is too high fails it too.
- `scripts/style-check/style-check.ts` rule `anyhow_pub`: a public function of a library file returns a typed error, not `anyhow`. It counts each public fn whose return type names `anyhow::Result` or `anyhow::Error` (also through a `use anyhow::Result as X` or a `pub type` alias, and a `pub trait` method), and it skips binaries, CLIs and `bin/` targets. Its exceptions are its rows in `style-check.allow`, each with a reason.
- `scripts/script-language/script-language.ts` refuses a `.sh`, `.bash` or `.py` file, and a file with a shell or Python shebang. See the Scripts section.
- `typecheck:scripts` in `package.json` runs `tsc --noEmit -p tsconfig.scripts.json`. The `typecheck` script runs it too.
- `clippy::missing_panics_doc` (in `pedantic`, not silenced) refuses a public function that can panic and has no `# Panics` section. A probe fn with `expect` fails with "docs for function which may panic missing `# Panics` section" (2026-10-27).
- `clippy::missing_assert_message` is on by name in `[workspace.lints]`: an `assert!` outside test code needs a message. A probe `assert!(flag)` fails with "assert without any message" (2026-10-27). Clippy does not look at test code, so about 570 message-less `assert!` calls in tests stay.

### Rules we decline, or leave to the reviewer

- Module names after the primary item: a scan flags 98 of the 156 leaf files that declare a public type. The scan takes the first public type in each file, so it is too noisy to enforce. The reviewer checks it.
- Glob imports are not allowed. `warn-on-all-wildcard-imports` in `clippy.toml` makes clippy refuse them. Clippy exempts `pub use ...::*` facades and `use super::*` in a test module. Do not define a prelude of our own.
- `clippy::absolute_paths`: the owner set `absolute-paths-max-segments = 3` in `clippy.toml`. The lint is on in `[workspace.lints]`. `scripts/absolute-paths/` rewrote the hits to import the parent module.
- `non_exhaustive_omitted_patterns` is an unstable rustc lint. The project toolchain is a nightly. The `Omitted patterns` step in `.github/workflows/ci.yml` runs it with `-Zcrate-attr=feature(non_exhaustive_omitted_patterns_lint)` and `-D non_exhaustive_omitted_patterns`. The step checks three things: the workspace, `habilis-network-bench-wasm` on wasm32, and the `idb_browser`, `origin` and `conformance` tests of `habilis-network-chunks` on wasm32. A crate root gated by `target_arch` drops the crate attribute, so the wasm32 crates are checked on their own. Their test and bench bodies sit in modules for that reason. The step does not check the `wasm_runtime` test on wasm32, because `mio` does not build for wasm32.
- `exhaustive_enums` and `exhaustive_structs`: the owner decided to mark public types `#[non_exhaustive]`. All public enums are marked. A public struct is marked too, except one that keeps a private field (`AppClass`). A struct that other crates build gets `new` with all fields (up to four, no two adjacent of one type), or `new` with the required fields and a `with_` method for each optional field that a call site sets. Never set a field after `Default`, because `field_reassign_with_default` refuses it.
- A `match` on a foreign `#[non_exhaustive]` enum names every variant and keeps a wildcard arm last. The compiler needs that arm and `wildcard_enum_match_arm` refuses it, so the arm carries `#[expect(clippy::wildcard_enum_match_arm, reason = "...")]` on the narrowest scope. Use `expect`, never `allow`: a stale `expect` is a warning.
- Errors in public signatures: a library crate returns a typed error from each public function. The gate is `anyhow_pub` in `scripts/style-check/style-check.ts` (see What each gate refuses). The exceptions are the `anyhow_pub` rows of `style-check.allow`, and nothing else: the webrtc bench harness (`bench.rs`, behind the `bench` feature), and the test relay helper `spawn_plain` (`lookup/mod.rs`, behind `iroh-test-utils`). Binaries, CLIs and `bin/` targets are outside the rule and keep `anyhow`.
- `Arc`: the reviewer judges each use, and no gate checks it. Use `Arc` to share across tasks or threads, or for a trait object, and write the reason when it is not clear.
- `From<&str>` that can panic: a type that validates its input has `new` returning a `Result`, and no `From<&str>`. `AppTag` and `CorrId` follow this, and a `compile_fail` doc test pins it.
- Returning `Vec<T>` from a public function: the reviewer checks it. A scan of 2026-10-27 (`git grep -nE "pub (async )?fn [a-z_0-9]+.*-> Vec<"`) finds 31 such functions. Most return an owned collection that the caller keeps (`heads`, `snapshot`, `to_bytes`, `canonical_bytes`), which the guide allows.
- `as_`, `to_`, `into_` names: `clippy::wrong_self_convention` is on by default and nothing in the repository silences it (`git grep wrong_self_convention` finds no line on 2026-10-27).
- `&String` in a trait impl: a method of a trait takes `&T::Address`, so an impl with `type Address = String` must take `&String`. `ptr_arg` does not fire on trait impls, and `cargo clippy -p habilis-network-netplay --tests -- -D warnings` is clean. The one such site is `Wire::send_to` in `habilis-network-netplay/tests/peers.rs`.

### Rules of the guide that do not apply

- A rule that the guide tags for Chromium, Android or Fuchsia does not apply. This repository is none of them.
- The guide names a closure accessor `with_foo`. This repository also uses `with_foo` for a builder method that returns `Self`, for example `EndpointAddr::with_ip_addr` of iroh. Keep the builder meaning.

### Rules still under audit

- Everything else follows the guide until issue #29 records a decision.

## Scripts

Write every script in TypeScript, and run it with Bun (`bun scripts/<name>.ts`). CI fails on any `.sh`, `.bash` or `.py` file, or a shell or Python shebang file, unless `scripts/script-language/script-language.allow` names it with a reason. Do not write a new shell script or Python script. A test for a script is a `bun test` file next to it. A script in another language is a fault to port, not a model to copy.

## Newtypes

A newtype is a struct with one field that gives a primitive a domain meaning. This section holds the rules for newtypes on this branch.

### When to write one

- Write a newtype when a primitive carries a domain meaning and a second value of the same primitive type can be in scope at the same place.
- If a crate already has a type for the value, use that type. Examples are `iroh_base::Signature` and `x25519_dalek::PublicKey`.
- Do not write a newtype for raw input at an edge. Parse the input into a newtype at the entry.
- Give one value one type and one name.

### How to write one

- Write the type by hand in the shape of `TopicId`. Do not use a macro, except the existing `string_newtype!` for validated strings.
- Make the field private.
- Give the type a `const fn from_bytes` or a `const fn new`, where the field allows it. A `SymmetricKey`, a `TicketSecret`, and a `StreamSecret` cannot be const, because each holds a `Zeroizing` value. Their `from_bytes` and `as_bytes` are not `const fn`.
- Mark each getter `#[must_use]`.
- Add no dependency for a newtype.

### Secrets

- Give a secret type a hand-written `Debug` that prints no byte.
- Do not derive `PartialEq` or `Eq` for a secret type.
- Compare two secrets with `ct_eq` on `as_bytes`.
- Make a secret type wipe its bytes on drop.
- Hold a raw secret buffer in `Zeroizing` from its creation. A buffer that is wiped by hand leaks on an early return.
- Move a secret that is already in `Zeroizing` into its type with `from_zeroizing`. Never copy it through a plain array. Use `from_bytes` only for raw input at an edge. The wipe is best-effort: `from_zeroizing` removes the copies that we write, and a move can still leave bytes on the stack.

### Roles and argument pairs

- Give each role of an id its own type when one node holds two ids of one primitive type. In the multihop transport, `AppId` is the endpoint that the topology and the routes name, and `UnderlayId` is the endpoint that carries the cells and that a forwarder dials. A swap of the two is a compile error.
- Keep the raw `EndpointId` where it is the id of the iroh layer: `linked_endpoints`, `peer_endpoints`, `path_kinds`, and `route_dialed`. Wrap it with `AppId::new` or `UnderlayId::new` at the call into the multihop transport.
- Do not write two arguments of one type in a row when a swap changes the result. Name them with a small struct: `Leg { src, dst }`, `Contest { own, rival }`, `GraftTarget { peer, rendezvous }`, `RivalFlag { proven, held }`, and `Frame { dst, src, datagram }`.

### Options and sentinels

- Key a map by the author with `AuthorKey`. Use `Option<AuthorKey>` only where a fixture can push an unsigned message. Write the reason beside it.
- Keep a sentinel inside the type that owns it. Examples are `Frame::NULL` and `LinkMetric::INFINITE`.
- At a wire edge or an API edge, turn a sentinel into `Option`.
- Make `Deserialize` and `Serialize` refuse a value that is not a real value of the type. A negative `Frame` is a parse error.

### Time spans

- A time span is a `std::time::Duration`. Never write a `u64` with a unit suffix such as `_secs` or `_ms`.
- Write a `const` span with `from_secs`, `from_millis`, `from_mins`, or `from_hours`. Use the largest unit that is exact.
- Do the arithmetic of a `const` span with `saturating_mul` and `saturating_add`.
- Convert a span to `u64` only at a wire edge, a `UnixSecs` edge, or a log edge.
- A tracing field keeps its name and its unit. A `*_secs` field gets `as_secs()`. A `*_ms` field gets `clock::millis_saturating()`.

### Wire format

- Make a newtype serialize as the value it wraps, with `#[serde(transparent)]` or by hand, so the bytes do not change.
- Treat a wire change as a named decision. Name it in the commit message and in `CHANGELOG.md`.
- Pin each wire form with a golden test. When a golden changes, keep the old literal in a second test that asserts the parse error.

### Where a bare primitive stays

| Place | Reason |
|---|---|
| `Opts` strings, FFI structs, and wasm structs | They hold raw input from JS and C. The code parses them into newtypes at entry. |
| Event and JSON output structs | They hold text for output, not values for logic. |
| The `[u8; 32]` decode in the transport crates | `EndpointId` exists. The decode makes one at the edge. |
| `Shard { idx, total }` | It is a struct with named fields. |
| The pair `(usize, usize)` of `Sync::new` and `P2PSession::new` | Each argument has its own name and its own role, and `PlayerHandle` covers the one that names a player. |
| `unix_nanos` in `habilis-network-util` | It has one caller. |
| `ContentId::new` | It is a newtype already. A new validation rule can reject ids that exist. |
| `util::logs::log_file_path(mesh_id: &str, nickname: &str)` | The util crate is below the protocol crate, so it cannot name `MeshId`. |
| The browser milliseconds in `habilis-network-iroh-webrtc-transport`: `DISCONNECT_GRACE_MS` in `liveness.rs`, and `CHANNEL_OPEN_DEADLINE_MS`, `ICE_GATHERING_DEADLINE_MS`, `ICE_QUIET_MS`, and `POLL_MS` in `web/jsep.rs` | The browser clock gives `f64` milliseconds, and the browser `sleep_ms` takes an `i32`. |
| `timeout_ms: c_int` in `habilis-network-ffi/src/ffi.rs` | It is a C edge. The code converts it into a `Duration` at entry. |
| The hidden `--*-secs` and `--*-ms` flags of agent-gossip (`cli/args/tuning.rs`) | They hold CLI input as `u64`. The CLI converts each value into a `Duration` where it builds `Tuning`. |

### Types that exist

| Type | File | Holds |
|---|---|---|
| `TopicId` | `habilis-network-protocol/src/topic.rs` | The 32 bytes of a gossip topic. |
| `MeshId`, `MeshName`, `MessageId`, `MessageBody`, `Nickname` | `habilis-network-protocol/src` (`mesh/id.rs`, `mesh/name.rs`, `message/id.rs`, `message/body.rs`, `nickname.rs`) | Validated strings. |
| `Password` | `habilis-network-protocol/src/crypto.rs` | An operator password, redacted. |
| `Seed` | `habilis-network-protocol/src/crypto.rs` | The wire seed of a mesh id and the salts of derivations. |
| `SymmetricKey` | `habilis-network-protocol/src/crypto.rs` | A key that encrypts, wraps, or derives. Wiped on drop. |
| `TicketSecret` | `habilis-network-protocol/src/crypto.rs` | The bearer secret of a ticket, and the token that a consumer presents. Wiped on drop. |
| `DedupKey` | `habilis-network-protocol/src/dedup_key.rs` | The 16-byte dedup and anti-entropy key of a message. |
| `AuthorKey` | `habilis-network-protocol/src/author_key.rs` | The public key of the author of a message. |
| `Signer` | `habilis-network-protocol/src/message/mod.rs` | The pair of an `AuthorKey` and its signature. A message holds both or neither (`Message::signer`). |
| `ContentHash` | `habilis-network-protocol/src/content_hash.rs` | The hash of a message that `prev` and `parents` link to. |
| `BlobDigest` | `habilis-network/src/blob/mod.rs` | The SHA-256 of a blob. |
| `StreamId`, `StreamSecret` | `habilis-network-stream/src/hash.rs` | The public id and the bearer secret of a stream. |
| `PlayerHandle`, `Frame` | `habilis-network-netplay/src/handle.rs`, `frame.rs` | A roster slot and a simulation frame. |
| `Epoch`, `SessionId`, `Tick`, `TickSpan` | `habilis-network-netplay/src/mesh/lobby.rs` | The match number, the match id, and the lobby clock. |
| `LinkMetric` | `habilis-network-iroh-multihop-transport/src/metric.rs` | The cost of a link. |
| `ChunkHash`, `Root` | `habilis-network-chunks/src/lib.rs` | A chunk hash and the root of a chunk tree. |
| `UnixSecs` | `habilis-network-util/src/clock.rs` | A point in time, in whole seconds since the epoch. `Message::timestamp`, `Listing::first_seen_unix`, and the expiry of an invite ticket hold one. A wire struct converts with `as_secs`. |
| `AppId`, `UnderlayId` | `habilis-network-iroh-multihop-transport/src/role.rs` | The application endpoint and the underlay endpoint of a node. |
| `Leg` | `habilis-network-iroh-multihop-transport/src/graph.rs` | The two ends of a route, `src` and `dst`, both `AppId`. |
| `Contest` | `habilis-network/src/beacon/mod.rs` | The two holders of one beacon, `own` and `rival`. |
| `GraftTarget` | `habilis-network/src/transport/probe.rs` | The peer of a graft and the rendezvous it is told apart from. |
| `RivalFlag` | `habilis-network/src/daemon/state.rs` | What a `PeerInfo` says about the rendezvous: `proven` says that the sender proved its endpoint, and `held` says that it carries the beacon flag. |

## Typestate

A typestate is a type per state of a value, where each operation exists only on the type of the state it is legal in. A transition consumes the value and returns the value of the next state, so the compiler rejects an operation in the wrong order. Use it where the order is a rule of the code, not a fact of the network.

### When to use one

- Use it when the state is known at compile time: the caller can name the state it holds.
- Use it when one function drives the whole sequence, from the first state to the last.
- Use it when a wrong order is guarded only by a runtime check or a comment today. Examples are an `ensure!` on the order of setup steps, or a `let Some(key) = … else { return }` fallback.

### How to write one

- Write one type per state, not one type with a state field. A state field brings back the runtime check.
- Make each transition take `self` by value, so the old state cannot be used after it.
- Make every field private. The constructor and the transitions are the only way in.
- Make the constructor the only entry. A struct literal in another module must not compile.
- Do not implement `DerefMut` on a proof type. A `Deref` to the data is fine, because it gives only read access.
- Add a `compile_fail` doc test for each illegal transition, and a passing control next to it, so that the test fails for the reason it names.

### Where an enum stays

Runtime events drive these transitions, so their state is not known at compile time.

| Place | Reason |
|---|---|
| `SessionState` (`habilis-network-netplay/src/session.rs`), `PeerState` (`habilis-network-netplay/src/protocol.rs`), `DirectState` (`habilis-network/src/daemon/state.rs`), `ConnectionPhase` (`habilis-network-iroh-webrtc-transport/src/liveness.rs`) | Network events, probes and timers drive their transitions, so the state is not known at compile time. |

### Typestates that exist

| Type | File | Holds |
|---|---|---|
| `LockedMesh` / `Mesh` | `habilis-network-protocol/src/mesh/mod.rs` | A decoded mesh with no secret. `unlock` turns it into a `Mesh`, or returns an `UnlockError` that says why not. Only `Mesh` derives a topic, a rendezvous or a port, and `Mesh::new` refuses a config that carries a secret. |
| `Verified` / `Authored` | `habilis-network-protocol/src/message/verified.rs` | `Verified` is a message whose signature is checked, with its key. It is what the wire and the log take. `Authored` is a message whose author is proven: a read-only view with no `Serialize` of its own. `Deref` is a read door: `Message` has no public `Serialize`, so `&*authored` does not serialize, and only `Verified::serialize` makes a `WireFrame`, which every sender takes. Both share the message behind an `Arc`. `Proof` is the sealed trait both implement, so the gate and the app surface are generic over either. |
| `WireFrame` | `habilis-network-protocol/src/message/wire.rs` | The bytes of one signed message as they go on a socket. Only `Verified::serialize` makes one, and its field is private, so the senders take a `WireFrame` and cannot be handed an unsigned frame. |
| `InjectedEndpoint` | `habilis-network/src/daemon/setup.rs` | An endpoint that `InjectedEndpoint::bind` binds. `bind` checks the keys of the handles before it binds, and makes the admission table the hook reports to. The fields are private, so no other path builds one. |
| `PendingOffer` / `PendingAnswer` | `habilis-network-iroh-webrtc-transport/src/native/jsep.rs` (and `web/jsep.rs`) | A JSEP offer or answer that waits for the remote side. `complete` consumes it. |
| `NegotiatedSession` | `habilis-network-iroh-webrtc-transport/src/native/driver.rs` | A data channel that is open and ready to carry datagrams. Only the `complete` of a pending offer or answer produces one. |

The test-only fixture doors are `Verified::fixture_unchecked`, `Verified::fixture_with_signature`, `WireFrame::fixture_raw` and `Frame::fixture` (in the transport crate). Each one is behind `test-fixtures`: it exists in unit tests and in any build that enables `test-fixtures`, so a release binary must not enable that feature.
