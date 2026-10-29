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

Code: `protocol::seal_error`.

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
- `missing_copy_implementations` is on by name in `[workspace.lints.rust]`, so a struct whose fields are all `Copy` is `Copy`. Covering gates for the type traits: `missing_debug_implementations` (Debug), `missing_copy_implementations` (Copy), and the derive lints of R2 and R4 below.
- Leaf file names (O9): `scripts/module-layout/module-layout.ts` refuses a leaf file, one that declares no child module, whose public types are not named after the file (`frame_cache.rs` holds `FrameCache`). A leaf whose public types do not match its file name needs a row in `scripts/module-layout/module-layout.allow` with its count and reason. A leaf named after its type needs no row, and a file with no public type is fine.
- Non-leaf files (O11): the same script refuses a `mod.rs` or `lib.rs` that defines an item (struct, enum, trait, fn, impl, const, static, type). Its rows are counted in `module-layout.allow` and go when the items move into leaf files. Up to 20 non-blank lines of definitions are small core glue and are not a hit (O13).
- Constructor names (N10): `scripts/naming/naming.ts` refuses a file with a `fn new_<x>` and no plain `fn new`. Each such file needs a counted row in `scripts/naming/naming.allow` with its reason.
- Conversion names (N12): the same script refuses a file with a `fn from_<x>` and no `impl From<` in it. Each such file needs a counted row in `scripts/naming/naming.allow` with its reason.
- Trait impls (R2, R4): clippy's default `should_implement_trait` and `derivable_impls` run under `-D warnings`, and no site silences either. A method named like a std trait method must implement the trait, and a hand impl that a derive gives must be the derive.
- `scripts/style-check/style-check.ts` checks the rules that no compiler lint covers: the `name:` entries of the file, from `poison` to `abbrev_name` (`anyhow_pub` has its own bullet below). Each rule's `why` text says what it refuses. Each exception is a line in `style-check.allow`, with a count and a reason. A new violation fails the check. An exception whose count is too high fails it too.
- `pub_const_fn` in `scripts/style-check/style-check.ts`: a public `const fn` needs a row in `style-check.allow` that says why it stays const (a const context, a newtype accessor, or a trivial accessor). A new one fails until a reviewer adds the row. The counts may only go down.
- `scripts/style-check/style-check.ts` rule `anyhow_pub`: a public function of a library file returns a typed error, not `anyhow`. It counts each public fn whose return type names `anyhow::Result` or `anyhow::Error` (also through a `use anyhow::Result as X` or a `pub type` alias, and a `pub trait` method), and it skips binaries, CLIs and `bin/` targets. Its exceptions are its rows in `style-check.allow`, each with a reason.
- `scripts/script-language/script-language.ts` refuses a `.sh`, `.bash` or `.py` file, and a file with a shell or Python shebang. See the Scripts section.
- `typecheck:scripts` in `package.json` runs `tsc --noEmit -p tsconfig.scripts.json`. The `typecheck` script runs it too.
- No glob import, with no exemption: not `use super::*` in a test module, not a `pub use ...::*` facade, not a third-party prelude. The `glob` rule of `scripts/style-check/style-check.ts` refuses every `::*` import (0 left on 2026-10-28, so it has no rows in `style-check.allow`). `warn-on-all-wildcard-imports` in `clippy.toml` stays as a second check. Do not define a prelude of our own.
- `clippy::doc_paragraphs_missing_punctuation` is on by name: a doc paragraph must end with punctuation. It had 0 hits when it was turned on (2026-10-28). Capital letters at the start of a sentence are not checked by any tool.
- `clippy::clone_on_ref_ptr` and `clippy::redundant_clone` are on by name: an `Arc` or `Rc` clone is written `Arc::clone(&x)`, and a clone that the code never uses again is refused. about 24 sites in 15 files were fixed when they were turned on (2026-10-28). `implicit_clone` is on through `pedantic`, and `clone_on_copy` is in the default set.
- `clippy::missing_panics_doc` (in `pedantic`, not silenced) refuses a public function that can panic and has no `# Panics` section. A probe fn with `expect` fails with "docs for function which may panic missing `# Panics` section" (2026-10-27).
- `clippy::missing_assert_message` is on by name in `[workspace.lints]`: an `assert!` outside test code needs a message. A probe `assert!(flag)` fails with "assert without any message" (2026-10-27). Clippy does not look at test code, so about 570 message-less `assert!` calls in tests stay.
- No `for` loop header holds a combinator chain: a `git grep` for `for … in … .iter()/.into_iter()/.chars()/.lines()/.split() .method(` finds 0 lines (2026-10-27). The reviewer keeps it that way. (P16)
- Every `unsafe fn` has a `# Safety` section: the 4 in `habilis-network-ffi/src/ffi.rs` each carry one. `unsafe_code` is denied everywhere else, and 6 `expect(unsafe_code)` sites remain. (D4)
- The docs follow the rustdoc rules: the `Doc links` step of `ci.yml` runs `cargo doc --workspace --no-deps --all-features` with `RUSTDOCFLAGS=-D rustdoc::broken_intra_doc_links`. (D10)
- `clippy::doc_markdown` (in `pedantic`) refuses an identifier in a doc comment that has no backticks. `clippy.toml` extends its list of domain terms. It does not check the rest of the Markdown, so the reviewer does. (D11)
- `clippy::new_without_default` (default group, not silenced) refuses a `pub fn new() -> Self` with no `Default` impl. A probe with `-D clippy::new_without_default` fails on the bare type and passes once `impl Default` is added (2026-10-28). A `Default` for a type with public fields is still the reviewer's call. (R17)
- A map key carries `Hash` and `Eq`, and a `BTreeMap` key carries `Ord`: rustc refuses an insert without them. A probe `HashMap` insert of a type with only `PartialEq` fails with exit 1, and the same type with `Eq, Hash` passes (2026-10-28). Every map key of the crates derives both (`git grep` of 17 key types). (R20)
- A type with a float field cannot derive `Ord` or `Eq`: rustc refuses it. A probe with `Ord` derived on `f64` fails with exit 1, and the same type with `PartialOrd` only passes (2026-10-28). Whether a type with a total order should derive `Ord` is for the reviewer. (R19)

- Do not overuse type inference (P1): three gates name the cases the compiler cannot show. `untyped_generic_let` (P4) counts a let that takes its type from parse, into or try_into. `untyped_long_chain_let` (P5) counts a let of a five-call chain with no type. `turbofish_collect_parse` (P2) counts a collect or parse turbofish. A gate over every untyped let would count 9261 lines and separate no correct code from a wrong one, so P1 is not gated on its own.
- U10, `_mut` accessors: the `accessor_name` rule of `scripts/style-check/style-check.ts` refuses a method named `*_mut` that does not return `&mut`. A probe `pub fn x_mut(&mut self) -> &u8` makes the rule count 1 (red), and its removal makes the count 0.
- U11, `take_` methods: the `accessor_name` rule refuses a method named `take_*` that does not take `&mut self`. A probe `pub fn take_x(self) -> u8` makes the rule count 1 (red), and the `&mut self` form counts 0. A free function such as `take_array` is not a method and is not counted.
- U14, `replace_` methods: the `accessor_name` rule refuses a `replace_*` method with no return value. A probe `pub fn replace_x(&mut self, v: u8)` makes the rule count 1 (red), and `-> u8` counts 0.
- N1, method names with a `self` receiver: the `self_convention` rule of `scripts/style-check/style-check.ts` counts a public `as_`/`to_` method that takes self by value and an `into_` method that takes a reference. The guide lets a Copy type take self by value, so the rule skips the impl of a type that derives Copy in the same file, and it has no rows. Clippy's `wrong_self_convention` did not fire in two probes (`as_x(self)` on a non-Copy type, and `into_x(&self)`), so the rule carries the check. Probes: `cargo clippy -p habilis-network-util -- -D warnings` on each.
- Operator overloads (Z14): the `operator` rule of `scripts/style-check/style-check.ts` counts an `Index` or `IndexMut` impl, which hides a lookup that can fail. An arithmetic or logic operator keeps its math meaning by name, so `Add`, `Sub`, `BitOr` and the like have no rows. A probe `impl Index<usize> for Demo` makes the rule count 1 (red), and `impl Add<u8> for Demo` counts 0.
- N7, generic parameter names: the `generic_name` rule of `scripts/style-check/style-check.ts` counts a generic that is not T, U, E, K, V, F, I, R or S and not a CamelCase word of three letters or more. Its 43 hits (A, C, D, H, W, X, O, Q) were renamed to words (Driver, Peer, Decoder, Handle, Writer, Link, Reply, Query, Cmd). A probe `pub struct Wrap<A>` makes the rule count 1 (red), and the renamed form counts 0.
- N13, letter-deleted abbreviations: the `abbrev_name` rule of `scripts/style-check/style-check.ts` counts a declared or used identifier named ctx, addr, conn, msg, buf, opts, prev, req, resp, idx, cfg, tmp, attr, cmd, ident, rng, pos or sig (not in a string, comment, attribute or path). Its rows in `style-check.allow` may only go down. A probe `let ctx = 1;` makes it count 1 (red); `let context = 1;` counts 0. Serde fields keep the old JSON key with `#[serde(rename)]`.

- A public fn is `const` only where a const or static initializer calls it: `pub_const_fn` reads every `const` and `static` line of the crates for the names they call, and flags a `pub const fn` none of them calls (Z7). A newtype or trivial accessor is not exempt by its shape.
### Rules we decline, or leave to the reviewer

- `clippy::absolute_paths`: the owner set `absolute-paths-max-segments = 3` in `clippy.toml`. The lint is on in `[workspace.lints]`. `scripts/absolute-paths/` rewrote the hits to import the parent module.
- `non_exhaustive_omitted_patterns` is an unstable rustc lint. The project toolchain is a nightly. The `Omitted patterns` step in `.github/workflows/ci.yml` runs it with `-Zcrate-attr=feature(non_exhaustive_omitted_patterns_lint)` and `-D non_exhaustive_omitted_patterns`. The step checks three things: the workspace, `habilis-network-bench-wasm` on wasm32, and the `idb_browser`, `origin` and `conformance` tests of `habilis-network-chunks` on wasm32. A crate root gated by `target_arch` drops the crate attribute, so the wasm32 crates are checked on their own. Their test and bench bodies sit in modules for that reason. The step does not check the `wasm_runtime` test on wasm32, because `mio` does not build for wasm32.
- `exhaustive_enums` and `exhaustive_structs`: the owner decided to mark public types `#[non_exhaustive]`. All public enums are marked. A public struct is marked too, except one that keeps a private field (`AppClass`). A struct that other crates build gets `new` with all fields (up to four, no two adjacent of one type), or `new` with the required fields and a `with_` method for each optional field that a call site sets. Never set a field after `Default`, because `field_reassign_with_default` refuses it.
- A `match` on a foreign `#[non_exhaustive]` enum names every variant and keeps a wildcard arm last. The compiler needs that arm and `wildcard_enum_match_arm` refuses it, so the arm carries `#[expect(clippy::wildcard_enum_match_arm, reason = "...")]` on the narrowest scope. Use `expect`, never `allow`: a stale `expect` is a warning.
- Errors in public signatures: a library crate returns a typed error from each public function. The gate is `anyhow_pub` in `scripts/style-check/style-check.ts` (see What each gate refuses). The exceptions are the `anyhow_pub` rows of `style-check.allow`, and nothing else: the webrtc bench harness (`bench.rs`, behind the `bench` feature), and the test relay helper `spawn_plain` (`lookup/test_relay.rs`, behind `iroh-test-utils`). Binaries, CLIs and `bin/` targets are outside the rule and keep `anyhow`.
- `Arc`: the reviewer judges each use, and no gate checks it. Use `Arc` to share across tasks or threads, or for a trait object, and write the reason when it is not clear.
- `From<&str>` that can panic: a type that validates its input has `try_new` returning a `Result`, and no `From<&str>`. `AppTag` and `CorrId` follow this, and a `compile_fail` doc test pins it.
- Returning `Vec<T>` from a public function: the `pub_vec_return` rule of `style-check.ts` counts each public fn that returns a Vec of values where an iterator fits. A `Vec<u8>` is a byte buffer and is not counted, so `to_bytes`, `seal_symmetric` and their kin need no row. An owned collection of values that the caller keeps has a counted row with its reason. The counts may only go down.
- Taking a `Vec<T>` or `impl Into<T>` in a public function: the `pub_vec_param` and `pub_impl_into` rules of `style-check.ts` count them. A public function that only iterates takes `impl IntoIterator`. One that stores or sorts the vector takes a `Vec`, and its row says so. The counts may only go down.
- `as_`, `to_`, `into_` names: the `self_convention` rule of `style-check.ts` (N1, above) counts them. It skips the impl of a type that derives Copy in the same file, and it has no rows. `clippy::wrong_self_convention` is on by default and nothing in the repository silences it.
- Taking a `Vec<T>` in a public function: the `pub_vec_param` rule of `style-check.ts` counts a `Vec` parameter that the body only borrows to iterate (`name.iter()`, `for x in &name`). Such a function takes `impl IntoIterator`. A `Vec` that the body stores, mutates or moves on (a by-value loop, `into_iter`) keeps the `Vec` type, and the rule does not count it.
- Taking `impl Into<T>` in a public function: the `pub_impl_into` rule of `style-check.ts` counts each one, and none is allowed. A library fn takes `&str` and copies it with `to_owned` when the body stores it, or takes the owned type. The counts may only go down.
- `as_`, `to_`, `into_` names: the `self_convention` rule of `style-check.ts` (N1, above) counts them. Its rows are Copy types. `clippy::wrong_self_convention` is on by default and nothing in the repository silences it.
- `&String` in a trait impl: a method of a trait takes `&T::Address`, so an impl with `type Address = String` must take `&String`. `ptr_arg` does not fire on trait impls, and `cargo clippy -p habilis-network-netplay --tests -- -D warnings` is clean. The one such site is `Wire::send_to` in `habilis-network-netplay/tests/peers.rs`.
- Doc examples: the `crate_example` rule of `style-check.ts` (D2) counts each library crate without a doc example (a fenced code block in a `///` or `//!` comment). Such a crate needs a row with its reason. A `compile_fail` doc test pins each illegal typestate transition (see Typestate). The reviewer asks for an example on a new public item whose use is not clear from the signature. (D2)
- A doc comment that explains the basics of the language: the `doc_basics` rule of `style-check.ts` (D6) refuses the phrases that give it away. The reviewer removes the rest. A doc comment that only restates the item name is the `restating_doc` rule (D7).
- A comment says something the code does not: no gate covers it. The reviewer asks for a rename or an extraction where a comment would only say what the code does. (D7)
- Type inference: the rules P2, P4 and P5 below cover the three common cases. In any other case the reviewer asks for a type on a variable when the right side does not show it. (P1)
- Turbofish: the `turbofish_collect_parse` rule of `style-check.ts` (P2) counts a `collect` or `parse` turbofish. Clippy has no lint that asks for a typed variable instead. The reviewer asks for the type on the variable, and accepts `_` where the compiler forces a turbofish. (P2)
- Generic-return calls: the `untyped_generic_let` rule of `style-check.ts` (P4) counts a let that takes its type from `parse`, `into` or `try_into`. The compiler already demands a type where it cannot infer one. The reviewer checks that the target type is visible where the rule does not reach. (P4)
- The result of a five-call iterator chain: the `untyped_long_chain_let` rule of `style-check.ts` (P5) counts a let of such a chain with no type. The reviewer asks for a typed variable when a chain ends in `collect`, `sum` or `parse` and the type is not clear. (P5)
- Context strings on `assert!`: `missing_assert_message` makes one required outside test code. Whether the string helps (a logged value, misuse versus bug) is for the reviewer. (P13)
- An assertion message that only repeats the condition: the `assert_repeats_condition` rule of `style-check.ts` (P14) counts it. The reviewer asks for a message that adds the value or the reason.
- Long or complex iterator chains: the `long_chain` rule of `style-check.ts` (P15) counts a statement with five or more calls in one chain. The reviewer asks for a `for` loop or a named step when a chain is short by that count but still hard to read. (P15)
- Macros (M3): no gate. The reviewer checks each new `macro_rules!`, and `AGENTS.md` allows only `string_newtype!` for a newtype. Eight `macro_rules!` sites on 2026-10-28, all in `git grep "macro_rules!"`: `digest_newtype` (chunks), `for_each_case` and two `run` (chunks conformance), `warn_refusal` (doc), `string_newtype` and `check` (protocol), `cells` (network send ladder matrix test).
- `From<&str>` that can panic: a type that validates its input has `new` returning a `Result`, and no `From<&str>`. `AppTag` and `CorrId` follow this, and a `compile_fail` doc test pins it.
- Macros (M3): `scripts/macro-rules/macro-rules.ts` refuses a `macro_rules!` or a proc macro that `scripts/macro-rules/macro-rules.allow` does not name, and a count that differs from its row. The rows are `string_newtype!` (AGENTS.md allows it for a newtype), `for_each_case` and two `run` callbacks (one `#[test]` per case per backend), `cells!` (one `#[test]` per matrix cell), and the test-only proc macro `habilis-network-test-tracing-macros` (the `test` attribute that fails a test on a WARN or ERROR).
- Macro order for an API (M1): a fn, a generic or a trait comes before a macro. The gate above holds the count, and no row is an API.
- Traits (R7): `scripts/pub-trait/pub-trait.ts` refuses a `pub trait` that `scripts/pub-trait/pub-trait.allow` does not name with its exact count and a reason: a generic bound, a dyn object, a sealed trait or an extension trait.
- When to add an impl (R1): judgment only, because no gate can know which impls a future caller needs. Proxies tried: the derive lints of R2 and R4, `missing_debug_implementations`, `missing_copy_implementations`, and the Clone, Copy, Eq, Ord and Hash gates of the other branches. Red probe, 2026-10-28: a scratch crate with a hand `Default` and a `from_str(&str)` fires `derivable_impls` and `should_implement_trait` under `-D warnings`.
- Cost of a macro (M2): each row states its reason, so the cost of a macro is read in review. The proc macro sits on the test path only.

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
| `InjectedEndpoint` | `habilis-network/src/daemon/setup/injected_endpoint.rs` | An endpoint that `InjectedEndpoint::bind` binds. `bind` checks the keys of the handles before it binds, and makes the admission table the hook reports to. The fields are private, so no other path builds one. |
| `PendingOffer` / `PendingAnswer` | `habilis-network-iroh-webrtc-transport/src/native/jsep.rs` (and `web/jsep.rs`) | A JSEP offer or answer that waits for the remote side. `complete` consumes it. |
| `NegotiatedSession` | `habilis-network-iroh-webrtc-transport/src/native/driver.rs` | A data channel that is open and ready to carry datagrams. Only the `complete` of a pending offer or answer produces one. |

The test-only fixture doors are `Verified::fixture_unchecked`, `Verified::fixture_with_signature`, `WireFrame::fixture_raw` and `Frame::fixture` (in the transport crate). Each one is behind `test-fixtures`: it exists in unit tests and in any build that enables `test-fixtures`, so a release binary must not enable that feature.
