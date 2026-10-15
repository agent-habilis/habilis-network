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

Code: `crypto::stretch_mesh_password`, `crypto::password_verifier`, `TicketAuth`, `Mesh::apply_password`.

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
- Do not write two arguments of one type in a row when a swap changes the result. Name them with a small struct: `Leg { src, dst }`, `Contest { own, rival }`, `GraftTarget { peer, rendezvous }`, and `Frame { dst, src, datagram }`.

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
| `Signed` | `habilis-network-protocol/src/message/mod.rs` | The pair of an `AuthorKey` and its signature. A message holds both or neither. |
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
