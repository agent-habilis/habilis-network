# Changelog

All notable changes to the habilis-network workspace. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); all member crates
share one version and move together. A release is a git tag — nothing is
published to a registry; pin it with
`habilis-network = { git = "https://github.com/agent-habilis/habilis-network", tag = "v0.6.0" }`.

## [Unreleased]

### Added

- `EventLoopConfig::with_owner_pid`: a CLI daemon started detached lives for
  an explicit owner process instead of its parent, and quits gracefully once
  the owner exits. The start time captured at startup guards against pid
  reuse, and an unreaped zombie owner counts as gone. The state file carries
  the pid as `owner_pid`, read back as `SessionEntry::owner_pid`.
  `runtime::validate_owner_pid` runs the same checks, for a launcher that
  refuses a bad pid before it re-spawns the daemon.
- Native pairs race WebRTC against UDP on a `udp,webrtc` mesh. A session
  that attaches after UDP won is detached, and the far side drops its half
  at once. A path watcher races the pair again when UDP is lost, and detaches
  the session when UDP returns; while a pair rides WebRTC it nudges iroh each
  alive tick to try the UDP punch again.
- `habilis-network-stream`: 1-1 byte streams addressed by a hash. A producer creates a
  stream and hands its hash to one consumer. The bytes ride a direct QUIC path
  or a WebRTC data channel by default, the relay only when the stream's
  `transport` allows it, never gossip, and the consumer paces the producer.
  A second consumer is refused (`Refused::Taken`), and a producer dropped
  before it closes abandons the stream (`Refused::Abandoned`).
  `close_or_abandon` ends the stream if a consumer has claimed it and
  abandons it otherwise. It builds for wasm32, so a tab can produce as well
  as read.
- The `habilis-network-stream` binary (`crates/habilis-network-stream-cli`): stdin to one
  reader, or a hash's stream to stdout. It prints the hash, and with
  `--web-url` the page URL with the hash in its fragment.
- `packages/habilis-network-stream-web`: the stream's web page, a static build. `#<hash>`
  reads a stream; no fragment produces one. It registers `stream_write`,
  `stream_close`, `stream_read` and `stream_status` as WebMCP tools, with the
  same functions on `window.stream`.
- Byte streams in the C ABI, ten calls: `habilis_network_streams_bind`,
  `habilis_network_streams_bind_for`, `habilis_network_streams_close`, `habilis_network_stream_create`,
  `habilis_network_stream_hash`, `habilis_network_stream_write`, `habilis_network_stream_close`,
  `habilis_network_stream_open`, `habilis_network_stream_read` and `habilis_network_reader_close`, with a
  32-byte `habilis_network_stream_opts` (`encodeStreamOpts` in `packages/habilis-network-ffi`).
- `habilis_network::membership`: the gossip mesh embedding, moved into the engine from
  `habilis-network-pipe`. `join` returns a `Membership` that sends and receives whole
  text messages (`msg`). `MAX_MSG` (1408 bytes) is the worst-case bound;
  `msg_fits` says whether a given text fits.
- `habilis-network-wasm`: the browser peer, with `habilis_network::membership` and the byte
  streams as wasm-bindgen classes, and `packages/habilis-network-wasm` as its JS
  backend (`join` for a mesh, `bindStreams` / `bindStreamsFor` for streams).
  `cargo task build-wasm` builds it.
- A custom relay ladder (`relay_urls` / `relayUrls` / `--relay-url`) on every
  create surface. The ladder is mixed into a derived topic id, so every
  member must pass the same list.
- `habilis_network_protocol::Lookup` and `Transport`, the entries of the `lookup` and
  `transport` lists every create surface takes, with `LookupSet::from_lookups`,
  `TransportPolicy::from_transports` and `MeshConfig::resolve` behind them, so
  a consumer parses the two lists and applies the cross-rules with no code of
  its own.
- `cargo task e2e --suite mesh`, `--suite chat` and `--suite stream`: a real
  native peer and a real browser tab on a local plain-HTTP relay. The mesh
  suite sweeps the relay policy, the native transport set and the join mode;
  the stream suite streams bytes both ways between the binary and the page.
  Behind the `mesh` feature of `tasks`, and local-only for now.

### Changed

- **Breaking:** the project is renamed from fofoca to habilis-network, and it
  moves to `github.com/agent-habilis/habilis-network` (https://habilis.network).
  Every crate, package, C symbol (`habilis_network_*`), C type
  (`HabilisNetwork*`), header (`habilis_network.h`) and environment variable
  (`HABILIS_NETWORK_*`) takes the new name.
- **Breaking (wire):** the ALPNs (`habilis-network/stream/1`), the endpoint-proof
  domain and the chunk-store root context take the new name. A habilis-network
  peer does not interoperate with a fofoca peer, and chunk roots differ from
  those of a fofoca store.
- **Breaking (C ABI):** the mesh calls are `habilis_network_mesh_*`, and a mesh sends
  and receives whole text messages with `habilis_network_msg_send` and
  `habilis_network_msg_recv` into an 80-byte `habilis_network_msg`. A message too big for the
  receive buffer stays queued, and the call returns -2. `habilis_network_open`,
  `habilis_network_send`, `habilis_network_send_eof`, `habilis_network_recv`, `habilis_network_frame` and
  `habilis_network_max_chunk` are gone (`habilis_network_max_msg` replaces the last). C consumers
  must rebuild against the new `include/habilis_network.h`.
- **Breaking:** the browser peer, `habilis-network-api` and the chats send `msg`
  messages over `habilis_network::membership` instead of `habilis-network-pipe`'s numbered
  byte frames. A peer on the old wire cannot read them.
- **Breaking (TS):** `habilis-network-api`'s `Mesh` sends and receives whole text
  messages. `send` takes a `string` only (was `string | Uint8Array`),
  `sendEof` is gone, and `maxChunk` is `maxMsg`. A `Message` is
  `{ from, text, directed }`: `bytes` and `eof` are gone, and `text` is
  always set. The backend seam's `BackendFrame` is `BackendMsg`, and
  `BackendSink.frame` is `BackendSink.msg`.
- **Breaking (C ABI):** `habilis_network_opts` is now 64 bytes: the five discovery
  ints (`is_public`, `mdns`, `dht`, `relay_lookup`, `relay_transport`) are
  replaced by two comma-list strings, `lookup` and `transport`, ahead of
  `relay_urls`. A consumer
  compiled against the old header keeps passing the old struct and the
  engine reads it wrong — there is no version field to catch that, so relink
  against the new `include/habilis_network.h`. The layout is pinned by a compile-time
  assert in `habilis-network-ffi` and by `packages/habilis-network-ffi`'s encoder test.
- **Breaking:** every create surface names three mesh-wide choices apart,
  one concept each. `lookup` (`lookup: ['mdns', 'dht', 'relay']`, any
  subset) is how members find each other. `transport` (`['udp', 'webrtc',
  'relay']`, any subset with `udp` or `webrtc`; `['udp', 'webrtc']` when
  empty) is what payload may ride. `relay_urls` is which relay.
  The `public`, `mdns`, `dht`, `relay_lookup` and `relay_transport` booleans
  are gone; `public: true` is spelled `lookup: ['mdns', 'dht', 'relay']`, and
  naming no lookup is a loopback mesh. A ladder no longer implies the relay
  lookup: both it and `'relay'` in `transport` need `'relay'` in `lookup`,
  and a config that breaks either rule is rejected before any network. A
  list without `'udp'` (a WebRTC-only mesh) needs `'relay'` in `lookup` as
  well, because the relay is the only path its WebRTC offers can take. The
  mesh id decides every path: there are no per-node path switches, and a
  browser refuses a mesh whose list has neither `'webrtc'` nor `'relay'`.
  In the wasm JSON every old field is an error,
  not a silent no-op. `habilis_network_protocol::resolve_lookups` lost its `public`
  parameter. `TransportOpts.relay` keeps its name — it is per-node
  capability, not the mesh policy.
- `MeshConfig::validate` now also rejects a custom relay ladder that would
  not survive the wire (more than 16 rungs, or a URL over 512 bytes). A
  caller-supplied ladder reached the encoder unbounded before: past 255
  rungs it panicked, and between 17 and 255 it minted an id no member could
  decode.
- The chat example lives in `examples/chat/rust` (package `chat`).
- A node without UDP needs the relay: `'relay'` in `lookup`, and a relay
  transport on the node. A browser always has no UDP, so a tab now refuses
  a mesh with no relay lookup at join, and a stream node refuses it at bind.
  A native node meets this rule only when its own paths leave out UDP.

### Fixed

- A stream rides the relay only if both lists allow it. A consumer whose own
  `transport` list left out `'relay'` still streamed over the relay when the
  producer's list allowed it.
- A dial that learned a WebRTC address after iroh had selected the relay
  path stayed on the relay: its Initials went only to the selected path, and
  the custom-transport path was never opened. The pinned iroh fork now fans
  Initials out and opens such paths (fofoca-network/iroh#2, pinned at its
  squash commit `66003af`).
- A beacon holder sheds its rendezvous periodically to re-arbitrate with a
  possible same-id co-host. It now waits, up to three rounds, while a
  data-channel peer depends on that beacon: a browser reaches the mesh
  through the rendezvous and has no second path, so the shed emptied its
  roster mid-transfer.
- A node judged its own need for the `WebRTC` lane from its endpoint address,
  which is empty in a browser whenever the relay link is down; empty read as
  "has IP", so a tab that was the lower id skipped the lane for a native peer
  and stayed relay-only. The pair decision and the rendezvous offer now use
  the node's own transport set (`EventLoopState::local_ip_transport`).
- A negotiated WebRTC session is registered as a transport address, so a
  bare-id dial migrates onto it instead of being refused on the relay.
- An offer from a peer we already hold a session with detaches the old
  session and answers fresh.
- Every `joined` re-floods our `PeerInfo` behind a per-endpoint cooldown, so
  a newcomer or a rejoin across a beacon epoch is not unreachable forever.
- A public rendezvous claim needs two consecutive free probes, so a probe
  inside a live beacon's release window no longer stands up a rival copy.
- A fresh unicast dial waits up to five seconds for a direct path before its
  first frame, which the pool used to refuse as relayed.
- A digest window is bounded by the extent of its slice rather than by its
  first and last entries; the log is in arrival order, so the ends bounded
  nothing and a holder answered "nothing missing" for a gap.
- On a lookup-only mesh the debug census no longer demotes a proven peer on
  a relayed `conn_path` reading, which stopped every payload lane to it.
- A mesh larger than a node's 16 direct-peer slots no longer stalls at the
  rendezvous. A WebRTC-only mesh formed only for its first 16 members: the
  rendezvous pseudo-node held each joiner's session and its gossip link for
  ever, filled its 16 slots, and every later joiner stayed alone with an empty
  roster. A UDP mesh of about 65 hit the same wall at the beacon's 64-place
  gossip view. A node that holds three links to other members now lets go of
  the rendezvous (it closes the connections and detaches the session) and comes
  back only while it has fewer than three links, or once after the sweep removed
  a silent roster peer, which is how islands of a split mesh meet again. The
  node that hosts the beacon keeps its own link, so that a joiner always
  finds a member in the beacon's view. A refusal at the cap now waits 30 s
  before the next offer, not five minutes.
- A gossip connection on a lookup-only mesh whose selected path stays on the
  relay for longer than `PROBE_DEADLINE` after the accept is closed with the
  gossip relay-refused code. The accept gate checked the path only once, so a
  path lost later left a link up on the relay with nothing to say that no
  payload may ride it.

### Removed

- **Breaking:** `habilis-network-pipe`, the byte pipe over gossip. Byte streams are
  `habilis-network-stream`, over a direct path by default; the mesh embedding is
  `habilis_network::membership`. The v0.6.0 tag keeps the crate.
- **Breaking:** the `habilis-network-blobs` crate, and with it the workspace's only
  OPFS store backend. `habilis-network-chunks` is the store: chunks prove content,
  where blobs' bao outboards proved placement. No known consumer imported
  `habilis_network_blobs` at removal time; the v0.6.0 tag keeps the crate.

## [0.6.0] - 2026-08-30

The first tagged release. Everything since the extraction of the engine into its own repo.

### Added

- A WebRTC transport for iroh: QUIC datagrams over one unreliable data
  channel, with a native (str0m) and a browser (`RTCPeerConnection`)
  backend, signalled over the iroh relay with no signaling server
  (`habilis-network-iroh-webrtc-transport`).
- A multihop transport: source-routed QUIC relaying through peers
  (`habilis-network-iroh-multihop-transport`).
- The engine runs in the browser: `--no-default-features` leaves a portable
  core for wasm32, guarded by CI.
- `habilis-network-blobs`: a BLAKE3/bao store of verification metadata for bytes the
  caller already owns, with fs, memory, OPFS, and IndexedDB backends.
- `habilis-network-chunks`: the content-addressed chunk store, moved in from
  agent-share. Chunks prove content; `habilis-network-blobs` outboards prove
  placement. It is meant to replace `habilis-network-blobs` eventually.
- The `blob` feature: a point-to-point side channel for oversize payloads,
  with bearer-secret tickets.
- A C ABI (`habilis-network-ffi`) and one JS API over it for Bun, Deno, and Node
  (`packages/habilis-network-api`, `habilis-network-pipe`).
- `habilis-network-netplay`: GGPO-style rollback netcode for peer-to-peer games, and
  the light-cycles example that proves it in CI.
- The relay transport policy lives in the mesh id: a mesh can declare its
  relay lookup-only, and members prove a direct path before payload flows.

### Changed

- **Breaking:** `MeshConfig` gained a `transport` section, and the default
  relay policy is lookup-only: the relay carries bootstrap, signaling, and
  NAT traversal — no payload. A gossip graft waits for a proven non-relay
  path.
- `blake3` is a workspace dependency with `default-features = false` as the
  floor; crates opt in.

### Fixed

- A browser WebRTC session whose ICE died under an open data channel stayed
  registered forever, blocking every re-dial; the hub now watches
  `connectionState` and evicts (`failed`/`closed` at once, `disconnected`
  after a 10 s grace).
- `swarm-discovery` 0.6.3 span every tokio thread retrying a send to a gone
  mDNS updater; the iroh-address-lookups fork now pins the unreleased
  upstream fix.
- Bounded what a ping, a digest, a blob serve, and the reassembly buffers
  can cost the receive path; bounded the channel orphan buffer; evictions
  come from the fullest author.
- Directed frames no longer reach peers they are not addressed to; documents
  sync over a rendezvous-only link; multihop cells relay only when the route
  names this node.
- Many WebRTC/JSEP hardening fixes: session slots reserved before their
  driver spawns, duplicate sessions refused without killing the survivor,
  STUN replies matched by transaction id, stray datagrams tolerated during
  the handshake, ICE candidates classified by `typ`.

## [0.5.0] - 2026-07-31

The state of the engine at its extraction into its own repo (86bd79d). Provenance and the
recorded fork changes live in [FORKED.md](FORKED.md).

[0.6.0]: https://github.com/agent-habilis/habilis-network/compare/86bd79d...v0.6.0
[0.5.0]: https://github.com/agent-habilis/habilis-network/commit/86bd79d
