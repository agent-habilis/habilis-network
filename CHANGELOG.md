# Changelog

All notable changes to the habilis-network workspace. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); all member crates
share one version and move together. A release is a git tag — nothing is
published to a registry; pin it with
`habilis-network = { git = "https://github.com/agent-habilis/habilis-network", tag = "v0.6.0" }`.

## [Unreleased]

### Added

- `SignalAdmission::connection_hook` and the `ConnectionHook` it returns: an
  endpoint hook that records every connection of the endpoint, on any protocol,
  under its peer in the direct-peer slot table, so that the table can prune the
  slots of closed connections, and that watches the gossip connections the node
  dials for the relay policy.
- `multihop` is an entry of the `transport` list, and the default list is
  `udp,webrtc,multihop`. A peer with no direct path is reached through other
  members. It needs `udp` or `webrtc` next to it in the list, and is native only; a
  browser ignores it, as it ignores `udp`. Multi-hop and `WebRTC` now share one
  endpoint and one key. A link-vector is signed by the peer that advertises it,
  so a node cannot claim another peer's underlay, and only the endpoint that the
  roster binds to the message's author is heard. Its `seq` is the sender's
  wall-clock time in milliseconds: a restart does not lose to the vectors it sent
  before, and a vector older than the max age is refused. A vector that stops
  arriving ages out after three advertisement intervals, `Left` drops a peer's
  vector at once, and a removed peer's highest `seq` is remembered for one max
  age so its last vector cannot return. Link-state is no longer retained in the
  message log: no peer holds it, so a retained copy was asked for again on every
  digest. The underlay endpoint keeps a key of its own, derived from the peer's
  (`underlay_secret`): a relay hands an id's packets to one endpoint only. With
  the relay for lookup alone, the underlay drops a cell unless the connection's
  selected path is not the relay, and a hop that stays on the relay past a
  deadline is not advertised as a link.
- `net::install_transports`: the one wiring of multi-hop, `WebRTC` and the
  connection hook onto an endpoint builder. `InjectedEndpoint` carries the
  `MultihopHandle` and the `SignalAdmission` its endpoint was built with.
  `check_injected_identity` checks the hop identity, refuses a handle that lets
  the relay carry cells on a mesh whose list has no `relay`, and refuses an
  admission table that no hook reports to (`SignalAdmission::is_observed`). A
  handle on a mesh whose list has no `multihop`, or on a node with no UDP, is
  dropped. `net::multihop_handle_config` gives an embedder the engine's handle
  settings.
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
- A ceiling C on the direct connections of a node (default 64): the unicast
  connections and the `WebRTC` sessions together, with a peer counted once. A
  gossip neighbor's session and the gossip links do not count. Nothing is refused
  for it: a newcomer past C evicts the least valuable peer (idle first, the least
  recently used first, a unit younger than 60 s last, one with a send in flight
  never). C is not a hard limit: the count can exceed it for a moment by the
  sends in flight, because a busy unit is never a victim. An evicted connection closes with the code `EVICTED` (11), and its peer
  makes no proactive dial back for about a minute; a send still dials at once. A
  peer whose session was evicted has its offer refused with the same code for that
  minute. One idle backstop of 900 s closes a connection or session that nobody used.
- A lane peer (a browser, or a node without UDP) gets a session when a frame is held
  for it, and loses an unused one at the backstop, instead of keeping it for ever.
  When both ids offer at once, the lower id wins.
- A peer that refuses a graft is left alone for 60 s, then 120 s, up to 15 min
  (with a jitter of 20 percent), so a late node no longer asks the same full peers
  every few seconds. A starved node, one that holds two or more links fewer than the
  active view for five minutes, falls back to a `Join` once per five minutes. The
  engine asks for a link with the low-priority `NeighborPeers` command, so that a
  graft no longer makes a full peer drop a neighbor.
- Every endpoint, the multihop underlay and the blob endpoint included, sets
  generous QUIC windows: 16 MiB for a stream, 16 MiB for a connection and 16 MiB
  to send, so that one blob stream can use the whole window. One connection holds at
  most 32 MiB in the worst case.

### Changed

- A node picks its path by one ladder: a direct IP path, then `WebRTC`, then
  multihop, then the relay, and the lowest RTT inside a rung. Multihop used to
  rank below the relay on a mesh with `WebRTC`, and the order changed with the
  transport list. Both path selectors now take the rank from `Rung` in
  `habilis-network-iroh-transport-util`. A pair that multihop carries is no
  longer "proven direct" for the decision to offer a `WebRTC` session, so it
  still offers one, and the session ranks above multihop. Test hooks:
  `block_rung`, `Request::BlockRung` and `Request::SelectedRung` take a node down
  the ladder one rung at a time. The multihop path stays open as a backup under
  an IP or `WebRTC` path too, so its cost grows with the number of open paths,
  not with the number of pairs on `WebRTC`. Measured on three idle members on one
  host, with one multihop path per pair: 99 cells in 60 s over the whole mesh,
  that is 0.55 cells/s and 42 bytes/s per open path, both directions together
  (0.28 cells/s per direction). 95 of the 99 cells were 30 bytes and 4 were 1200
  bytes. No hop forwarded a cell, because the shortest route was the direct link
  between two underlays. A path routed through a member costs that figure once
  per hop; that is not measured. Gaps: no test routes the multihop rung through
  a member (a hook that cuts the direct underlay link would close it), and when a
  hop of a route leaves, the path does not re-route (a multihop address is one
  fixed route): its cells are dropped at the missing hop, QUIC abandons the path
  at its idle timeout, and the pair falls to the next rung. The order also
  applies when the relay may carry payload: multihop then beats the relay with no
  look at RTT, so a pair that two or three members carry can be slower than it
  was on the relay.
- **Breaking:** the mesh id is version 2. The transport policy is always one
  explicit byte after the lookups: `udp`, `webrtc`, `multihop`, `relay`, one bit
  each. An id of version 1 is refused with a request to upgrade. Every mesh id
  and every golden id changes; create the mesh again.
- **Breaking:** `MultihopHandle::new` takes the peer's `SecretKey` (it signs the
  link-vectors), an underlay bound to `underlay_secret(secret)`, and a
  `HandleConfig` (relay rule, vector max age, relay deadline). `LinkVector::new`
  is `LinkVector::signed`, and `MultihopHandle::link_vector` makes the `seq`.
- **Breaking:** an invite ticket is version 2, because it names a mesh id. A
  version 1 ticket is refused with a request to upgrade.
- **Breaking, steps for the tools that embed the engine** (agent-share,
  agent-gossip). Both must move in the same release as the engine: a member of
  version 1 and a member of version 2 never share a mesh.
  1. An injected endpoint (agent-share) must give the engine its admission table.
     Make a `SignalAdmission`. Build the endpoint with `net::install_transports`
     and handles that carry this table. Pass the table in
     `InjectedEndpoint { endpoint, webrtc, multihop, admission }`: on a host,
     `multihop` is the handle that the endpoint was built with, or `None`. The
     `admission` field is required on every target, so every
     `InjectedEndpoint { .. }` literal must change.
  2. `net::check_injected_identity` has new arguments: the multihop identity, the
     admission table, and whether the mesh list has `relay`. It refuses a table
     that `connection_hook` was never called on.
  3. `TransportHandles` has a new public field, `underlay`. A struct literal must
     name it, or end with `..TransportHandles::default()`.
  4. agent-gossip: multihop is now ON by default. Every native node of a default
     mesh binds a second endpoint (the underlay) with its own relay registration,
     and sends one signed link-state through every member every 15 s, browsers
     included. A mesh that wants the old behaviour is created with
     `transport: udp,webrtc`. Drop the `--multihop` flag, `SetupParams::multihop`
     and `TransportOpts::multihop`.
  5. Every saved mesh id, gossip hash and invite ticket stops working (see the
     entries above): create the mesh again.
- A chat digest is answered by three members, not by all of them, and the event
  loop no longer waits to send the answer. Each member that held a message the
  asker lacked used to broadcast up to 64 messages, and every broadcast reaches
  every link: about N^3 deliveries per round, which filled the queues of the
  gossip actor at about 40 members. A digest id and the member names now pick
  the answerers (`ANTIENTROPY_ANSWERERS`, 3), and they change with each digest,
  so a message that only one member holds still comes back within a few rounds.
  The answer goes into a bounded outbox (`RESEND_OUTBOX_CAP`, 256) that its own
  task drains; what does not fit is dropped, and the next digest asks again. The
  `mesh census` line gains `idle_resent` and `idle_resend_dropped`. A mesh of
  four or fewer is answered by every member, as before. A late joiner in a large
  mesh can need several digest rounds (10 s each) to get the full history,
  where one round was enough.
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
- **Breaking:** the setting `max_sessions` is now `max_direct`, the ceiling C of
  direct connections (default 64, it was the cap of 32 on `WebRTC` sessions). The
  field of the C struct keeps its place (offset 64, 72 bytes), the TS option is
  `maxDirect`, the CLI flag `--max-direct`, and the load driver variable
  `MESH_MAX_DIRECT`. A node no longer refuses an offer at a cap: the cap code of
  older peers is still read.
- The idle closes of the pool (120 s), the acceptor (240 s) and the session
  detach (120 s) are one backstop of 900 s, read from the last use of the peer.

### Fixed

- The `iroh` fork moves to `c2e81ee` (agent-habilis/iroh PR #1). iroh opens a
  custom-transport path that it learns while another custom path is already
  selected. Before, a pair that multihop carried never opened a `WebRTC` path
  that came up later, so it could not climb back to `WebRTC` (4 of 14 runs of the
  ladder test). The `iroh-gossip` fork moves to `eca06e4`, which names the same
  `iroh`. It also fixes the gossip actor in two ways: it never waits for a full
  connection queue, and on overflow it drops and counts data but disconnects the
  peer for any other message.
- A member that let go of the rendezvous was dialed back by the beacon, which
  kept it in its passive view and refilled its active view from there, so in a
  steady 10-node UDP mesh members let go of the rendezvous 33 times in 10
  minutes, each time after the beacon had dialed them again. The member now
  tells gossip to leave the rendezvous (`GossipSender::leave_peers`, from the
  iroh-gossip fork): the beacon learns that the member left on purpose and
  keeps no claim on it. The link is never closed from this side, because an
  early close reaches the beacon as a lost connection. Once gossip has closed
  the link, the heal tick detaches the `WebRTC` session, as it does for any
  node that does not want the rendezvous. A session to
  the rendezvous that attaches after the release no longer grafts it again. The
  same 10-minute run now shows 0 releases.
- The anti-entropy digest no longer reports a gap that does not exist. A
  window was a slice of the log in arrival order, but its range ran from the
  least to the greatest timestamp of that slice. A log of more than 140
  messages (about 19 members) then lay inside the ranges without being listed,
  and holders re-sent those messages at the full budget on every digest. A
  window now covers a slice in `(timestamp, id)` order, bounded by that key,
  and the windows tile the log. A one-second burst of more than 70 messages
  no longer empties the digest. **Wire change:** each window carries `lo_key`
  and `hi_key` next to `lo` and `hi`, and a digest without them is ignored.
  Members on the old build and on this build do not repair each other's
  gaps until all upgrade.
  A node logs a warning, once per author per 10 minutes, for a digest that it
  cannot read.
- A member whose clock runs ahead no longer slows the repair of the newest
  messages. A message carries the timestamp of its sender, and nothing bounds
  how far ahead that is. The newest anti-entropy window took the 70 newest by
  timestamp, so 70 messages stamped ahead held it on every node, and a lost
  fresh message of another member waited for the sweep (13 rounds on a full
  log, 1 round before). The newest window now takes the 70 newest up to the
  local clock. Messages stamped ahead of the clock are reached by the sweep.
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
- A unicast connection that nothing sends on is closed after two minutes, on the
  dial side by the pool and, after four minutes, on the accept side. Before,
  every peer that was ever sent to kept a QUIC connection for the life of the
  process. The next send dials again. The close carries its own code, so the
  other side can tell it from a refusal.
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
  the rendezvous (it tells gossip to leave it, and detaches the session once
  gossip has closed the link). It
  comes back only while it has fewer than three links, or once for two minutes
  after the sweep removed a silent roster peer, which is how islands of a split
  mesh meet again; a node that came back stays 30 s and lets go again, and a
  node that does not want the rendezvous detaches a session to it. The node
  that hosts the beacon keeps its own link, so that a joiner always finds a
  member in the beacon's view. A refusal at a peer's cap makes a node wait, per
  peer: 30 s, doubling with each refusal in a row up to five minutes, and
  starting over after a success.
- The relay watcher covers the gossip connections that a node dialed, not only
  the ones it accepted. iroh-gossip keeps one connection per pair and drops the
  other, so a pair could keep the dialed connection on the relay, with no
  watcher on that end, after the accepted one was closed: the link stayed up
  and no `NeighborDown` followed.
- The answerer of a `WebRTC` session round nudges iroh once after the attach.
  iroh opens a new path only from the client side of a connection, so a
  connection that the answerer had dialed over the relay stayed there while the
  session was up, and the relay policy then closed it.
- A gossip connection on a lookup-only mesh whose selected path stays on the
  relay for `PROBE_DEADLINE` (15 s), the wait of the accept gate, after the accept is closed
  with the gossip relay-refused code. The accept gate checked the path only once, so a
  path lost later left a link up on the relay with nothing to say that no
  payload may ride it.

### Removed

- **Breaking:** the `--multihop` flag, `SetupParams::multihop` and
  `TransportOpts::multihop`. Multi-hop follows the mesh's transport policy.
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
