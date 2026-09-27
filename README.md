# fofoca

A serverless gossip-network engine. Peers find each other over mDNS, the mainline
DHT or a relay, form a mesh, and exchange messages and a shared CRDT document —
with no server in the middle.

It is built on [iroh](https://github.com/n0-computer/iroh) for transport and
[automerge](https://automerge.org) for shared state, and it is embeddable: the
event loop runs on a tokio runtime inside the calling process, so joining a mesh
costs a function call rather than a daemon.

Its first non-Rust consumer is [mallorca](https://github.com/dviramontes/mallorca),
an Odin application that links [`fofoca-ffi`](crates/fofoca-ffi) as a static
library and joins a mesh from its own process.

## The crates

See [docs/architecture.md](docs/architecture.md) §3 for the full dependency
graph and the role of each crate. In outline, dependencies point downward:

```
fofoca-util          host helpers, no deps of consequence   (13 crates resolved)
  └── fofoca-protocol    wire vocabulary, + iroh-base      (138 crates)
        ├── fofoca-doc          shared-state CRDT channels
        ├── fofoca-logging      tracing sink + filter
        └── fofoca         the engine, + iroh, iroh-gossip (436 crates)
              ├── fofoca-stream                 1-1 byte streams, tab and terminal
              │     ├── fofoca-stream-cli       the `fofoca-stream` binary
              │     ├── fofoca-ffi              the C ABI
              │     └── fofoca-wasm             the browser peer (wasm32 only)
              ├── fofoca-netplay                rollback netcode for p2p games
              ├── fofoca-iroh-webrtc-transport  QUIC over a WebRTC data channel
              └── fofoca-iroh-multihop-transport  QUIC relayed through peers

fofoca-chunks                     content-addressed chunk store, + blake3
```

`fofoca-chunks` is standalone: nothing here depends on it. The two transports
depend on nothing else here either, but the engine depends on *them* — on the
multihop transport under `host`, and on the WebRTC transport per target.

The load-bearing property: **the engine's dependents never name `iroh`
themselves.** Four crates here do name it — `fofoca`, the two transports, and
`fofoca-protocol` (which takes `iroh-base` alone, so the wire vocabulary pulls no
tokio, QUIC, TLS or DNS; `-doc`, `-logging`, `-reassembly` and `-directory`
inherit that). Everything else, in this workspace and downstream, reaches iroh
through `fofoca::iroh` so the graph can never hold two copies.

[`fofoca-chunks`](crates/fofoca-chunks) is a content-addressed chunk store:
fixed 64 KiB chunks addressed by BLAKE3 of their own bytes, so a chunk proves
itself and dedups across files, and the store never copies the caller's bytes.
It replaced `fofoca-blobs`, whose bao outboards proved placement inside one
file rather than content (removed after v0.6.0).

[`fofoca-netplay`](crates/fofoca-netplay) is GGPO-style rollback netcode for
peer-to-peer games on a mesh: peers agree a roster in a lobby, then each
simulates immediately against *predicted* remote inputs and rolls back to
re-simulate whenever a real input contradicts the guess. Only inputs cross the
wire, so bandwidth is O(players) and independent of world size, and no peer is
authoritative. The price is strict determinism — integer arithmetic, no hashed
iteration, no clocks in the simulation — which `SyncTestSession` checks locally
rather than leaving to fail as a desync mid-match.

[`fofoca-iroh-webrtc-transport`](crates/fofoca-iroh-webrtc-transport) carries
QUIC datagrams over a WebRTC data channel as an iroh custom transport. It is how
a browser reaches a peer at all: a tab has no UDP socket, so iroh's own paths do
not exist there. One crate, two mutually exclusive backends behind features —
`native` (sans-io str0m on tokio) and `web` (the browser's own
`RTCPeerConnection`) — sharing one protocol half, because two peers that
disagree about the transport id or the envelope shape fail to connect with no
useful error.

[`fofoca-iroh-multihop-transport`](crates/fofoca-iroh-multihop-transport) is the
other custom transport: source-routed relaying through intermediate peers, for
when no direct path exists at all.

None of the three knows what a mesh is, and the engine takes only the multihop
one. The other two meet it in a consumer.

That is the whole reason the split exists. Cargo features cannot be selected
per-consumer across a dependency edge, so a consumer that wants the wire
vocabulary without the network stack needs a crate boundary, not a feature flag.
The engine was 39.4 MiB of mallorca's 40.7 MiB release binary before it.

The crates are versioned in lockstep from `[workspace.package]`. They were carved
out of one engine to control the dependency closure, not to be released on
separate cadences.

## Related repos

- [`iroh`](https://github.com/fofoca-network/iroh) and
  [`iroh-gossip`](https://github.com/fofoca-network/iroh-gossip) — forks carrying
  two unreleased fixes, pinned by rev in `[patch.crates-io]`. See
  **Patch pins — do not drop** in [`FORKED.md`](FORKED.md).

## Build and test

```bash
cargo check --workspace
cargo test  --workspace          # 29 suites, 518 tests
```

That is the default position only. Several features are off by default and a
whole target is invisible from here, so the gate CI applies is wider — the
clippy pass over `blob`, the WebRTC crate's two mutually exclusive backends, the
doc-link check, and the wasm32 half. `cargo task` runs it:

```bash
cargo task ci                    # the whole gate, in the order CI runs it
cargo task lint                  # or one part of it
cargo task wasm
```

Every task takes `-p` to narrow it to one crate, which keeps the edit-check loop
proportional to what you changed:

```bash
cargo task ci   -p fofoca-chunks # the same gate, one crate
cargo task test -p fofoca        # its default tests and its `blob` ones
```

The gate itself is a table in [`tasks/src/gate.rs`](tasks/src/gate.rs), one row
per invocation in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). CI
still runs those commands directly, so it stays readable as a workflow and each
step keeps its own result; the table is the same list, runnable. If the two ever
disagree, the table is the one that is wrong.

The `mdns` and `dht` features (default on) gate iroh's discovery closure, and
`async-io` on `fofoca-util` gates its only tokio use, so the off positions are
worth checking too — `cargo task check` covers both, or by hand:

```bash
cargo check --workspace --no-default-features
cargo check --workspace --all-features
```

## Releasing

All member crates share one version from `[workspace.package]` and move as
one release. Nothing is published to a registry; a release is an annotated
tag plus a GitHub Release, and a consumer pins it:

```toml
fofoca = { git = "https://github.com/fofoca-network/fofoca", tag = "v0.6.0" }
```

The pin is self-contained: this workspace carries no `[patch.crates-io]`
(every fork is a direct git dependency with an exact version), so a consumer
restates nothing. Proven by a scratch crate that pins the tag and
`cargo check`s clean.

To cut a release:

1. Bump `version` in `[workspace.package]` (root `Cargo.toml`) and the
   version line in `docs/architecture.md`; run `cargo check --workspace` so
   `Cargo.lock` follows.
2. Add the section to `CHANGELOG.md`.
3. Run `cargo task ci` and make sure it is green.
4. Commit as `chore: release vX.Y.Z`, then tag: `git tag -a vX.Y.Z`.
5. Push with the tag, then publish the notes:
   `gh release create vX.Y.Z --title "fofoca X.Y.Z"` with the CHANGELOG
   section as the body.

## The browser

The engine runs in a tab. `--no-default-features` drops `host` and leaves the
portable half — gossip, the CRDT documents, the protocol and identity types,
address lookup, and the whole node runtime — so a browser peer is the same peer
a CLI runs, not a reduced stand-in. What it loses is the control socket, the
session state file, the process helpers and the log sink, none of which have a
wasm32 equivalent.

Six crates reach that target — `fofoca-wasm` is the browser peer itself,
behind `packages/fofoca-wasm` — each at its own feature position, and CI
checks and lints every one:

```bash
rustup target add wasm32-unknown-unknown
cargo task wasm                              # all six
cargo task wasm -p fofoca-chunks             # or one
```

`cargo check` is not enough on its own, which is why
[`crates/fofoca/tests/wasm_runtime.rs`](crates/fofoca/tests/wasm_runtime.rs)
exists: `std::time::Instant::now()`, `tokio::time` and `tokio::spawn` all
compile for wasm32 and then panic at runtime. Running it needs a wasm-capable
clang for `ring`'s C core, so it is a compile check in CI and a real run
locally:

```bash
CC=$(brew --prefix llvm)/bin/clang CC_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/clang \
  cargo test -p fofoca --no-default-features --target wasm32-unknown-unknown
```

`fofoca-chunks`'s IndexedDB tests need a real browser and are not in CI:
`wasm-pack test --headless --chrome crates/fofoca-chunks`.

Neither is the WebRTC transport's browser suite, which drives real browsers over
a build-profile and main-thread-pressure sweep: `cargo task e2e`, or
`cargo task e2e --quick` for the fast single-browser pass.

The native↔browser matrix — the one that proves a terminal and a tab exchange
payload on every lane under every relay policy — is
`cargo task e2e --suite mesh` (`--quick` for the four-cell pass). It needs the
wasm glue built first (`cargo task build-wasm` — the mesh suite also builds
it itself), bun, and a browser. The suites that drive one tab (`mesh`,
`stream`, `chat`) open Safari Technology Preview by default; `--only` picks
another (`safari`, `cft` for Chrome for Testing through `agent-browse`,
`chrome-ci` for Chrome through chromedriver). Each Safari needs
`sudo <its safaridriver> --enable` once. The suite runs with the task runner's
`mesh` feature, which it turns on by re-running itself through cargo, so the
first run builds the engine a second time with its test relay.

[`chat-webrtc`](crates/fofoca-iroh-webrtc-transport/examples/chat-webrtc) is a
runnable demonstration of the browser leg on its own: a chat room a tab and a
terminal both join, where the tab's connection is QUIC over a `WebRTC` data
channel and there is no signalling server. It is a workspace of its own and
depends on nothing here but `fofoca-iroh-webrtc-transport`, so it doubles as a
check that a consumer of that crate restates no iroh pin.

To build the C ABI as a static library:

```bash
cargo build --release -p fofoca-ffi   # -> target/release/libfofoca_ffi.a
```

[`crates/fofoca-ffi/include/fofoca.h`](crates/fofoca-ffi/include/fofoca.h) is the
hand-written declaration a C caller compiles against, and the counterpart of
`crates/fofoca-ffi/src/ffi.rs`. Change one, change the other; CI asserts the
archive actually exports everything the header declares.

## Provenance

A hard fork of [agent-habilis/agent-gossip](https://github.com/agent-habilis/agent-gossip).
[`FORKED.md`](FORKED.md) records every divergence and maps upstream paths to
their homes here; [`VENDORED.md`](VENDORED.md) is the superseded original
vendoring contract, kept for the record.

## License

MIT — see [`LICENSE`](LICENSE).
