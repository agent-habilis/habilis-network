# light-cycles

A real-time multiplayer Tron/light-cycles game over `fofoca` — a serverless,
peer-to-peer showcase for something latency-sensitive and interactive, not
another chat log. A terminal and a browser tab can join the same room and
race each other, with **no server and no authoritative peer**: every
client runs the same deterministic simulation over the same inputs and
arrives at the same result on its own. Nothing about who's alive or who
won is ever announced — only one small input per player per tick is sent, over
[`fofoca-netplay`](../..), which is GGPO-style rollback netcode on a fofoca
mesh.

## What it demonstrates

- **Rollback netcode over a gossip mesh.** Each peer simulates immediately
  using *predicted* remote inputs and rolls back to re-simulate when a real
  input contradicts the guess. The prediction window, the state snapshots,
  the input redundancy and the desync checksums all live in
  `fofoca-netplay`; this example only supplies a simulation and fulfils the
  session's `SaveState`/`LoadState`/`AdvanceFrame` requests.
- **A fixed roster, agreed before anyone plays.** The lobby settles who is
  in a match and in what order, and `RoundDescriptor::derive(session_id,
  roster)` turns that into byte-identical spawn positions on every peer with
  no messages about the arena itself. Handles are positional, so that shared
  order is load-bearing.
- **Determinism you can test.** `native/game/tests/sync_test.rs` runs the
  simulation under `SyncTestSession`, which forces a rollback every frame
  and compares state checksums — so a violation of the determinism contract
  fails locally instead of desyncing a real match.
- **Two independent implementations of one wire protocol.** `native/` and
  `web/` share no code (see "Workspace layout" below) — deliberately, to
  prove the protocol itself is the contract, not a shared crate. A native
  terminal and a browser tab playing a full round against each other (see
  "Cross-play" below) is the one check that actually proves this.
- **Two different rendering hosts, one reactive model.** `native/`'s TUI
  (`visage-rust-tui`, a from-scratch Rust port) and `web/`'s canvas
  (`visage-canvas`) are both generator/signal-driven components — the same
  architecture, a different `Host`.

## Workspace layout

```
crates/fofoca-netplay/          # the rollback session, lobby and mesh transport — used by both clients
└── examples/light-cycles/
    ├── native/                 # terminal client — own cargo workspace, pinned to nightly
    │   ├── game/               #   CLI (create/join), game logic, the fofoca embedding
    │   └── visage-rust-tui/    #   a first-draft Rust port of visage-dom + visage-tui's terminal diffing
    └── web/                    # browser client — own cargo workspace + Bun frontend
        ├── wasm/               #   game logic (independent copy, wire-compatible with native/game's), the fofoca embedding, the wasm-bindgen JS API
        ├── vendor/             #   vendored visage-dom/visage-canvas/visage-style
        └── src/                #   the Bun/TypeScript frontend
```

## Run it

### Native (terminal)

**Your terminal needs at least 66 × 54 characters.** The arena is a fixed
64 × 48 field — a cross-play contract with the browser client, so it cannot
shrink to fit — and below that size the client shows what it needs and waits
for you to resize rather than drawing a screen with the room code cut off it.

Two terminals on one machine, which is the usual case:

```sh
cd crates/fofoca-netplay/examples/light-cycles/native
cargo run -p light-cycles-native -- create --nick alice --local
# prints a room code — type it into the other terminal exactly as shown
cargo run -p light-cycles-native -- join <room-code> --nick bob --local
```

`--local` finds the other player over loopback: instant, and no internet.
**Both sides must pass it** — the flag changes how the mesh is derived, so a
`--local` peer and a public one look for each other in different places and
never meet.

Drop `--local` to play with someone on another machine. That path bootstraps
over mDNS/DHT/relay and takes 20–30s to converge even when both players are
local, so give it time before assuming it is stuck.

Arrow keys or WASD to turn; `q`/Esc/Ctrl-C to quit.

Room codes are case-sensitive — `topic_seed` hashes the string byte for byte,
so `Volt-Paddle` and `volt-paddle` are different rooms.

If a match will not start, the status line says why (`WAITING`,
`2 PLAYERS READY`, `SYNCING`, or the reason it is blocked — two players
sharing a nickname, say). For anything below that, `--log-file game.log` with
`RUST_LOG=fofoca=debug` writes the engine's own log to a file; it cannot go to
the terminal, which the game's alternate screen owns.

### Web (browser)

Prerequisites: `rustup target add wasm32-unknown-unknown`,
`cargo install wasm-bindgen-cli --version 0.2.127`, [Bun](https://bun.sh),
and on macOS `brew install llvm` (Apple's clang has no wasm backend, and
`ring`'s C core needs one).

```sh
cd crates/fofoca-netplay/examples/light-cycles/web
./build-wasm.sh
bun install
bun run dev
# open the URL dev printed (3000, or the next free port) — "create game" or paste a room code to join
```

### Cross-play

Run both: create a room on one, join it with the room code on the other.
"Create" and "join" are the same operation for both clients — a
topic-derived mesh converges regardless of who calls it first.
