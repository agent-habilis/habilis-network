# Mesh load harness

One process is one node. `crates/habilis-network/examples/mesh_peer_load.rs` is the
node, and the scripts here start N of them on one host and read what they print. The
creator hosts a local relay, so no run touches a public relay, the DHT or mDNS.

## Build

Build the driver in release mode, outside the worktree if other jobs share it:

```bash
cargo build --release -p habilis-network --features host,iroh-test-utils --example mesh_peer_load
```

A debug build (leave out `--release`) is slower and uses more memory. State which one
a result comes from.

## Run

One run: 48 nodes, 240 s of steady time after the last start, gossip only.

```bash
MESH_TRAFFIC=off RUST_LOG="habilis_network=info,iroh_gossip=warn" \
  bun scripts/perf/run.ts target/release/examples/mesh_peer_load 48 240 /tmp/perf/n48
bun scripts/perf/summarize.ts /tmp/perf/n48
```

A series, each run after the host has calmed down (`load1` below 5, at most 15 min of
waiting), with the uptime of every start and end in `drive.log`:

```bash
MESH_TRAFFIC=off bun scripts/perf/series.ts target/release/examples/mesh_peer_load \
  /tmp/perf 240 48:1 48:2 48:3 66:1
bun scripts/perf/summarize.ts /tmp/perf/N*
```

Close builds and other heavy work first. A run of N = 48 takes about 5 min, and N = 66
about 6 min, with 30 s of rest between two runs.

## Settings of the driver

All are environment variables, and all are optional. The header of the example has the
full text.

| Variable | Meaning |
| -- | -- |
| `MESH_TRANSPORT` | `udp` (default) or `webrtc`; multihop is added to `udp` unless `MESH_MULTIHOP=off` |
| `MESH_TRANSPORTS` | the whole list, for example `udp,webrtc,multihop,relay`; only the creator reads it |
| `MESH_TRAFFIC` | `off`: no directed messages. On, each node sends one per second to each roster peer |
| `MESH_MAX_PEERS` | G, the gossip active view; `0` takes the engine default |
| `MESH_MAX_DIRECT` | C, the ceiling of direct connections (WebRTC sessions and unicast connections together); `0` takes the engine default, 64. A newcomer past C evicts the least valuable peer |
| `MESH_TRAFFIC_UNTIL_SECS` | the directed messages stop after this many seconds. With `MESH_BLOCK_UDP_AFTER_SECS` and `MESH_TRANSPORTS=udp,webrtc,multihop` this is the run of the idle detach |
| `MESH_TRAFFIC_BURSTY` | `1`: instead of a message per second to every peer, every 60 to 240 s (random) one message to each of 3 to 5 random peers. A connection then idles, and is needed again |
| `MESH_FLOOD_PEERS` | K: from second 30 on, messages of 3000 bytes to the first K roster peers as fast as the node accepts them. The RSS against K is the worst case of one connection (with `MESH_TRAFFIC=off`). Read the RSS of the sender and of the receiver: the flood fills the send buffer of the sender as well as the receive window of the receiver |
| `MESH_FLOOD_SENDERS` | S: with `MESH_FLOOD_PEERS`, only the nodes with index 1 to S flood; the others only receive. `run.ts` sets `MESH_NODE_INDEX` (1 is the creator). Each per-second line then ends with `role sender` or `role receiver`, so the RSS of the two roles can be read apart. Unset: every node floods, and the line has no role |
| `MESH_BLOCK_UDP_AFTER_SECS` | after this many seconds the node takes IP away from every connection of its process, once |
| `MESH_UNDERLAY_LEG` | `off`: the multihop underlay holds no WebRTC leg (the control cell) |
| `STAGGER` | seconds between two node starts (`run.ts`, default 0.3) |

## Output

Each node prints one line per second:

```text
t 123 phase 1 peers 47 links 32 sessions 0 underlay 0 rss_mb 91 idle_sessions 0
```

`peers` is the roster, `links` the gossip neighbors, `sessions` the WebRTC sessions of
the app endpoint, `underlay` those of the multihop underlay, and `rss_mb` the current
resident memory. `qclose`, `pclose` and `sclose` count the closes of every QUIC connection
(the gossip links too), of the pooled unicast connections that a send used, and of WebRTC
sessions, and `qredial`, `predial` and `sredial` the closes that were followed by a connection to
the same peer within 300 s: `bun scripts/perf/redial_report.ts <run folder>` prints them
per node per hour, and the share of closes that were followed by a re-dial. `idle_sessions` counts the WebRTC sessions to members that are not gossip
neighbors. `phase` is 2 once the node has taken IP away.

A run folder holds `n<i>.out` and `n<i>.err` per node, `summary.txt` (the last census
line of each node), `host.log` (one line per 10 s), `canary.log` (every pause of the host
over 0.5 s), `probe.log` and `done`. `summarize.ts` prints one line per run: nodes with a
full roster, isolated nodes, stalls, link churn (`up` and `down`), dropped data messages,
send-queue disconnects, the digest answers, memory and load.

## Memory of the underlay sessions

Two cells, three runs each, release build, N = 33 (G = 32), traffic on, the relay in the
transport list:

```bash
export MESH_TRANSPORTS=udp,webrtc,multihop,relay MESH_BLOCK_UDP_AFTER_SECS=60
bun scripts/perf/series.ts target/release/examples/mesh_peer_load /tmp/perf/leg-on 240 33:1 33:2 33:3
MESH_UNDERLAY_LEG=off \
  bun scripts/perf/series.ts target/release/examples/mesh_peer_load /tmp/perf/leg-off 240 33:1 33:2 33:3
bun scripts/perf/underlay_report.ts /tmp/perf/leg-on/N* /tmp/perf/leg-off/N*
```

The marginal memory of one session is (the delta with the leg on minus the delta with the
leg off) divided by the mean number of underlay sessions per node. Each run takes about
6 min, so the two cells take about 36 min.

## Oracle file

The oracle file is the record of the user data that the runner sent. It is the only
source of the data bytes in the ratio. The engine counters do not name data.

The file is `oracle.jsonl` in the run folder. It has one JSON line per user payload that
the runner sends. Each line has these keys, and no other key:

| Key | Type | Meaning |
| -- | -- | -- |
| `sender` | string | the nickname of the sending daemon |
| `kind` | string | `broadcast`, `msg`, `task_brief`, `task_status` or `task_artifact` |
| `receivers` | integer | how many daemons must receive the payload: 63 for a broadcast in a mesh of 64, 1 for a `msg` |
| `bytes` | integer | the length of the user text that the runner sent, in bytes of UTF-8 |
| `seq` | integer | the number of the line, from 0, one count for the whole run |
| `ts` | integer | the send time, in milliseconds since the epoch |

The runner writes the line when the send command returns without an error. A payload
that failed to send has no line.

### Rules for the ratio

- Data is the exact user text that the runner sent. The envelope of a frame is not data:
  the header, the signature, the ids and the nonce are metadata.
- Delivered data bytes are the sum of `bytes` times `receivers` over all lines.
- A duplicate copy of a data frame counts as metadata. The first copy that a receiver
  gets is data.
- Metadata bytes are the wire bytes minus the delivered data bytes.
- The runner plays the worker of each task. Each task makes one `task_brief`, one or more
  `task_status`, and one `task_artifact`. Each of them has a line.

### Two layers

- Frame layer: the wire bytes of the frames, from the `idle_wire_*` census fields. The
  summary asserts this layer. It fails if the metadata bytes are negative.
- UDP layer: the bytes of the iroh socket, from the `idle_net_*` census fields. The
  summary reports this layer and asserts nothing, because QUIC adds its own framing.

### Two phases

- Idle phase (no workload): the result is the metadata bytes per second per daemon. It
  is an absolute number. There is no data, so there is no ratio.
- Loaded phase (workload): the result is the metadata bytes per delivered data byte. The
  window of the phase comes from `result.json`.

### Example

A mesh of 2 daemons. The runner sends one broadcast of 200 bytes and one `msg` of
200 bytes. Then `receivers` is 1 for both lines, and the delivered data bytes are
200 + 200 = 400. If the wire bytes are 1000, the metadata bytes are 600, and the ratio
is 1.5.

### Memory by N

`summarize.ts` also reads `host.jsonl` of the run folder, which the runner writes every 10 s. The sample with
the largest RSS sum gives `rss_n` (the daemon count), `rss_mean_mb_per_daemon`, `rss_max_mb` (the largest
daemon in the run) and `rss_sum_mb`. A run of 16 daemons that gives 52.6 MB per daemon and a run of 8 that
gives 29.7 MB show how the RSS per daemon grows with N.

## Load gates

`gate.ts` holds the numbers, from the idle meshes on nyc-macmini1 (8 cores, 8 GiB). `b4.ts` applies them.

- Start gate: load1 is at most 2.0 now, and at most 2.5 in the 3 min before. (First values 1.5 and 2.0: the host idles at 1.5 to 1.76 with no daemon of ours, so that gate never opened.) The driver waits up to 20 min.
- Phase gate: the median load1 of a phase is at most 4.0, and the max is at most 6.0. A run with a phase over
  the gate is void and runs again, twice at most.
- A/B gate: the idle1 medians of the two arms of a pair are within 35 percent. A pair that fails runs once more. A void run or a failed pair stays on disk, and its folder name starts with `void-`.

`b4.ts` runs pairs of arm a (the plain baseline, for CPU) and arm b (the baseline with counters, for bytes and
the ratio), in turn, with the order swapped in every second pair. Both arms have the same warm-up (300 s of
settle). Arm a has no loaded phase: it has no wire counters, so it gives no ratio. Run it after `ulimit -n 10240`.

To compare two builds that both have the wire counters, give arm a a loaded phase with `--plain-loaded 300`. Both
arms then give a ratio, and the step measure of the unicast digests used it: arm a was the build before the change and
arm b the build with it, 3 pairs at N = 16.

## Ratio test

`ratio.test.ts` holds the goal: at N = 16 the frame-layer metadata bytes per delivered data byte are at most half of
the baseline (`baseline-ratio.json`: 78.9, from pairs 2 and 3 of B4 on nyc-macmini1). A second test is the regression
budget: at most the `head_value` of that file plus 10 percent. Both tests run `bench.ts` for about 20 min on the
binary in `RATIO_BIN` (a build with the wire counters), so run them on a quiet host:

```bash
RATIO_BIN=<binary> bun test scripts/perf/ratio.test.ts
```

A host with too little memory for N = 16 fails the host tests and prints `SKIPPED`. `RATIO_ALLOW_SKIP=1` lets it skip.

## What it does not do

- The nodes are native processes. A browser costs more.
- The host runs other work. Read `host.log` and `canary.log` before you trust a run, and
  log the uptime beside the timings (`series.ts` does).
- `peak_resident_memory_mb` in the census is a peak: it includes the burst at join time.
  Use `rss_mb` for growth.

## Ratio test

`ratio.test.ts` is a benchmark, not a unit test. It runs `bench.ts` for about 20 min and needs a quiet host, so CI skips it (`package.json`, `test` script). Run it by hand:

```bash
RATIO_BIN=<binary> bun test scripts/perf/ratio.test.ts
```

Set `RATIO_ALLOW_SKIP=1` on a host with too little memory to skip the two host tests.
