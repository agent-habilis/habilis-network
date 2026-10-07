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
  scripts/perf/run.sh target/release/examples/mesh_peer_load 48 240 /tmp/perf/n48
python3 scripts/perf/summarize.py /tmp/perf/n48
```

A series, each run after the host has calmed down (`load1` below 5, at most 15 min of
waiting), with the uptime of every start and end in `drive.log`:

```bash
MESH_TRAFFIC=off scripts/perf/series.sh target/release/examples/mesh_peer_load \
  /tmp/perf 240 48:1 48:2 48:3 66:1
python3 scripts/perf/summarize.py /tmp/perf/N*
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
| `MESH_MAX_SESSIONS` | D, the cap on WebRTC sessions; `0` takes the engine default. D has an effect only when `webrtc` is in the list: set `MESH_TRANSPORTS=udp,webrtc,multihop` for a run of D. The default list has no `webrtc` |
| `MESH_BLOCK_UDP_AFTER_SECS` | after this many seconds the node takes IP away from every connection of its process, once |
| `MESH_UNDERLAY_LEG` | `off`: the multihop underlay holds no WebRTC leg (the control cell) |
| `STAGGER` | seconds between two node starts (`run.sh`, default 0.3) |

## Output

Each node prints one line per second:

```text
t 123 phase 1 peers 47 links 32 sessions 0 underlay 0 rss_mb 91
```

`peers` is the roster, `links` the gossip neighbors, `sessions` the WebRTC sessions of
the app endpoint, `underlay` those of the multihop underlay, and `rss_mb` the current
resident memory. `phase` is 2 once the node has taken IP away.

A run folder holds `n<i>.out` and `n<i>.err` per node, `summary.txt` (the last census
line of each node), `host.log` (one line per 10 s), `canary.log` (every pause of the host
over 0.5 s), `probe.log` and `done`. `summarize.py` prints one line per run: nodes with a
full roster, isolated nodes, stalls, link churn (`up` and `down`), dropped data messages,
send-queue disconnects, the digest answers, memory and load.

## Memory of the underlay sessions

Two cells, three runs each, release build, N = 33 (G = 32), traffic on, the relay in the
transport list:

```bash
export MESH_TRANSPORTS=udp,webrtc,multihop,relay MESH_BLOCK_UDP_AFTER_SECS=60
scripts/perf/series.sh target/release/examples/mesh_peer_load /tmp/perf/leg-on 240 33:1 33:2 33:3
MESH_UNDERLAY_LEG=off \
  scripts/perf/series.sh target/release/examples/mesh_peer_load /tmp/perf/leg-off 240 33:1 33:2 33:3
python3 scripts/perf/underlay_report.py /tmp/perf/leg-on/N* /tmp/perf/leg-off/N*
```

The marginal memory of one session is (the delta with the leg on minus the delta with the
leg off) divided by the mean number of underlay sessions per node. Each run takes about
6 min, so the two cells take about 36 min.

## What it does not do

- The nodes are native processes. A browser costs more.
- The host runs other work. Read `host.log` and `canary.log` before you trust a run, and
  log the uptime beside the timings (`series.sh` does).
- `peak_resident_memory_mb` in the census is a peak: it includes the burst at join time.
  Use `rss_mb` for growth.
