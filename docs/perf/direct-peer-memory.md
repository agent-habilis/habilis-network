# Direct-peer memory baseline

Phase 0 of the direct-peer cap plan. It measures memory before any code change.

Base commit: `29d3895`. Date of the runs: 2026-10-03. Host: one Mac, shared with other work.

## Question

Does a gossip link cost more memory than a cap on direct unicast connections saves?

A gossip link is not under the planned cap. A cap on direct peers only limits unicast connections and WebRTC sessions.

## Method

Each node is one process. A throw-away driver, `mesh_peer_load`, is not committed. This section gives the facts that are needed to rebuild it.

- The driver uses the public `membership` API: `resolve_kind`, `setup_mesh` and `MembershipApp`. It does not copy `mesh_peer.rs`. The reason is that `send_app` is private to the crate.
- The first process creates the mesh. It also starts a local plain-HTTP relay with `net::test_relay::spawn_plain`. No run uses a public relay, the DHT or mDNS.
- The lookup list holds only `relay`. The transport list holds only `udp`, or only `webrtc`.
- `max_peers` is 64, the default gossip active view.
- Once per second, each node reads its roster with `Request::Peers`. With traffic on, it sends one directed `msg` to each roster peer with `Request::Send`. This opens one unicast connection per peer.
- With traffic off, the node sends no directed message. This is the gossip-only run.
- `MESH_MULTIHOP=on` sets `multihop: true` in `SetupParams`. This registers the second endpoint of the multihop underlay.
- The driver prints `peers <roster> sessions <WebRTC sessions>` once per second.

The runner starts the creator, reads the mesh id from its output, then starts the other nodes. It starts one node every 0.3 s. After the last node starts, it waits 120 s. Then it reads the last `mesh census` line of each node.

Build and run:

```text
cargo build --release -p habilis-network --features iroh-test-utils --example mesh_peer_load
MESH_TRANSPORT=udp|webrtc MESH_TRAFFIC=on|off MESH_MULTIHOP=on|off  mesh_peer_load          # creator
MESH_TRANSPORT=udp|webrtc MESH_TRAFFIC=on|off MESH_MULTIHOP=on|off  mesh_peer_load <mesh id> # each other node
```

Readings:

- `peak_resident_memory_mb`, `links_direct` and `link_len` come from the census line (`crates/habilis-network/src/daemon/timers.rs`).
- The census line has no session count. The session count comes from `WebRtcHandle::session_count()`, which the driver prints.
- `peak_resident_memory_mb` has a resolution of 1 MB.

Statistics:

- The creator also hosts the relay. Its memory is shown in its own column. The median and the maximum cover all other nodes.
- N is the number of processes. Each node has N-1 roster peers in a full mesh.

Limits of the method:

- The host ran other work during the runs. The load average was between 6 and 20. A heavy host can slow the formation of a mesh.
- The runs of `plant-stack` (a spike of 2 or 3 processes) could have run at the same time. I did not measure this.
- Each cell is one run. The noise is about 1 to 2 MB. Do not read a difference smaller than this.

## Results

Peak resident memory in MB, as median / maximum over all nodes except the creator.

UDP only:

| N | gossip only | directed | directed + multihop | mean gossip links (directed) | isolated nodes (directed) | creator (directed) |
| -- | -- | -- | -- | -- | -- | -- |
| 2 | 29 / 29 | 29 / 29 | - | 1.0 | 0 | 32 |
| 8 | 32 / 32 | 32 / 32 | - | 7.0 | 0 | 38 |
| 17 | 36 / 37 | 38 / 39 | 41 / 42 | 16.0 | 0 | 50 |
| 33 | 53 / 60 | 59 / 64 | 60.5 / 65 | 32.0 | 0 | 93 |
| 65 (join every 0.3 s) | 79 / 100 | 75 / 100 | 73 / 126 | 29.6 | 18 | 136 |
| 65 (join every 1 s, 180 s) | 94 / 123 | 86 / 114 | - | 37.8 | 9 | 145 |

WebRTC only:

| N | gossip only | directed | mean sessions (directed) | mean gossip links (directed) | isolated nodes (directed) | creator (directed) |
| -- | -- | -- | -- | -- | -- | -- |
| 2 | 32 / 32 | 33 / 33 | 2.0 | 1.0 | 0 | 36 |
| 8 | 35 / 35 | 37 / 37 | 8.0 | 7.0 | 0 | 44 |
| 17 | 40 / 42 | 44.5 / 46 | 15.0 | 14.1 | 1 | 61 |
| 33 | 30 / 43 | 30 / 45 | 7.5 | 7.0 | 17 | 66 |
| 65 | 30 / 42 | 30 / 44 | 3.8 | 3.5 | 49 | 77 |

An isolated node has an empty roster. The multihop column covers N = 17, 33 and 65 only, as the scope change asked.

### Two rows are not full-mesh readings

- **WebRTC, N = 33 and 65.** A node accepts at most `MAX_DIRECT_PEERS` (16) sessions, and the rendezvous peer counts as one. The first 16 nodes fill the rendezvous peer. The later nodes cannot attach, and they stay isolated at the idle size of about 30 MB. A WebRTC-only mesh therefore does not grow past about 16 peers. Use the rows for N = 2, 8 and 17 for the cost of a session.
- **UDP, N = 65.** The mesh did not form fully in any run. Between 9 and 18 nodes had an empty roster, and the others had rosters of 39 to 64 peers. The log of an isolated node repeats `reclaim tick: re-graft the rendezvous (link lost)`. A slower join did not remove the effect. I did not find the cause. A loaded host can be the cause, and a limit in the rendezvous peer can be the cause. Do not use the N = 65 UDP rows as a per-link figure.

## Costs per peer

Each cost comes from full-mesh rows only (N up to 33 on UDP, N up to 17 on WebRTC).

| Cost | Source | MB |
| -- | -- | -- |
| Gossip link, per added peer | UDP gossip only, N 8 to 17 and 17 to 33 | 0.4 to 1.1 |
| Unicast connection | UDP directed minus gossip only, N = 17 and 33 | 0.1 to 0.2 |
| Multihop underlay, per node | UDP directed with and without multihop, N = 17 and 33 | 1.5 to 3 in total |
| WebRTC session, beyond a UDP link | WebRTC minus UDP, N = 8 and 17 | 0.3 to 0.6 |
| WebRTC stack, fixed | WebRTC minus UDP, N = 2 | 3 to 4 in total |

In a full mesh each peer has one gossip link. The gossip cost per peer therefore also holds the roster and the state for that peer. The data does not separate the two.

## Decision

A unicast connection costs little: about 0.15 MB. A gossip link costs 0.4 to 1.1 MB per peer, 3 to 7 times more.

At N = 65, a cap of 16 direct peers removes about 48 unicast connections. This saves about 7 MB per node. The gossip-only reading at N = 65 is 79 to 94 MB, about 50 to 65 MB above the 29 MB idle size. The gossip links cost more than the cap saves.

Capping UDP unicast buys little memory. The WebRTC cap already exists. It limits the sessions to 16, which is about 8 MB at 0.5 MB per session.

Caveat: the figure at N = 65 is an extrapolation from N up to 33. No full mesh of 65 nodes formed.
