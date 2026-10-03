# Direct-peer memory baseline

Phase 0 of the direct-peer cap plan. It measures memory before any code change.

Base commit: `29d3895`. Date of the runs: 2026-10-03. Host: one Mac, shared with other work. Nodes are native processes only. A browser session costs more, and this document does not measure it.

## Question

Does a gossip link cost more memory than a cap on direct unicast connections saves?

A gossip link is not under the planned cap. A cap on direct peers only limits unicast connections and WebRTC sessions.

## Method

Each node is one process. A throw-away driver, `mesh_peer_load`, is not committed. This section gives the facts that are needed to rebuild it.

- The driver uses the public `membership` API: `resolve_kind`, `setup_mesh` and `MembershipApp`. It does not copy `mesh_peer.rs`. The reason is that `send_app` is private to the crate.
- The first process creates the mesh. It also starts a local plain-HTTP relay with `net::test_relay::spawn_plain`. No run uses a public relay, the DHT or mDNS.
- The lookup list holds only `relay`. The transport list holds only `udp`, or only `webrtc`.
- `max_peers` is 64, the default gossip active view. One run uses 8 (`MESH_MAX_PEERS`).
- Once per second, each node reads its roster with `Request::Peers`. With traffic on, it sends one directed `msg` to each roster peer with `Request::Send`.
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
- The census line has no session count. The session count comes from `WebRtcHandle::session_count()`, which the driver prints. It counts the rendezvous session.
- `peak_resident_memory_mb` has a resolution of 1 MB. It is a peak, so it includes the burst at join time and the messages that a node still holds.
- Some nodes of the large runs print no census line in time. Their memory is missing from the statistics. Their roster size is still known.

Statistics:

- The creator also hosts the relay. Its memory is shown in its own column. The median and the maximum cover all other nodes.
- N is the number of processes. Each node has N-1 roster peers in a full mesh.

### What "gossip only" contains

The gossip-only column is not free of unicast connections. For each IP peer, `ensure_direct` (`crates/habilis-network/src/transport/probe.rs`) proves the direct path with `pool.warm_or_dial`. Each gossip link therefore brings one pooled unicast connection, with or without traffic.

As a result:

- The gossip-only cost is the cost of a mesh member: one gossip link, one pooled connection, and the state for that peer.
- The difference between the directed run and the gossip-only run is only the cost of sending over a connection that already exists.
- This difference is an upper bound for the cost of a unicast connection. The bound is about 0.2 MB.

Limits of the method:

- The host ran other work during the runs. The load average was between 6 and 20 in the main matrix, and up to 32 in the last three runs. A heavy host can slow the formation of a mesh.
- The runs of `plant-stack` (a spike of 2 or 3 processes) could have run at the same time. I did not measure this.
- Each cell is one run. The noise is about 1 to 2 MB. Do not read a difference smaller than this.

## Results

Peak resident memory in MB, as median / maximum over all nodes except the creator. The creator column holds the relay as well, so it is higher than the other nodes.

UDP only:

| N | gossip only | directed | directed + multihop | mean gossip links | isolated nodes | creator (directed) |
| -- | -- | -- | -- | -- | -- | -- |
| 2 | 29 / 29 | 29 / 29 | - | 1.0 | 0 | 32 |
| 8 | 32 / 32 | 32 / 32 | - | 7.0 | 0 | 38 |
| 17 | 36 / 37 | 38 / 39 | 41 / 42 | 16.0 | 0 | 50 |
| 33 | 53 / 60 | 59 / 64 | 60.5 / 65 | 32.0 | 0 | 93 |
| 65 (join every 0.3 s) | 79 / 100 | 75 / 100 | 73 / 126 | 29.6 | 18 | 136 |
| 65 (join every 1 s, 180 s) | 94 / 123 | 86 / 114 | - | 37.8 | 9 | 145 |

The links and isolated columns come from the directed runs. The multihop column covers N = 17, 33 and 65 only.

UDP, gossip only, added in the repair:

| Run | median / max | mean gossip links | isolated nodes | creator |
| -- | -- | -- | -- | -- |
| N = 33, `max_peers` 64 (row above) | 53 / 60 | 32.0 | 0 | 88 |
| N = 33, `max_peers` 8 | 74 / 86 | 6.6 | 0 | 178 |
| N = 60, `max_peers` 64 | 85 / 105 | 45.3 | 0 | 146 |
| N = 66, `max_peers` 64 | 95 / 120 | 41.5 | 3 | 200 |

In the N = 60 run, 51 of 60 nodes printed a census line. In the N = 66 run, 56 of 66 did.

WebRTC only:

| N | gossip only | directed | mean sessions (directed) | mean gossip links (directed) | isolated nodes (directed) | creator (directed) |
| -- | -- | -- | -- | -- | -- | -- |
| 2 | 32 / 32 | 33 / 33 | 2.0 | 1.0 | 0 | 36 |
| 8 | 35 / 35 | 37 / 37 | 8.0 | 7.0 | 0 | 44 |
| 17 | 40 / 42 | 44.5 / 46 | 15.0 | 14.1 | 1 | 61 |
| 33 | 30 / 43 | 30 / 45 | 7.5 | 7.0 | 17 | 66 |
| 65 | 30 / 42 | 30 / 44 | 3.8 | 3.5 | 49 | 77 |

An isolated node has an empty roster.

### Rows that are not full-mesh readings

- **WebRTC, N = 17.** One node is isolated, so this is not a full mesh.
- **WebRTC, N = 33 and 65.** A node accepts at most `MAX_DIRECT_PEERS` (16) sessions, and the rendezvous peer counts as one. The first 16 nodes fill the rendezvous peer. The later nodes cannot attach, and they stay isolated at the idle size of about 30 MB. A WebRTC-only mesh therefore does not grow past about 16 peers.
- **UDP, N = 60, 65 and 66.** No run formed a full mesh. See the boundary test below.

## Main finding: the cost per member rises with N

Take the gossip-only runs of full meshes. Each row adds members, and each member brings one link.

| Step | Added members | Added MB | MB per added member |
| -- | -- | -- | -- |
| N 2 to 8 | 6 | 3 | 0.5 |
| N 8 to 17 | 9 | 4 | 0.44 |
| N 17 to 33 | 16 | 17 | 1.06 |

The cost per member is more than twice as high in the last step. A cost that depends only on the number of connections would stay flat. Something else grows faster than the connection count.

The run with `max_peers` 8 gives a first hint. Its nodes hold 6.6 links instead of 32, and the roster is still complete (32 peers). The median memory is 74 MB, not 53 MB. The logs of this run hold 5296 lines `re-graft the rendezvous`. The N = 33 run with `max_peers` 64 holds 90. The small view causes churn, so the run cannot separate the cost of the links from the cost of the state per member. It does show that fewer links did not give less memory.

## Costs per peer

Each cost comes from full-mesh rows only (N up to 33 on UDP, N up to 17 on WebRTC).

| Cost | Source | MB |
| -- | -- | -- |
| Mesh member (gossip link, pooled connection and per-peer state), per added member | UDP gossip only | 0.44 at N 8 to 17, 1.06 at N 17 to 33 |
| Sending over a pooled connection, per peer | UDP directed minus gossip only, N = 17 and 33 | at most about 0.2 |
| Multihop underlay, idle, per node | UDP directed with and without multihop, N = 17 and 33 | 1.5 to 3 in total |
| WebRTC stack, fixed | WebRTC minus UDP, N = 2 | 3 to 4 in total |
| WebRTC session, per added session | WebRTC minus UDP, N = 2 to 17, net of the fixed stack | about 0.2 |

About the multihop row: in a full direct mesh no cell goes through a relay hop. The row is the idle cost. The cost of forwarding is not measured. The maximum of 126 MB in the N = 65 multihop run comes from one run, and I have no explanation for it.

## Boundary test: N = 60 and N = 66

The default gossip active view is 64 (`GOSSIP_ACTIVE_VIEW_CAPACITY`, `crates/habilis-network-util/src/tuning.rs`). The test was this: if N = 60 forms and N = 66 loops on `re-graft the rendezvous`, the limit is the 64 boundary.

Result, UDP, gossip only:

- N = 60: no isolated node. The rosters range from 28 to 59 peers, and only 9 nodes see all 59 peers. The logs hold 146 `re-graft` lines.
- N = 66: 3 isolated nodes. The other rosters range from 2 to 61 peers, and no node sees all 65. The logs hold 284 `re-graft` lines.

Verdict: not confirmed, and not refuted. N = 66 is worse than N = 60, which agrees with a limit near 64. But the earlier N = 65 runs had 9 and 18 isolated nodes, which is worse than N = 66. N = 60 is also far from complete. The load average was 20 to 32 during these runs. A clean answer needs a quiet host or a longer wait.

## Decision

A mesh member costs 0.4 to 1.1 MB, and the cost per member rises with N. Sending over a pooled connection costs at most about 0.2 MB.

At N = 65, the most that any limit on the unicast pool can save is about 7 MB per node. This is the 48 connections past a cap of 16, at about 0.15 MB each. The growth of the gossip-only reading is 50 to 65 MB above the idle size of 29 MB.

The reading at N = 65 is 79 to 94 MB, from runs with isolated nodes. Use it as a lower bound. An extrapolation from N up to 33 gives 53 + 32 × 1.06, about 87 MB.

A separate spike, not part of this document, reports that a peer past the cap keeps one QUIC connection over multihop. If this holds, the cap saves about 0 MB.

Gossip links and per-member state cost more than a cap on direct unicast connections saves. The WebRTC cap already exists. It limits the sessions to 16, which is about 3 MB at 0.2 MB per session.

Caveat: the figure at N = 65 is an extrapolation from N up to 33. No full mesh of 60 or more nodes formed.
