# Direct-peer memory baseline

Phase 0 of the direct-peer cap plan. It measures memory before any code change.

Base commit: `29d3895`. Date of the runs: 2026-10-03. Host: one Mac, shared with other work. Nodes are native processes only. A browser session costs more, and this document does not measure it.

## Question

Does a gossip link cost more memory than a cap on direct unicast connections saves?

A gossip link is not under the planned cap. A cap on direct peers only limits unicast connections and WebRTC sessions.

## Method

Each node is one process. The driver, `mesh_peer_load`, was a throw-away file when these runs were made. It is now committed as `crates/habilis-network/examples/mesh_peer_load.rs`, with the scripts in `scripts/perf/` (see its README). This section gives the facts of the runs below.

- The driver uses the public `membership` API: `resolve_kind`, `setup_mesh` and `MembershipApp`. It does not copy `mesh_peer.rs`. The reason is that `send_app` is private to the crate.
- The first process creates the mesh. It also starts a local plain-HTTP relay with `net::test_relay::spawn_plain`. No run uses a public relay, the DHT or mDNS.
- The lookup list holds only `relay`. The transport list holds only `udp`, or only `webrtc`.
- STUN: the `WebRTC` runs were not on a loopback mesh. By the code, a node on such a mesh asks two public STUN servers for its public address (`stun1.l.google.com:19302` and `stun.cloudflare.com:3478`, `DEFAULT_STUN_HOSTS`). Those servers only learn the public ip:port of the node, and no payload goes through them. I did not capture packets to confirm that the runs did this. The UDP runs do not use `WebRTC`, so they make no STUN request. The sentence above that no run uses a public relay, the DHT or mDNS is true. It does not cover STUN.
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

## Rerun at N = 66 after the release fix

Question: does N = 66 on UDP form a full mesh once a member lets go of the rendezvous with `leave_peers` (commit `932013a`, fork `5f7fe84`)?

Answer: no. In three runs, 0 to 2 of 66 nodes held all 65 peers, and 0 to 5 nodes were isolated. The cause is not found. The numbers below are not a verdict on membership, because of the first condition in the next list.

Conditions, which differ from the runs above:

- **Debug build.** The three runs use `target/debug` (`cargo build -p habilis-network --features iroh-test-utils --example mesh_peer_load`), not the release build in the method section. Memory and timing are not comparable with the rows above.
- **Throttled timers.** Nodes logged `maintenance timer stalled ... suspected="throttle"`. Run 1 has 11 lines on 4 nodes, run 2 has 12 lines on 4 nodes, and run 3 has 267 lines on 57 nodes. The largest gap is 168 s. In run 3, 57 of 66 nodes had a timer gap of minutes while the mesh formed. A census taken then shows nodes that recover from a stall. It is not evidence of a membership fault.
- **Wait of 240 s** after the last node starts, not 120 s.
- **Shared host.** Other jobs ran on the host. The 1-minute load is the value of `uptime` just before the run. The 66 processes drive the load to 83 to 97 during the run.
- **One commit.** Commit `6c3635a`. Traffic on, multihop on, `max_peers` 64. The wait for a quiet host used the 15-minute column of `uptime` by mistake, so runs 2 and 3 started with a 5-minute load of 11.4 and 6.4.

| Run | Load before (1 / 5 / 15 min) | Nodes with a census line | Full roster (65) | Isolated | Roster median (min) | Mean links (direct) | Peak MB median (max) | Peak MB per direct link | `re-graft` lines | Release lines |
| -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| 1 | 4.5 / 4.3 / 4.1 | 63 | 2 | 0 | 47 (2) | 25.8 (40.0) | 90 (156) | 2.25 | 293 | 65 |
| 2 | 2.6 / 11.4 / 9.9 | 65 | 0 | 1 | 48 (0) | 23.8 (35.8) | 87 (158) | 2.43 | 231 | 65 |
| 3 | 1.4 / 6.4 / 9.9 | 66 | 0 | 5 | 47.5 (0) | 23.5 (28.4) | 94 (246) | 3.31 | 371 | 65 |

Peak MB per direct link is the median peak divided by the mean direct links. It is a rough figure.

One earlier run on `6794bc6`, same build and conditions: 66 nodes with a census line, 2 with the full roster, 0 isolated, roster median 54 (min 34), mean links 20.3 (direct 36.5), peak 94 MB (max 153), 2.6 MB per direct link, 340 `re-graft` lines, and 141 release lines. That run is before the fix that makes a node release once (`6c3635a`). After the fix the release lines are 65 in every run, one per joiner.

What the numbers allow:

- The peak memory per link is about the same in all runs (2.2 to 3.3 MB). A higher peak at a higher link count can be the links. I have not shown that it is not a leak.
- The memory rise against the older run at `435031d` (peak median 73 MB, max 102 MB, mean 25.1 links) is not explained. The older run has no direct-link count, so its per-link value cannot be computed. It is also not known if that run was a debug build.
- The spread between runs is large. Run 3 is the worst on every row, and it is the run with the most stalls.
- No run is a clean answer. A clean answer needs a release build, a quiet host and no timer stalls.

### Rendezvous NeighborDown counts

The message of commit `932013a` says "Rendezvous NeighborDown over the run: 90 and 18", for N = 10 on UDP over 10 minutes, before and after the change. I measured it again at `d671e88`, which only adds the node id to the log lines. Host load 10 to 32, because other jobs shared the host.

| Run | Rendezvous NeighborDown | Rendezvous neighbor-up | Release lines |
| -- | -- | -- | -- |
| N = 10, 5 minutes | 9 | 10 | 9 |
| N = 10, 10 minutes | 9 | 10 | 9 |

Each of the 9 joiners has one neighbor-up of the rendezvous, one release and one NeighborDown of the rendezvous. The creator hosts the rendezvous and has a neighbor-up and no NeighborDown. So a NeighborDown of the rendezvous in this run is the release, and I could not find a second one per joiner. I do not reproduce the 18 of the earlier run, and I do not know what the other 9 were. Two guesses, neither shown: each joiner came back to the rendezvous once in the earlier run, or the count of that run included lines of the creator.

### Crash test under load

The crash test (`a_joiner_after_a_crash_still_gets_the_full_roster`, 18 nodes, `WebRTC` only) failed once in three full gates at a host load of up to 19, with the message "2 members came back and 1 let go again". It has failed on CI since the pin. It has failed locally 1 time in about 78 runs after the pin, and 0 times in 30 runs before it. A race between the release waiter and a new visit may explain the first failure. That is a guess, and it is not shown. The waiter is removed in `c31e97d`, and the test still fails on CI after that commit.

## Decision

A mesh member costs 0.4 to 1.1 MB, and the cost per member rises with N. Sending over a pooled connection costs at most about 0.2 MB.

At N = 65, the most that any limit on the unicast pool can save is about 7 MB per node. This is the 48 connections past a cap of 16, at about 0.15 MB each. The growth of the gossip-only reading is 50 to 65 MB above the idle size of 29 MB.

The reading at N = 65 is 79 to 94 MB, from runs with isolated nodes. Use it as a lower bound. An extrapolation from N up to 33 gives 53 + 32 × 1.06, about 87 MB.

A separate spike, not part of this document, reports that a peer past the cap keeps one QUIC connection over multihop. If this holds, the cap saves about 0 MB.

Gossip links and per-member state cost more than a cap on direct unicast connections saves. The WebRTC cap already exists. It limits the sessions to 16, which is about 3 MB at 0.2 MB per session.

Caveat: the figure at N = 65 is an extrapolation from N up to 33. No full mesh of 60 or more nodes formed.

## Choosing G and D from a memory budget

This section turns the measurements above into a rule for two caps. Phase 2 of the plan sets both caps and measures the rule with the committed harness. Until then, the rule uses only the numbers in this document.

### The two caps

- **G** is the size of the gossip active view (`max_peers`). The planned default is 32. Today it is 64 (`GOSSIP_ACTIVE_VIEW_CAPACITY` in `crates/habilis-network-util/src/tuning.rs`).
- **D** was the cap on WebRTC sessions. Decision D11 replaced it with **C**, the ceiling of direct connections, which counts WebRTC sessions and unicast connections together. The default is 64 (`MAX_DIRECT_PEERS`) and the setting is `max_direct`. See the section "The ceiling C of direct connections (decision D11)" at the end of this document. The text and the measurements below were made with D, before D11.
- D counted WebRTC sessions only. Plain QUIC connections were not counted, and no count cap limited them. The idle closes limited them in time: 120 s on the dial side and 240 s on the accept side. Today one backstop of 900 s (`DIRECT_IDLE_BACKSTOP_SECS`) replaces both.

G bounds a count. It does not refuse a member. The iroh-gossip fork (`src/proto/hyparview.rs`, `on_join` and `add_active`) always accepts a high-priority `Join` or `Neighbor` request. If the active view is full, it first drops a random active member, and that member gets a disconnect. It refuses only a low-priority `Neighbor` request at a full view. A burst of joins can therefore replace the neighbors of a node that is at G. The number of links stays at G or less, but the churn is not bounded.

### Sessions of the multihop underlay

The multihop underlay is an endpoint of its own, and it can hold WebRTC sessions too. A node opens one to a gossip neighbor only when its application path to that neighbor is WebRTC, that is, when the pair has no IP path. Where IP works, the underlay reaches the neighbor over IP, and the node opens no session. These sessions count in G, not in D. The underlay keeps its own table of sessions, with a cap of G, and a session exists only to a gossip neighbor. So a node holds at most D + G WebRTC sessions. In practice only neighbors that have no IP path add to the count.

This document has no reading with underlay sessions. As a planning value, take the cost of one underlay session as the cost of one session of D (0.2 MB). That is an assumption, and a measurement must confirm it.

### The formula

Peak resident memory of one native node, in MB, in a release build:

```text
RSS = 29 + 5 + G x 1.1 + D x 0.2 + C x 0.2
```

G and D are the caps. C is the number of live plain QUIC connections beyond the one that each gossip member already brings. The formula takes each cap as full. Each term comes from a measurement above:

| Term | MB | Source in this document |
| -- | -- | -- |
| Idle node | 29 | UDP, N = 2, gossip only: 29 / 29. The isolated WebRTC nodes sit at about 30. |
| Stacks | about 5 | WebRTC stack 3 to 4, multihop underlay 1.5 to 3 (Costs per peer). The sum is 4.5 to 7, so 5 is the low end. A node without WebRTC pays only the underlay. |
| One member of G | 1.1 | 1.06 per added member, N 17 to 33 (Main finding). The step N 8 to 17 gives 0.44. |
| One session of D | 0.2 | About 0.2 per added WebRTC session, net of the stack (Costs per peer). |
| One plain connection | at most 0.2 | Sending over a pooled connection (Costs per peer). |

Read the formula with these limits:

- The cost per member rises with N. The measured steps are 0.5, 0.44 and 1.06 MB, and the last step stops at N = 33. Above N = 33 the 1.1 is an extrapolation (see Decision).
- The result is a peak. It includes the burst at join time.
- The numbers are for native processes. A browser session costs more, and this document does not measure it.
- For a debug build, use 3.3 in place of 1.1 as the worst case. In the three N = 66 debug runs, the peak per direct link is 2.25, 2.43 and 3.31 MB. These figures divide the whole peak, idle size included, by the links, so they are an upper bound for the cost of one link. Those runs also had timer stalls (see above).

### G and D against RSS

Release build, C = 0. The last column holds the closest reading of this document.

| G | D | Formula (MB) | Reading, median / max (MB) |
| -- | -- | -- | -- |
| 7 | 0 | 42 | N = 8, UDP directed, 7 links: 32 / 32 |
| 16 | 0 | 52 | N = 17, UDP directed with multihop, 16 links: 41 / 42 |
| 32 | 0 | 69 | N = 33, UDP directed with multihop, 32 links: 60.5 / 65 |
| 64 | 0 | 104 | N = 65, UDP, 9 to 18 isolated nodes: 73 / 126 (multihop), 79 / 100 and 94 / 123 (gossip only). Use these as a lower bound. |
| 32 | 16 | 72 | no reading (the planned G with today's D) |
| 32 | 32 | 76 | no reading (the planned defaults) |

The formula is above every median in the table. At G = 64 it is below the largest maxima (123 and 126). Those come from runs with isolated nodes, and from one run that this document does not explain. Use the formula as a planning ceiling for the median node. It is not a limit for the worst node.

The WebRTC N = 17 run is the one reading with sessions. A node holds 14.1 gossip links and 15.0 sessions, and reads 44.5 / 46 MB. That run has no underlay, so its stack is 3.5 MB. The formula gives 29 + 3.5 + 14.1 x 1.1 + 15.0 x 0.2, which is 51.0 MB. This is 6.5 MB above the median and 5 MB above the maximum. The single cost of 1.1 for all 29 peers gave 64 MB. Most of the remaining gap is the 1.1, because a member costs 0.44 at N 8 to 17. With 0.44 the formula gives 41.7 MB, which is below the reading.

To choose the caps from a memory budget of B MB, solve the formula for G:

```text
G = (B - 34 - 0.2 x (D + C)) / 1.1
```

With C = 0, B = 128 gives G = 85 for D = 0 and G = 79 for D = 32. B = 64 gives G = 27 and G = 21. A session or a plain connection costs only 0.2, so B = 128 and G = 32 leave room for 294 of them together (D + C). The planned defaults, G = 32 and D = 32, give about 76 MB for the median node in a release build.

### What this section does not measure

- The number of live plain connections under load. The harness census has no count of them.
- Sessions over time and refusals at the cap of D. No run formed a WebRTC session (see the next section).
- A full mesh above N = 33. No earlier run formed one.
- The cost of a session of the multihop underlay. See the section on those sessions above.

## Phase 2 measurement with the committed harness

The runs use `scripts/perf/` and the example `mesh_peer_load` from commit `b6b2d4a`, in a release build. Each node is one process, all on one host with 10 cores, with a local relay. G = 32 and D = 32 unless the table says otherwise. Each run is 240 s with traffic on, which is one directed message per second to every peer. The load column is the median 1-minute load of the host during the run.

| Run | Load | Full rosters | RSS median / max (MB) | Link ups / downs | Ups per member per min |
| -- | -- | -- | -- | -- | -- |
| N = 48, three runs | 217, 237, 220 | 48 / 48 each | 113 / 251, 112 / 268, 121 / 276 | 43585 / 42120, 40833 / 39381, 47549 / 46131 | about 216, 202, 236 |
| N = 48, traffic off | 192 | 48 / 48 | 113 / 234 | 34837 / 33378 | about 173 |
| N = 66 | 120 | 37 / 66 | 138 / 234 | 3506 / 1899 | not valid |
| N = 24, G = 32 | 5.3 | 24 / 24 | 46 / 69 | 611 / 58 | about 0.6 after the formation |
| N = 24, G = 8 | 20 | 24 / 24 | 59.5 / 85 | 9362 / 9194 | about 93 |

How far to trust each number:

- **The N = 48 and N = 66 runs ran on a starved host.** The load was 190 to 250 on 10 cores, with 48 to 66 processes, a Time Machine backup and the Tailscale network extension. Trust only the roster result (every node had a full roster, no node was isolated, no stall). Do not trust the link counts and the link churn: a node that misses keepalives drops links.
- **The N = 48 RSS is an upper reading.** The median is 113 MB, above the formula (about 78 MB). Starved nodes can hold more buffered data. The N = 24 run at low load reads 46 MB, below the formula (64 MB).
- **The N = 66 run is not valid.** Only 37 of 66 nodes had a full roster, with 395 stalls and a longest stall of 111 s. It does not measure the mesh.
- **The N = 24, G = 32 run is the clean run.** The load stayed low. Every node held 23 links, which is a full mesh, so no view was full. Its churn, 0.6 per member per minute, is not a reading for a full view.
- **The N = 24, G = 8 run has full views at a load of 20.** The churn is about 93 per member per minute. The load is not low, so this does not prove the churn at a full view. For comparison, the earlier N = 8, G = 4 run has 3.1 per member per minute. The churn at a full view seems to grow with N. A run below load 5 must confirm it.

### IP blocked

The driver starts the creator with the transport list `udp,multihop` unless `MESH_TRANSPORT` or `MESH_TRANSPORTS` says otherwise. This list holds no `webrtc`. Two runs with IP blocked at 60 s show two different cases.

**With `webrtc` in the list** (`MESH_TRANSPORTS=udp,webrtc,multihop`, N = 6, G = 3, D = 8, 180 s): the sessions form. Each node holds 5 or 6 sessions, the mean links are 2.2 to 3.0, and the largest RSS is 70 MB.

**Without `webrtc` in the list** (N = 24, G = 8, D = 8, 300 s): no session can form, and the run is bad.

- No node had a full roster at the end (0 / 24). One node was isolated.
- Memory rose on many nodes. The RSS median is 370 MB and the maximum is 6711 MB. One node went from 57 MB to 3248 MB in 15 s, peaked at 6684 MB, and fell to 73 MB after about 80 s. Fourteen other nodes peaked between 313 and 1721 MB.
- Two repeats with a guard that stops the run at 2 GB reproduced it (a node reached 2022 MB and 2152 MB). N = 6 does not show it.
- A heap profile of a growing node at 386 MB holds 482234 allocations, 309 MB, of 640 B each, all from `Box<[T]>::clone`. The CPU sample of the same node is in `iroh::socket::remote_map::remote_state::State::open_path_on_conn` of the iroh fork.
- The cause is proved, see the next section.

### The memory growth: cause, fix and result

The iroh fork queued a path open for a later attempt when a connection had no free path id. The timer (333 ms) takes the whole queue and opens every address on every connection of the remote again, and each connection that still had no free path id queued the address once more, with no check for a copy. With C such connections the queue grew by a factor of C at every attempt. The log of its length on one node reads 140, 268, 524, 1036, ... 262156 entries in 5 s, and it reached 3.5 million.

The fix queues an address once (iroh PR #2, `51e891c`). The same run (N = 24, G = 8, IP blocked at 60 s) with only that change: the largest queue is 13 and the largest node uses 96 MB, where it was stopped at 2091 MB before. It also happened with IP open (N = 24, G = 8, `udp,webrtc,multihop`, traffic off): 5.2 GB and 7.9 GB on one node before the fix.

On the pinned build `370e91a` (N = 24, G = 8, traffic off, 240 s, guards at 2 GB per node and 8 GB in total, no alert): the largest node uses 77 MB (median 50.5 MB), 1231 MB in total, and 24 of 24 rosters are full.

### Link churn at full views: cause, fix and result

At N = 24 and G = 8 the links changed about 70 times per member per minute at a low load (7112 link-ups in a run of 240 s). Two causes:

- A `PeerInfo` flood was allowed once per window for each neighbor, so every new link made a new flood, and every peer that heard it grafted. The window now follows the flood (`5e8bece`, `44c6ab6`).
- A graft was a `Join`. A peer with a full view always accepts a `Join` and drops a random neighbor, so a graft at a full view moved two links. A graft now asks with low priority (`NeighborPeers` in iroh-gossip, `fb5a9b2`): a full peer refuses it and keeps its neighbors. The rendezvous still gets a `Join`.

Result, same setup, three builds of one fork chain: 70 link-ups per member per minute (`370e91a`), 73 with only the fix for a stuck pending answer in the fork, and 0.8 after the first links with `fb5a9b2` (275 link-ups, 192 of them the first links). The largest node uses 68 MB, and 24 of 24 rosters are full. The mean number of links per member at the end is 7.75 of 8, and the last member to start held 6 for the whole run: every other peer was full, so its requests were refused.

The test `a_mesh_of_twelve_with_g_four_has_a_bounded_churn_after_formation` has the numbers for N = 12 and G = 4: 2.3 (`f6c3673`, fails), 1.6 (`328b187`) and 0.0 (`fb5a9b2`) link-ups per member per minute.

### Known limits

- **The lane pair was never detached.** Before D11, a pair that needs the `WebRTC` lane (a browser, or a node without UDP) was never held back and never detached, so such pairs held their sessions for ever. D11 solves this: see "Lane peers" in the section on C.
- **D and the idle detach were not exercised at scale.** The sessions form at N = 6 (5 or 6 per node), but no run hit the cap D, and no run showed a detach of 120 s. The detach has unit tests and one test with a real connection.
- **The last member to start can stay under-filled.** With no eviction, a member that arrives when every other member is full gets no link from its requests. The mean stays at 97 percent of G in the run above.
- **The `PeerInfo` graft leaves one slot free** in a mesh larger than G + 1 (`peer_info_graft_below`). Its reason, a graft that evicts, is gone since the graft is a low priority request. It is kept because every measurement above was made with it.

## The ceiling C of direct connections (decision D11)

D11 replaces the cap D with one ceiling C. A node never refuses an offer or a connection because of C. It evicts the least valuable peer when a newcomer needs the place. The numbers in this section are design values and test results. The memory of a node with C in place and the generous windows is **not measured yet**: it needs a run on a free host.

### What C counts

A peer is one unit when the node holds a unicast QUIC connection to it, or a `WebRTC` session to it while it is not a gossip neighbor. A gossip neighbor is held by its gossip link, so its session is not a unit. The gossip connections and the multihop underlay are not counted. The default of C is 64 (`MAX_DIRECT_PEERS`). The setting is `max_direct`. It replaced `max_sessions` at the same place in the C struct (offset 64, 72 bytes), so the meaning of the field changed but not its layout.

### The ledger

The ledger is a pure type, `Ceiling` (`crates/habilis-network/src/transport/ceiling.rs`). The admission table (`SignalAdmission`) holds one, and every QUIC connection of the endpoint reaches it through the connection hook. Its rules:

1. **An eviction is triggered only by an admission.** A unit that is added, or a peer that stops being a neighbor, can evict. A timer never evicts, except the backstop below. The refusal of the offer of a peer that was evicted lately is not an eviction. A node at C with no newcomer is quiet. Test: `a_fifth_unicast_connection_at_a_ceiling_of_four_evicts_the_least_recently_used` ends with exactly one eviction and no other.
2. **The order of the victims.** A peer that was idle for 30 s or more goes first, the least recently used first. A peer younger than 60 s goes last. A peer with a send or a stream in flight is never a victim.
3. **If every candidate is busy, the newcomer is admitted** and the count is over C by the number of busy units. The gauge `over_ceiling` in the census line says so. Test: `when_every_connection_is_busy_the_newcomer_is_admitted_over_the_ceiling`.
4. **A batch down to 90 percent of C** (rounded up) runs with an admission, at most once in 5 s, so that the next admissions do not each evict.
5. **The backstop.** A connection or a session that nobody used for 900 s closes. The session and the unicast connection of the same idle peer close together, at 900 s. It is the one idle timeout of the direct connections. A session reads its last use in the ledger, so it goes 900 s after the last use, and no second window is added when its connection has closed.
6. **A unit ends with its last connection.** When the last unicast connection of a peer closes, for any reason, the peer leaves the ledger, so a connection that closed by itself never keeps the count at C.

**A busy sender.** A node that sends to more than C peers in rotation makes each target evict one of its own idle units for every send, and the sender pays one dial per send. The rules of the order protect the hot connections: the victims are idle ones, and a unit younger than 60 s goes last. Only members of the mesh pass the admission gate, so a stranger from outside cannot cause an eviction. A misbehaving member can, and it pays for it with its own dials.

An eviction closes the unicast connections of the victim with the close code `EVICTED` (11) and detaches its session. The victim reads the code and, for 60 s (with a jitter of 20 percent), makes no proactive dial to the evictor: no direct-path probe and no offer of a session. A send to the evictor dials at once, and a frame held for a lane peer counts as a send. The path nudge is not held, because it opens no unicast connection and takes no unit.

### Lane peers

A pair that needs the lane has no direct path without a session. On a mesh whose relay is lookup only, a frame to such a peer is held. The held frame marks the peer wanted for 60 s, and the wanted peer is offered a session. When the session attaches, the held frames are flushed. If the higher id of the pair holds the frame, it offers at once. When both ids offer together, the lower id wins: the higher id gives its offer up and answers. An idle lane peer gets no session and loses an unused one at the backstop. On a mesh whose relay carries payload, the send goes over the relay and nothing is held.

### The underlay leg

The underlay keeps its own ledger with G as its ceiling. Before D11, that table refused the session after the G-th. Now it evicts at G. The leg opens a session only to a gossip neighbor, so its count stays at G or less, and the ledger does not act. Test: `a_ledger_with_g_as_its_ceiling_never_evicts_while_the_sessions_stay_within_g`.

### Generous windows of one connection

The count C is the real limit. Every endpoint of the engine, the multihop underlay and the blob endpoint included, also sets three generous windows (`build_endpoint`), so that one connection cannot grow without bound:

| Window | Value |
| -- | -- |
| One stream, receive | 16 MiB |
| All the streams of a connection, receive | 16 MiB |
| Send, bytes not yet acknowledged | 16 MiB |

The stream counts, the datagram buffer, the keep-alive, the idle timeout and the multipath settings stay at the iroh defaults. The iroh default is about 1.2 MiB for a stream. The window of a stream is the window of the connection, so one blob stream can use the whole window. A window allows one window per round trip, so 16 MiB at 100 ms is about 1.3 Gbit/s. The 16 MiB window of a connection is tighter than the iroh default, which is unbounded. The 16 MiB window of a stream is looser than the iroh default of about 1.2 MiB. The worst case for one connection is 32 MiB: 16 MiB to receive and 16 MiB to send. The gossip links share the endpoint config, so the bound for the node is base + (G + C) x 32 MiB, about 3 GiB at G = 32 and C = 64. A node reaches it only if every peer is a slow reader and a slow acknowledger at once. A real node stays far below it. Two tests show the windows: a receiver that never reads takes in about 16 MiB of a stream, and 40 unread streams take in about 16 MiB together. The windows were 8 MiB for a stream and 32 MiB for the connection and for sending until the user lowered them to 16 MiB; the runs below were taken at the earlier values. The flood mode of the harness (`MESH_FLOOD_PEERS`) measures what one connection costs.

### Keep-alive cost

iroh sends a heartbeat on each connection every 5 s. At C = 64 and G = 32, that is 96 connections and about 19 packets per second when the node is idle. This number comes from the iroh default and from the sum. It is not measured here.

### RAM after D11

The formula above holds with C in place of D for the sessions and connections. One connection can add up to 32 MiB in the worst case: 16 MiB to receive and 16 MiB to send (see the windows above). The cost of a busy connection is not measured: the flood run does it, and it is not done yet.

### Not measured yet

- The memory of one busy connection, with the flood run at K = 1, 4 and 11 peers, and how near to 32 MiB it gets.
- The rate of evictions per member per minute at N = 24 with C = 8, and the share of pooled closes that are followed by a re-dial with C = 64.
- A mesh of two nodes with real `WebRTC` sessions at the ceiling is tested only with loopback sessions in the unit tests.

## D11 gate runs, 2026-10-07

One host (a Mac shared with other work), release build of `mesh_peer_load`, native processes. The QUIC windows of these runs were 8 MiB for a stream and 32 MiB for a connection and for sending, the values before the user lowered all three to 16 MiB: the numbers below are not rerun at 16 MiB. The load is the 1-min load average of the host at the start of the run, and the reading is the only control: the host was busy with Spotlight and `spindump` before 12:25, which is not our load. Nothing of this is a result at scale: N is 12 or 24.

| Run | HEAD | N | G | C | Time | Load1 at start |
| -- | -- | -- | -- | -- | -- | -- |
| Gate loopback (2 tests) | 48cfd2b | 4 and 2 | default | 2 and default | 12:22-12:25 | 4.3 |
| Flood, 6 runs | 48cfd2b | 12 | 8 | 64 | 12:25-12:42, 150 s each | 1.5 to 12.7 |
| Bursty | 48cfd2b | 24 | 8 | 64 | 12:44-12:59, 900 s | 1.8 |
| Bursty | 48cfd2b | 24 | 8 | 8 | 12:59-13:15, 900 s | 1.6 |
| Session flood K = 4 | 48cfd2b | 12 | 8 | 64 | 13:15-13:25, 600 s | 3.1 |
| Lane test, before the fix | 7fd7356 | 2 | default | default | 12:42-12:44, 3 runs | 1.6 to 2.7 |
| Lane test, after the fix | 3d2eb45 | 2 | default | default | 13:32-13:35, 3 runs | 4.2 |

### The ceiling at C = 2 (loopback test)

`a_node_at_a_ceiling_of_two_delivers_every_frame_while_it_evicts`: alice, with C = 2, sends in rotation to three peers, three rounds. Every frame arrived. After each send the ledger of alice counted 2 direct units, and `over_ceiling` was 0 at the end. Passed in about 70 s.

### Flood: the cost of one busy connection

Every node floods frames of 3000 bytes to its first K roster peers from second 30. RSS in MB, from the per-second guard log of the 12 nodes. The idle node is 32 to 35 MB. The guards (2000 MB per node, 8 GB in all) never fired.

| Path | K | Peak of any node | Median of nodes, highest reading |
| -- | -- | -- | -- |
| quic (UDP open) | 1 | 54 | 39 |
| quic | 4 | 79 | 48 |
| quic | 11 | 46 | 35 |
| session (UDP cut at 20 s) | 1 | 52 | 40 |
| session | 4 | 90 | 44 |
| session | 11 | 54 | 42 |

The run of session K = 4 was repeated for 600 s. Its top node (n4) read 56, 57, 57, 54, 41, 41, 41, 42 and 42 MB at one-minute marks, with 1, 3, 4, 2, 2, 1, 1, 0 and 1 live direct units. It peaked at 57 MB, stayed there for about 4 minutes, and fell back to 41 MB: no growth, so no sign of a leak. 57 minus the 35 MB of an idle node is about 22 MB for at most 4 live units, about 5 MB for each, far under the bound for one connection (64 MiB at the windows of that run, 32 MiB at the windows of today). The peak of 90 MB of the 150 s run did not come back, and its cause is not known.

### Bursty at N = 24

Every 60 to 240 s, a node sends one message to each of 3 to 5 random peers. Closes and re-dials are per node per hour, from the counters of the per-second line.

| | C = 64 | C = 8 | Before D11 (earlier runs) |
| -- | -- | -- | -- |
| Nodes with a full roster | 24 of 24 | 24 of 24 | |
| Direct units, highest on any node / mean | 22 / 12.8 | 8 / 6.3 | |
| `over_ceiling`, highest | 0 | 0 | |
| Evictions, all nodes | 0 | 585 | |
| Evictions per member per minute | 0 | 1.6 (busiest node 2.7) | |
| Pooled closes / re-dials / share | 0.0 / 0.0 / 0.00 | 64.8 / 14.4 / 0.22 | share 0.26 |
| Session closes / share of re-dials | 2.6 / 0.00 | 3.1 / 0.05 | share 0.25 |
| QUIC closes, gossip links included / share | 90.8 / 0.68 | 257.7 / 0.72 | 167.7 / 0.56 and 349.2 / 0.81 |
| Gossip link-ups and link-downs | 280 and 89 | 275 and 84 | 302 and 113, and 284 and 93 |
| RSS, median / highest node (MB) | 47 / 78 | 47 / 75 | |
| Load1, median / highest | 3.0 / 6.4 | 3.7 / 14.6 | |

### The lane pair (webrtc-only mesh, every pair needs the lane)

`a_lane_pair_delivers_a_frame_sent_as_soon_as_the_roster_forms`, from the roster to a frame in each direction.

| Build | Result | Time from the roster |
| -- | -- | -- |
| 48cfd2b | failed after 120 s: no member link formed | |
| 7fd7356 | 3 of 3 passed | 28.4, 28.1, 28.1 s |
| 3d2eb45 | 3 of 3 passed | 2.0, 2.4, 2.3 s |

At 48cfd2b an unmeshed node parked a frame without asking for the session of its peer, and a node is meshed only by its first member link, which a lane pair makes with a session. At 7fd7356 the frame asked, but the offer waited for the next 30 s tick of the retry pass. At 3d2eb45 the offer goes out when the frame is parked.

### What these runs do not show

- **One RSS for each node.** Every node floods and receives at once, and the example prints one RSS for the node. The sender and the receiver cannot be told apart.
- **The idle backstop.** The bursty runs last 900 s, which is the backstop. A pooled close for idleness could not happen in that window. Pooled closes of 0 at C = 64 say that nothing thrashed, not that the backstop works. The backstop has unit tests with a paused clock.
- **Gossip link churn.** Link-ups and link-downs are the same as in the runs before D11. Per the review of trade-march (97f7c1f4) they are mostly the formation of the mesh. They were not split by time here.
- **Different commits.** The older runs in the last column are labelled by their folder, and are not from one commit.
- **The workflows.** The nightly (`cargo task matrix`) has not run on CI.

