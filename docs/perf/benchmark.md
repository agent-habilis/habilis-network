# Transport throughput

`cargo task benchmark` moves one bulk transfer over one QUIC bi-stream
between two iroh endpoints, in every pairing the WebRTC lane has, and reads
the result against two ceilings: plain iroh on UDP, and a bare data channel
with no QUIC in it. The question it was built to answer: is the
iroh↔WebRTC integration the bottleneck, and is the double encryption (DTLS
outside, QUIC TLS inside) the reason?

The short answer: **no, and no**. Browser↔browser, habilis-network reaches the data
channel's own per-message ceiling. Native↔native over str0m, the driver's
CPU goes to one UDP syscall per packet, and a long connection loses speed
for a reason below the transport that is not yet found. The inner
encryption is under 2% of native CPU, and about a quarter of the browser
tab's wall time — half of its busy time — but the tab is half idle, so it
does not set the throughput.

## Method

- One transfer per round, each on a new bi-stream of one QUIC connection.
  One warm-up round is discarded because the first transfer pays the
  handshake and the congestion-window ramp (measured: 34 Mbit/s on the raw
  channel's first round, 460 Mbit/s after).
- Timed on the receiving side only, from stream open to the last verified
  byte. The check compares 251-byte chunks against one block (0.16 ms for
  8 MiB), so it is not a measurable part of the window. The JSEP round is
  timed separately (`JSEP ms`) and is not in the window.
- Every cell asserts the path that carried it (`webrtc` / `ip` /
  `data-channel`), so a cell cannot quietly measure the wrong lane.
- Browser cells run each tab in its own browser process: Chrome for
  Testing over CDP, and Safari Technology Preview over
  W3C WebDriver, the same client the e2e suites use. This runner ferries the
  SDP between tabs. Host-only ICE, no STUN.
- STP needs *Settings ▸ Developer ▸ Allow remote automation* and a one-time
  `sudo safaridriver --enable` (the STP copy of the binary). A running STP
  copy can hang the session handshake; quit it and run again.
- Protocol and pages: `habilis_network_iroh_webrtc_transport::bench`,
  `crates/habilis-network-bench-wasm`. Runner: `tasks/src/bench.rs`.

```sh
cargo task benchmark                         # the matrix, 8 MiB × 5 rounds
cargo task benchmark --only native --rounds 20 --json target/bench.json
cargo task benchmark --only safari           # the two STP cells
cargo task benchmark --direction up          # or `both`
```

With `--direction both`, a sample counts the bytes of both directions, so its
rate is the total of the two. The JSON's top-level `bytes` is the requested
size, and each sample's `bytes` is twice that.

## Results

Apple M5, macOS 27.0, rustc 1.95.0, Chrome for Testing 152.0.7977.42.
8 MiB downloads, 5 timed rounds, two runs. `Mbit/s` is decimal megabits per
second, the median of the rounds; the range is min–max across both runs.

| cell | path | Mbit/s run 1 | Mbit/s run 2 | range | JSEP ms |
|---|---|---|---|---|---|
| habilis-network chrome-chrome | webrtc | 266 | 249 | 209–277 | ~970 |
| habilis-network chrome-native | webrtc | 166 | 164 | 121–171 | ~620 |
| habilis-network native-native | ip | 2215 | 2186 | 1788–2389 | 0 |
| habilis-network native-native (webrtc-only) | webrtc | 76 | 79 | 64–104 | 5 |
| iroh native-native (baseline) | ip | 1862 | 2392 | 1018–2404 | 0 |
| webrtc chrome-chrome (raw, 64 KiB msgs) | data-channel | 466 | 463 | 364–478 | ~690 |
| webrtc chrome-chrome (raw, 1200 B msgs) | data-channel | 258 | 255 | 249–273 | ~710 |

The Safari cells, one run of 2 timed rounds each. safari-native is measured
over WebDriver (range 81–123). safari-chrome is from the earlier
`safaridriver --mcp` driver, on a machine loaded to a load average of 20–30,
so read it as a lower bound until a rerun:

| cell | path | Mbit/s | JSEP ms |
|---|---|---|---|
| habilis-network safari-native | webrtc | 102 | ~610 |
| habilis-network safari-chrome | webrtc | 102 | ~950 |

Until this revision every round opened a new connection, so every timed
round paid the handshake and slow start. That hid one cell: on a new
connection per round, webrtc-only measured 136–153 Mbit/s; on one reused
connection it measures 64–104. The other cells did not move outside their
run-to-run spread.

Notes on the cells:

- `habilis-network native-native` is the engine's wiring for two native peers: the
  WebRTC transport is registered beside UDP and the selector prefers direct
  IP. It equals the iroh baseline, so registering the transport costs
  nothing on the UDP path.
- `habilis-network native-native (webrtc-only)` is str0m at both ends. It is the
  only native cell that goes through the data channel, and it has the
  widest spread.
- The raw channel is ordered and reliable (the default). The transport's
  channel is unordered and unreliable, with QUIC doing the recovery. The
  64 KiB row is what the browser can move; the 1200 B row is the same
  channel used the way the transport uses it, one QUIC datagram per SCTP
  message. The 1200 B raw row was added after run 1.

## Reading

**Browser↔browser.** habilis-network (209–277 Mbit/s) equals the raw channel at
1200-byte messages (249–273 Mbit/s). The integration adds nothing
measurable on top of the channel's per-message cost.

The cost is not the number of messages. It is how each message fits into
SCTP packets. A sweep of the raw cell's message size (one run each, median
Mbit/s):

| message bytes | 1000 | 1062 | 1100 | 1150 | 1160 | 1170 | 1200 | 1500 | 2048 | 4096 | 8192 | 16384 | 65536 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Mbit/s | 407 | 429 | 439 | 446 | 440 | 253 | 256 | 315 | 411 | 419 | 468 | 467 | 468 |

Throughput halves between 1160 and 1170 bytes. Past that size, Chrome's
SCTP sends each message as one full packet and one small packet. A QUIC
packet is at least 1200 bytes, so every datagram the transport sends is
past the limit. There are two ways out:

- Put several QUIC datagrams into one data-channel message. At 8 KiB or
  more the channel reaches its 64 KiB ceiling. This is a change inside the
  transport. The cost is loss amplification: one lost SCTP packet loses the
  whole message.
- Make QUIC datagrams on the WebRTC path larger, with the same loss cost.
  This is an MTU question for iroh's path configuration.

**Native (str0m).** 64–104 Mbit/s on one reused connection, below the
browser. It was 135–182 when each round used a new connection, and the
transport's outbound and inbound queues drop nothing in either case, so the
loss of speed on a long connection is below the transport: SCTP's own
congestion control under QUIC's, or UDP loss, is not yet measured. A 15 s
`sample` of the runner during the webrtc-only cell (80 rounds, a new
connection each, before this revision) puts the driver task's busy time at
roughly: `sendto` 70%, `recvfrom` 12%, `str0m::Rtc::poll_output` 7%, and
both AEADs together (ring `aes_gcm_*` for QUIC, aws-lc `aesv8_gcm_*` for
DTLS) under 2%. The cost is one blocking
`UdpSocket::send_to` per SCTP packet in `native/driver.rs`; batching sends
is the lever there.

**Browser CPU.** A 12 s Chrome sampling profile of the client tab during
chrome-chrome (attached over one long-lived CDP session; `agent-browse cdp` is
one-shot and cannot hold profiler state):

| share of wall time | what |
|---|---|
| 50% | idle |
| 27% | QUIC packet protection: `aes_nohw_encrypt_batch`, `aes_nohw_sub_bytes`, `gcm_mul64_nohw` |
| 15% | other wasm (5% is `curve25519` handshakes: the profile predates the reused connection) |
| 5% | `(program)` |
| 3% | JS glue |

`ring` has no hardware AES on wasm32, so the inner layer is bit-sliced
software AES-GCM. It is about half of the tab's busy time. Removing it
would cut renderer CPU, which matters under main-thread pressure and on
slow devices, but on this machine the tab is half idle and the number does
not move: the ceiling is in Chrome's network process, where SCTP and DTLS
run, and the tab profile does not see it.

## The path ladder

The `ladder` cells put one cell on each rung of the path ladder, with the
same bulk transfer and a round-trip probe. They are native only and run on
loopback, so they measure what each transport costs and not what a real
network adds. `cargo task benchmark --only ladder` runs them.

| cell | what carries the bytes |
|---|---|
| ladder udp | plain iroh on loopback UDP |
| ladder webrtc | str0m at both ends, the data channel is the only path |
| ladder multihop (direct) | two multihop nodes with one underlay link between them |
| ladder multihop (via third) | the same two nodes with a third member between them |
| ladder relay | no IP transport on either side, one local relay between them |

**Method.** Throughput is measured as in the cells above: one reused
connection, one discarded warm-up round, then the timed rounds. The round
trips follow on the same connection. One probe is one bi-stream with a
1 KiB request and a 1 KiB echo, timed on the client from stream open to
the last echoed byte. 50 probes are discarded and 1000 are timed. RTT p50
and p99 are nearest-rank percentiles of the 1000.

Each cell checks the path that carried it, and takes the path iroh selected,
not any path that was open. The via-third cell also fails if the third member
forwarded no cells, so it cannot report a direct number under its name. The
relay is `test_relay::spawn_plain` in the same process, over plain HTTP.

Apple M5, macOS 27.2, rustc 1.95.0. 8 MiB downloads, 5 timed rounds, two
runs. Load average was 3.95 at the start of run 1 and 11.70 at the start of
run 2, with other agents sharing the host. `Mbit/s` is the median of the
rounds. The range is min–max across both runs.

| cell | path | Mbit/s run 1 | Mbit/s run 2 | range | RTT p50 ms (run 1, 2) | RTT p99 ms (run 1, 2) |
|---|---|---|---|---|---|---|
| ladder udp | ip | 2176 | 2141 | 2111–2197 | 0.04, 0.04 | 0.06, 0.06 |
| ladder webrtc | webrtc | 70 | 74 | 63–101 | 0.11, 0.11 | 0.15, 0.15 |
| ladder multihop (direct) | multihop | 871 | 841 | 788–887 | 0.12, 0.12 | 0.16, 0.15 |
| ladder multihop (via third) | multihop | 441 | 430 | 403–449 | 0.24, 0.25 | 0.30, 0.53 |
| ladder relay | relay | 1813 | 1752 | 1600–1830 | 0.08, 0.08 | 0.12, 0.11 |

**Reading.**

- UDP is the ceiling on both measures. The webrtc cell matches the
  webrtc-only cell above (64–104 Mbit/s), so the path ladder adds nothing
  to it.
- Multihop with a direct link carries 40% of the UDP throughput and adds
  0.08 ms to the median round trip. The cause is not measured. One
  possibility is that every packet is wrapped and carried by a second
  QUIC connection, the underlay.
- A third member halves multihop again (about 435 Mbit/s) and adds about
  0.2 ms to the median round trip, against 0.08 ms for the direct link.
  This is the cost of one forwarding member. Do not read the two numbers as
  per-hop constants: no cell has two or more forwarding members.
- The p99 of the via-third cell was 0.30 ms in run 1 and 0.53 ms in run 2.
  The host was busier in run 2. This single value is not a result.
- The relay cell is fast because the relay is on the same machine. Do not
  read it as the speed of a real relay. Only its order against the other
  rungs on loopback is a result.
- The gossip rung has no cell here. It needs the gossip transport (Phase 6).

## The gossip backup path

`cargo task benchmark --only 'gossip backup'` measures what a gossip path costs
the mesh while it is open but not selected, because a pair stands on IP. The
question: does an open backup path put frames on the topic, and how many?

**Method.** N members share one in-memory flood: every frame that one member sends
reaches every other member, as a gossip broadcast does. Two of them are real iroh
endpoints, A and B, with IP on loopback and the gossip transport beside it, and
the path ladder ranks IP first. A dials B with the IP address and the gossip
address. The control run gives the IP address only. After 3 s to settle, the
pair idles for 30 s, then moves 5 timed rounds of 8 MiB over IP. The run counts
the frames each member puts on the topic and reads, the datagrams that iroh sent
and received on the gossip path (`Path::stats`), and the lost packets of the
connection at both ends.

Apple M5, macOS 27.2, rustc 1.95.0, the runner's `bench` build. One run. Load
average 1.96 at the start. N = 8 and N = 32 gave the same numbers.

| | gossip path open under IP | control, IP only |
|---|---|---|
| selected path | ip | ip |
| gossip path open | yes | no |
| datagrams on the gossip path in 30 s (tx, rx) | 8, 8 | none |
| lost packets on the gossip path | 0 | none |
| frames on the topic in 30 s | 16 | 0 |
| frames out per second, A and B each | 0.27 | 0 |
| frames in per second, each bystander | 0.53 | 0 |
| bytes in per second, A and B each / each bystander | 26 / 51 | 0 |
| frames on the topic during 40 MiB of bulk | 0 | 0 |
| lost packets during bulk, at A and at B | 0, 0 | 0, 0 |
| throughput, median of the rounds (min–max) | 1803 Mbit/s (1682–1864) | |

**Reading.**

- With IP selected, an open gossip path costs one 96-byte frame per 3.7 s in each
  direction (66 bytes of header and a 30-byte datagram, so a QUIC probe or a
  keepalive). It carried no payload: the bulk put 0 frames on the topic.
- The cost of one pair does not depend on N. Every frame reaches every member, so
  the cost for one member is the number of such pairs times 0.53 frames/s. If every
  pair had an open backup path, that is about 15 frames/s (1.4 KB/s) per member at
  N = 8 (28 pairs) and about 264 frames/s (25 KB/s) at N = 32 (496 pairs). These two
  figures are arithmetic from the measured rate. They were not measured.
- This is the traffic that `GossipHandle::allow(dst, false)` stops. A pair that a
  higher rung carries has no use for the gossip path, so the engine blocks its
  frames. The lookup rule alone does not remove it, because iroh also opens a
  learned custom address as a backup path.

**Limits.** One run, and one pair in the group. The flood is all-to-all and in
memory: a real gossip topic builds a tree and adds lazy `IHAVE` messages and
delay, so frames per member would differ. The idle window is 30 s, so a probe
interval longer than that would not show. The lost packets here are those of the
IP path. The inner QUIC retransmits of a pair that gossip carries come with the
gossip-only cell.

## The gossip rung

`ladder gossip` measures a QUIC connection that gossip carries, over the real iroh-gossip topic (not an in-memory flood). Three members, A, B and C, join one
topic over IP. A has the `IPv6` loopback only and C has `IPv4` only, so A and C cannot send each other an IP packet. A dials C with the gossip address alone,
and every packet of the connection is a frame that B reads and passes on. B has both address families and holds the gossip links. `cargo task benchmark --only 'ladder
gossip'` runs it, and it is skipped, with the reason, on a machine that cannot bind `::1`.

Apple M5, macOS 27.2, rustc 1.95.0, the runner's `bench` build. One run, 8 MiB downloads, 5 timed rounds after 1 warm-up, then 50 + 1000 round trips. Load average
2.55 at the start.

| | ladder gossip |
|---|---|
| selected path | gossip |
| throughput, median of the rounds (min–max) | 732 Mbit/s (670–815) |
| round trip p50, p99 | 0.17 ms, 0.27 ms |
| frames originated (A and C together) | 46052 |
| frames received (all members together) | 91814 |
| flood amplification (received over originated) | 1.99 |
| bytes out: A, C | 3.36 MB, 57.2 MB |
| bytes in: A, B, C | 56.8 MB, 60.5 MB, 3.36 MB |
| frames out at C, frames in at A | 38781, 38523 |
| lost packets of the inner QUIC connection: at A, at C | 0, 249 |

**Reading.**

- A connection that gossip carries moves 732 Mbit/s and answers in 0.17 ms at the median, on loopback. Beside the other rungs of the ladder table above, that is below IP (2141–2176
  Mbit/s) and the relay (1752–1813), and above multihop through a third member (430–441). The round trip is in the range of multihop (0.12–0.25 ms). These are
  loopback numbers: there is no network time in them, and they say what the transports cost, not what a network adds.
- The flood costs what a flood must. Each frame reached both other members: amplification 1.99 against the expected N−1 = 2 at N = 3. B only reads and passes frames on,
  and it received 60.5 MB, more than the 50.3 MB that A downloaded (6 transfers of 8 MiB) because the flood also carries the acknowledgements and the round-trip probes. The cost of a gossip
  pair is paid by every member, in proportion to the bytes the pair moves.
- Frames cost a header of 66 bytes each on frames that average 1474 bytes (C's bytes out over its frames out): 4.5%.
- The inner connection lost 249 packets at C, the sender of the bulk, and none at A. C put 38781 frames on the topic and A read 38523: **258 fewer**, which matches the 249 lost packets within 9.
  So in this first run the topic delivered about 0.65% fewer frames than were sent, and QUIC recovered them by retransmitting. Three more runs, below, say where they are lost.
- The inner QUIC did not collapse under 0.4% to 1% loss on loopback. This is no proof about a real network, where the outer connection's retransmits and the inner ones can stack:
  the concern in the design (two loss-recovery loops) is **not settled** by this run.

**Limits.** The debug build of the runner. Three members, one pair. The topic's byte budget was not set, so nothing was limited.

### Where the frames are lost: three more runs

The report now also counts, per member, the frames that the sink queue refused (`dropped_sink_refused`), the inbound queue to iroh (`queue_full`), oversized packets, and the
topic's `Lagged` events. Three runs of `cargo task benchmark --only 'ladder gossip' --rounds 5 --json`, same machine and build. Load average 1.96 at the start of run 1 and 8.89 at the
start of runs 2 and 3.

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| throughput, median (min–max), Mbit/s | 712 (706–754) | 681 (656–716) | 882 (845–917) |
| round trip p50, p99, ms | 0.16, 0.25 | 0.17, 0.25 | 0.17, 0.21 |
| flood amplification | 1.98 | 1.99 | 1.99 |
| frames C put on the topic, frames A read, gap | 38803, 38531, **272** | 37504, 37147, **357** | 37356, 37209, **147** |
| frames the sink at C refused (not counted in the line above) | **161** | 0 | 0 |
| lost packets of the inner connection at C | 422 | 357 | 147 |
| `Lagged` events at A, at B | 4, 13 | 4, 0 | 5, 8 |
| `queue_full`, oversized packets at any member | 0, 0 | 0, 0 | 0, 0 |
| frames A put on the topic, frames C read | 7241, 7245 | 5811, 5815 | 5719, 5722 |

**Reading.**

- Every frame that did not arrive shows up as a lost packet of the inner connection: gap plus sink refusals is 433, 357 and 147 against 422, 357 and 147 lost packets. In runs 2 and 3 the two are equal.
  QUIC retransmitted all of them, and the transfers completed.
- The loss is at two places. **The sink queue at C** refused 161 frames, in run 1 only: a burst filled its 256 frames. **The topic's delivery to A** is the larger part: a gap of 147 to 357 frames after
  the sink, with 4 or 5 `Lagged` events at A in every run. My inbound queue to iroh was never full and no packet was oversized, so those two are not where frames are lost.
- The `Lagged` event is the topic saying that the receive loop did not read fast enough: the subscription holds 2048 events by default (`TOPIC_EVENTS_DEFAULT_CAP`, set with
  `subscription_capacity` in `JoinOptions`), and the oldest are dropped when it is full. The documentation of that option says the subscriber is closed after a `Lagged` event; in these runs A kept
  receiving after its first one, so I do not know which of the two holds in this fork.
- This is at an offered load of about 700 Mbit/s, on a debug build where one runtime serves three endpoints. The default budget of 1 MiB/s is about 80 times lower (700 Mbit/s is about 87 MB/s). Nothing here says the
  budget would see loss. It says what the topic does when a member is pushed far past it, and that the engine's receive path must not be slower than the reader here: the engine reads the topic in
  its event loop, which also does other work.
- The A to C direction (acknowledgements and probes) lost nothing: C read 4 to 3 frames **more** than A put on the topic in each run, and I did not look into those few extra frames (a count taken at two
  different instants is the likely cause).

### The split of the mesh topic under load (Phase 6, step 5)

The engine reads the mesh topic in a task of its own (`gossip/split.rs`): a frame of the gossip transport goes to the transport, a mesh message goes to the event loop on a bounded queue, and
the control events go on a queue that never drops. This measures what the split changes, on real iroh-gossip. The run is the ignored test `real_gossip_split_run`
(`cargo test --release -p habilis-network --lib -- --ignored real_gossip_split_run --nocapture`).

**Method.** Two members on loopback. A sends unique frames of 3840 bytes (header included; a rate counts whole frames), as fast as the topic takes them or at a set rate, for 30 s. B reads the topic, and B's event loop is busy for 80 ms of every
100 ms (it blocks a worker). *Inline* is the old shape: one reader does both. *Splitter* is the new one. Release build, load average 2.4 to 3.9 before each run, 4 worker threads.

**Paced sweep** (two runs per cell; `Lagged` events at B, and the frames B read of the frames A sent):

| rate of A | inline, cap 2048 | splitter, cap 2048 | splitter, cap 8192 |
|---|---|---|---|
| 1 MiB/s (8192 frames) | 0, 0 | 0, 0 | 0, 0 |
| 16 MiB/s (131k frames) | 0, 0 | 0, 0 | 0, 0 |
| 64 MiB/s (524k frames) | 9 and 15 (lost 2.2k and 3.7k) | 6 and 0 (lost 319 and 0) | 0 and 1 (lost 0 and 54) |
| 128 MiB/s (1.05M frames) | 309 and 319 (**lost 22% and 23%**) | 8 and 10 (lost 0.1% and 0.4%) | 10 and 8 (lost 0.1%) |

**Unthrottled** (A sends 450 to 600 MB/s): inline 381 to 437 `Lagged` events and about 84% of the frames lost; splitter 320 to 424 events and 52% to 55% lost, at every capacity from 2048 to 32768
(three runs each). The queue does not matter there: A offers about 135k frames/s and the splitter drains about 63k/s, so any queue fills.

**Mesh messages beside the frames** (20000 of them at once, unthrottled; one run per capacity): the data queue peaked at 5985 (cap 8192) and 3583 (cap 16384), and dropped none.

**Reading.**

- With the busy loop, the topic does not lag below about 16 MiB/s in the old shape, and below about 64 MiB/s with the split. At 128 MiB/s the split cuts the `Lagged` events by a factor of 30 to 40 and the lost
  frames from about 22% to 0.1% to 0.4%.
- The capacity of the subscription (2048 against 8192) made no difference we can measure at 64 or 128 MiB/s. What remains at 128 MiB/s is a few `Lagged` events of 150 to 400 frames each, when the topic
  delivers a burst faster than the splitter task is scheduled. So the engine keeps iroh's default of 2048: at most 8 MB of queued events, where 8192 would allow 31 MB.
- The queue of mesh messages is the one place where more capacity helped, and only for a synthetic burst of 20000 messages. A real burst (a digest round, a roster refresh at N = 66) is some hundreds.
  A message dropped from that queue is counted in `forward_dropped` and repaired by anti-entropy.
- A `Lagged` event did not close the subscription in any of these runs: B kept reading after the first one.
- The default budget of 1 MiB/s is per member. A node can receive about N MiB/s from N members that all send at the budget, so 64 MiB/s is about N = 64.

**Limits.** Loopback, one flooding member, 4 worker threads, a blocking sleep as the model of a busy loop. The result for the real event loop is not measured.

## What this says about removing the inner encryption

- It is not what limits throughput in any cell.
- On native it is noise (<2%).
- In the browser it is real CPU (~27% of wall time on the receiving tab)
  but not the bottleneck. If it is done, the gain to claim is CPU, not
  Mbit/s, and it must be measured under pressure (`cargo task e2e` has the
  pressure axis) rather than here.
- The cheaper wins this table points at: data-channel messages past
  Chrome's ~1165-byte SCTP limit, by batching QUIC datagrams per message or
  by larger datagrams on the WebRTC path (browser); batched sends in the
  str0m driver, and the long-connection slowdown (native).
