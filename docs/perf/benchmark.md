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
