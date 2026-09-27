# chat-webrtc

A chat room a browser tab and a terminal can both join, where the tab's
connection is **QUIC over a `WebRTC` data channel** — one iroh `Connection`, one
`RTCDataChannel` under it, no signalling server anywhere.

The iroh ecosystem has no `WebRTC` transport, so a tab cannot reach an iroh peer
at all today except through a relay. This is a working one
([`fofoca-iroh-webrtc-transport`](../..)), and this example is the smallest
thing that shows it doing its job.

## What it demonstrates

- A browser tab holding a real iroh QUIC connection to a native process, over a
  data channel.
- **No signalling server.** The iroh relay the two peers already use to find
  each other carries the SDP exchange on an ALPN of its own. Nothing else is
  deployed.
- Native peers can use the same path (`join --webrtc`), so the transport is
  testable end to end with no browser in the loop.
- Every peer prints which transport is actually carrying its connection, because
  "it connected" proves nothing — a peer that quietly fell back to the relay
  connects perfectly well and looks identical from the chat's point of view.

```
native host                                browser peer
───────────                                ────────────
Endpoint(relay + webrtc, additive)         Endpoint A: relay only  ──┐
  ├─ accept  chat-webrtc/signal/1  ◀───────── connect ──────────────┘  offer ▸
  │                                  ─────────────────────────────▸   ◂ answer
  └─ accept  chat-webrtc/chat/1    ◀──────  Endpoint B: webrtc only, no relay
                                              connect(EndpointAddr{id, Custom(webrtc)})
```

## Run it

Prerequisites: `rustup target add wasm32-unknown-unknown`,
`cargo install wasm-bindgen-cli`, [Bun](https://bun.sh), and on macOS
`brew install llvm` (Apple's clang has no wasm backend, and `ring`'s C core
needs one).

```sh
# 1. the room, which is also the third participant
cargo run -p chat-native -- host

# 2. the browser half
./build-wasm.sh
cd web && bun install && bun run dev

# 3. open the URL the room printed — http://localhost:3000/#<ticket>, on the port dev printed
```

Another terminal peer, over `WebRTC` like a tab:

```sh
cargo run -p chat-native -- join <ticket> --nick bob --webrtc
```

Drop `--webrtc` for the control: a native peer should normally prefer iroh's own
transports, which are considerably faster, and the status line will say `ip` or
`relay` instead. On a machine with no internet, add `--host-ice` to both sides
to skip the STUN round trip.

Everyone's status line should read `webrtc`. In a tab it also names the ICE
candidate pair, read from the browser's own `getStats` rather than from us.

## What it needs from iroh

This is the part written for n0. Three things, in descending order of how much
they cost:

**1. `unstable-custom-transports` is unstable, and pinned to a fork.**
`CustomTransport` / `CustomEndpoint` / `CustomSender` are exactly the right
shape — the transport implements them and nothing else — but they are behind an
unstable feature, so this cannot be published. Everything below is downstream of
wanting that stabilised.

**2. The default path selector will not select an unmeasured path.**
`BiasedRttPathSelector` skips paths it has no RTT sample for, and a freshly
attached `WebRTC` path always is one. The effect is not "it takes a while to
switch": the connection settles on the relay and stays there for its entire
life, while the data channel sits open and idle beside it. Registering the
transport is therefore *not enough* — the transport ships its own
`WebRtcPreferred` selector (`src/selector.rs`, ranking `ip > webrtc > relay`)
purely to work around this, and every consumer has to remember to install it.
**We think this is a bug, not a policy.** A path with no sample is not a bad
path; it is an unmeasured one, and the two should not be treated alike.

**3. A live connection cannot be upgraded onto a newly attached transport.**
iroh only fans a connect's Initial out to candidate paths *while the remote has
no selected path*. Since a session must exist before it can be selected, and the
session is negotiated over a connection that has already selected the relay,
a tab cannot simply attach the transport and carry on. It has to bind **two
endpoints on one secret key** — a signalling one that holds the relay, and a
chat one with `RelayMode::Disabled` and nothing registered but `WebRTC`, so the
chat dial has no other path to lose to. That works, and it is well tested, but
it is a workaround a reader has to be told about rather than something the API
suggests. (One key, because the room keys its roster, its session registry and
its TLS by endpoint id. Only the signalling endpoint may hold the relay: two
same-key endpoints registering with one relay server fight over the
registration, and ICE never completes.)

## Known limits

- **No TURN, by policy.** `accept_ice_uri` refuses `turn:`/`turns:` at the
  enforcement point. A pair that cannot ICE falls back to the iroh relay rather
  than to a second relay at the ICE layer — running two relay systems for one
  job is not worth it.
- **Vanilla ICE, no trickle.** Candidates ride inside the SDP, so gathering
  completes before the envelope goes out. Joining a room takes a few seconds and
  the tab says so while it waits.
- **One data channel per peer**, negotiated unreliable and unordered
  (`maxRetransmits: 0`). QUIC above owns loss recovery and congestion control;
  reliable ordered SCTP underneath would stack a second retransmission loop on
  every loss and head-of-line-block unrelated QUIC streams.
- **Browsers withhold candidate addresses.** `getStats` reports an address only
  for candidates whose address already went out on the wire. Measured: Safari
  withholds it for `host` and `prflx` and names only `srflx`; Chrome withholds
  it for `prflx`. The candidate *type* is always reported, which is the more
  interesting half anyway, so the status line shows the type and appends the
  address only when there is one.
- **Native ↔ native does not use this.** Measured with transport as the only
  variable, the data channel gives roughly 6× less throughput at 36× the
  latency of iroh's own hole-punched path. `--webrtc` exists for testing, not
  because it is a good idea.

## Layout

| | |
|---|---|
| `chat-proto/` | the wire vocabulary — ALPNs, messages, framing, ticket. Builds for wasm32 and the host from one source. |
| `chat-native/` | the room and a terminal client. `src/signal.rs` is the JSEP exchange and the most interesting file here. |
| `chat-web/` | the tab: an iroh endpoint compiled to wasm. Its own workspace — `web-sys` does not exist off wasm32. |
| `web/` | a Bun app, ~200 lines of plain DOM. |

This directory is **its own cargo workspace**, and deliberately so. It is a
consumer of the transport, reaching it by path, and it declares no `iroh`
dependency at all — everything iroh-shaped arrives through
`fofoca_iroh_webrtc_transport::iroh`. That is not tidiness: the transport is
built against a fork pin, and a consumer that names `iroh` itself resolves a
second copy whose `CustomTransport` impls no longer satisfy the trait iroh hands
back, with an `E0308` pointing nowhere near the manifest at fault. If that ever
stops being true, this workspace fails to build and says so.
