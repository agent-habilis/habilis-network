# habilis-network-iroh-nostr-address-lookup

A small Nostr relay client. habilis-network uses it to find peers and to carry the WebRTC
offer and answer when the iroh relay is not available.

The name is ahead of the contents. Today the crate is the relay client only.
An iroh `AddressLookup` over Nostr, like `iroh-mdns-address-lookup`, is
planned for this crate.

- **Events.** Events are NIP-01 events with ephemeral kinds (20000–29999). Relays
  forward these kinds and store nothing. Each event carries one `x` tag. A
  random BIP-340 key for each pool signs the events. This key satisfies the
  relay and proves nothing more. The engine seals and signs its own payload
  inside `content`.
- **Sockets.** A process opens one socket for each relay URL, and all pools
  share it.
- **Relay choice.** A `Pool` holds the healthiest `width` relays of a ranked
  list. A pool at width 1 and a pool at width 3 on the same ranking still
  overlap.
- **Relay health.** The rules are the same as Trystero's:
  - `rate-limited:` backs off from 1 min, doubling up to 15 min.
  - `blocked:`, `restricted:`, `auth-required:` and `pow:` retire the relay for
    the life of the process.
  - A dropped socket reconnects, starting at 1 s and doubling up to 1 min. The
    delay resets only after a socket stays up for 30 s.
  - A relay that owes us the echo of our own event for 10 s stops counting
    toward the width, because it accepts events and forwards none.
  - A relay that is dialing counts as usable for up to 10 s. Until then, a
    pool on dead relays opens no spares.
- **Data lane.** Signalling uses kinds 20000–24999, and data uses kinds
  25000–29999. The data lane has its own sockets, health and rate-limit
  waits, so a relay that limits our data does not stop our signals.
  - A node holds one data socket on each relay of its custom list, up to 4
    (`MAX_DATA_RELAYS`), for the life of the node. It holds them only when the
    mesh lists Nostr. A relay of the pinned list never carries data.
  - It sends each datagram to the first relay that is `Up`. A relay that
    limited us and whose wait is over gets one probe copy each 5 s, and gets
    all the data only when no relay is `Up`.
  - A receiver listens on every one of those relays, so it hears a sender that
    fell to a later relay.
  - Limit: a receiver that cannot reach a relay that the sender can reach does
    not hear the sender there, and no log shows it.
  - `DataPool::sendable` tells a transport when a datagram has a relay: one is
    `Up`, or one is limited with its wait over. The first frame after the wait
    is the probe.
  - The `from` field of a batch is the id that the sender wrote. Any member
    that holds the mesh key can write any id, so nothing proves it. Treat it
    as a hint.

## Risks

- **Public relays.** The pinned list is public relays that anyone runs. They
  can drop ephemeral events, rate-limit, require auth or proof of work, or
  go away, and the list goes stale. A relay sees each client IP, the timing
  and the tags. It cannot read a signal, because the engine seals every one.
  `nostr_urls` replaces the list with relays you run.
- **Replay window.** A signal is valid for ±120 s, and the engine remembers
  each nonce it has seen in memory. So a node that restarts inside those
  120 s accepts one replay of a signal it saw before the restart. A wall
  clock that is wrong by more than 120 s blocks signalling. A relay can
  have a shorter window than ours: strfry refuses an ephemeral event that
  is older than 60 s. The client logs a warning when a relay refuses an
  event as `expired`, `too early` or `too old`.
- **Who can reach the room.** On an open mesh the id is the bearer
  credential: anyone who holds it can derive the room tag and send offers,
  so they can fill a node's direct slots, the same as over the iroh relay.
  On a password or invite-only mesh the room tag derives from the stretched
  key or the invite root, so only a member can reach the room. No mesh stops
  a member from using other members' slots, because gossip admission does
  not see a WebRTC session. That is the same exposure as the relay lane.

## Probe

`cargo run -p habilis-network-iroh-nostr-address-lookup --example probe` tests which public relays forward
an ephemeral event between two subscribers.

On 2026-09-24:
- 20 of 32 candidates forwarded the event, with round trips from 57 ms to 1.1 s.
- With `probe cadence`, 10 nodes published 90 events in 30 s on one tag:
  - `nos.lol` and `relay.primal.net` delivered 81 of 81 events to every node.
  - `relay.damus.io` delivered 4–5 of 81.

On 2026-11-15, with the same 32 candidates:
- 21 forwarded the event, with round trips from 67 ms to 4.2 s. Three
  connected and returned no echo (`relay.damus.io`, `strfry.shock.network`,
  `relay-rpi.edufeed.org`), and eight did not connect.
- The probe ends with the list to pin: the fastest forwarding relay of each
  operator (found by apex domain), and no test host. `staging.yabu.me` and
  `top.testrelay.top` were dropped from the pinned list by that rule.

## Tests

`cargo test -p habilis-network-iroh-nostr-address-lookup` runs against `test_relay::TestRelay`, an
in-process relay (feature `test-relay`). It checks ids and signatures, filters
events like a real relay, and can refuse, swallow events, or drop connections.

A few tests wait on real timers: backoff, the echo deadline, and a relay that
hangs up. So the suite takes about a minute. The sleeps are what the tests
measure, so do not shorten them.
