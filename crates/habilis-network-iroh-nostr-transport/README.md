# habilis-network-iroh-nostr-transport

Nostr as an iroh custom transport. Each outbound QUIC datagram becomes one frame, and the
data lane of the Nostr relay client carries it in an ephemeral event to the tag of the
destination. It is the last rung before `Other`: a pair uses it only when no other path
links the two.

The frame, the byte budget, the counters and the receive path are the ones of
`habilis-network-iroh-gossip-transport`. This crate gives that core the Nostr transport id
and a sink over the data lane.

## When a pair uses it

The transport starts closed. No frame, and no address of it, leaves for a peer until the engine
allows the pair, or until a frame of that peer arrives and shows that it chose this path. The
engine allows a pair only when no other usable path serves it. On a mesh whose relay is lookup
only, a relay path is not a usable path.

The first dial of a pair on a healthy mesh never names the Nostr address. A dial names it for a
pair that the engine wants Nostr for: no other path served the pair at the last reading, or a dial
to it failed.

## Fail-over

Fail-over to Nostr is not instant. A connection that loses every path stays selected on the dead
path until QUIC closes it at the idle timeout. The sweep of the admission table (up to 5 s) then
reads the pair as unserved. The first dial after the loss names no Nostr address, so it fails. The
failed dial marks the pair as one that the engine wants Nostr for, and the next dial names the
Nostr address. The pair then links over Nostr. Expect about the idle timeout, plus the sweep (up
to 5 s), plus one failed dial, plus one dial.

A gossip link never rides Nostr: the engine closes it with its own code. A pair on Nostr carries
directed payload, not the mesh topic.

## Reach of the relays

A node listens on every relay of the custom list, up to 4, and sends on the first healthy relay
of that list. A pair whose two ends cannot both reach the same relay of the list has no Nostr path,
even when one relay of the list serves both. Nothing logs this. Give both ends the same custom
list, and choose relays that every member can reach.

The browser data path is proven by compilation and by a case that binds an endpoint and activates
the transport. No test sends a datagram through the web socket yet.
