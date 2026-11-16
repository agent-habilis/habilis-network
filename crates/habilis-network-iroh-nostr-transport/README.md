# habilis-network-iroh-nostr-transport

Nostr as an iroh custom transport. Each outbound QUIC datagram becomes one frame, and the
data lane of the Nostr relay client carries it in an ephemeral event to the tag of the
destination. It is the last rung before `Other`: a pair uses it only when no other path
links the two.

The frame, the byte budget, the counters and the receive path are the ones of
`habilis-network-iroh-gossip-transport`. This crate gives that core the Nostr transport id
and a sink over the data lane.
