# habilis-network-iroh-gossip-transport

Gossip as an iroh custom transport. Each outbound QUIC packet becomes one binary
frame on the mesh gossip topic. Every member receives the frame, and the member
whose id is the destination hands the packet to iroh.

Status: Phase 6 of PR #2, built in steps. Step 2 is the frame codec (`frame`).
The design is in `~/.claude/plans/phase6-gossip-transport.md`.
