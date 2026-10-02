# habilis-network-protocol

The wire vocabulary every habilis-network consumer speaks: messages, mesh ids,
nicknames, seed-derived identity, sealing, and invites.

Flat by design. The implementation is split across private submodules,
and everything is re-exported at the crate root, so a consumer writes one
import path.

The crate depends on `iroh-base` only. It pulls no tokio, no QUIC, no
TLS, and no DNS, so the wire vocabulary is cheap to take anywhere.

See `src/lib.rs` for the API: `Message`, `MeshName`, `Password`, the
derivation functions, and the base58check codec.
