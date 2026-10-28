//! The wire version of the message envelope.

/// Protocol version embedded in every message, `12.0` for the engine's
/// de-branding. The crypto byte-domains are mixed into signature and
/// key-derivation transcripts, so any rebrand changes the bytes an older build
/// derives and its signature verification fails *silently*. The exact-match gate
/// in `parse` exists to turn that into a loud rejection rather than a frame that
/// folds to a no-op and diverges. Rebrand the domains, bump this.
///
/// As of `12.0` the domains carry the **engine's** name, not the product's
/// (`habilis-mesh/…`): the unicast and blob ALPNs, the seal/sym/x25519/invite
/// seeds, the message signing domain, the directory base seed, and the
/// shared-document genesis actor. A consumer's own bridge ALPN stays branded
/// because it belongs to the application, not to this engine.
///
/// The identity wire key stays **`mesh`**, and so does the internal vocabulary.
/// The user-facing noun for a session is **gossip**, but that is a CLI/docs/MCP
/// surface word and never reaches the wire.
///
/// **`12.0` is the first version bump that breaks real interop.** `11.0` shipped
/// (v0.7.4, on the Homebrew tap), so an `11.0` peer and a `12.0` peer cannot form
/// a mesh at all — not merely fail on one frame kind. That is the designed
/// behavior of the `parse` gate: a loud rejection beats silent divergence. Every
/// bump below it predates any release, so no peer ever ran them, and they are
/// *format* history rather than interop history:
///
/// `12.0` also split the shipped consumer's chat tag in two, one per
/// addressing: a broadcast tag every member receives, and a directed tag
/// carried to a single addressee. That is an application-side change — the
/// `App` envelope has been tag-opaque since `8.0` — and it is recorded here
/// only because it lands inside the same interop break rather than needing one
/// of its own.
///
/// - `11.0` — a product rebrand (the product's name was in the byte-domains).
/// - `10.0` / `9.0` — the agent-mesh → agent-square and swarm → mesh renames.
///   `9.0` also moved the identity wire key to `"mesh"` and the JSON-RPC
///   namespace to `mesh:*`.
/// - `8.0` — the payload-generic `App` envelope (opaque `tag`, addressee `to`,
///   generic `corr`), multipart bodies up to
///   [`habilis_network_util::consts::MAX_SHARD_TOTAL`] (`64 MiB`), and password-mesh
///   `{"k":"enc",…}` content encryption.
/// - `7.0` — the automerge `state`/`meta` channels: Base58 change bodies,
///   heads-based digests.
/// - `6.0` — directed sealing.
/// - `5.0` — the application's v1.0 / `ProtoJSON` payload migration.
/// - `4.0` — the native application-payload port.
/// - `3.0` — the application-payload migration.
/// - `2.0` — RFC 6902 → RFC 7386 shared state.
pub(crate) const VERSION: &str = "12.0";
