//! The wire version of the message envelope.

/// Protocol version embedded in every message, `13.0`. The change body of a gated channel carries
/// an epoch, and the digest window ids are Base64 (see below). The recipient of a directed frame
/// (`to` of an `app` and of a `pong` frame) is an author key and no longer a nickname. A nickname
/// is a label that two live keys can share, so a frame to a nickname reached both. A `12.0` peer
/// reads a key as an invalid nickname, so the frames of the two versions must not meet silently:
/// `parse` names the version of a frame that it refuses, also when the frame fails on a field
/// that the version changed.
///
/// `12.0` was the engine's de-branding. The crypto byte-domains are mixed into signature and
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
/// - `13.0` — the change body of the `state` and `meta` channels may carry an epoch key `e` (left
///   out at epoch 0), and the digest window ids are Base64 and not Base58. The recipient of a
///   directed frame (`to` of an `app` and of a `pong` frame) is an author key, not a nickname. A
///   `12.0` peer and a `13.0` peer do not form a mesh: the join succeeds, then each side refuses
///   every frame of the other, with an error that names the wire version and its own. Without the
///   bump an old peer would read a change of epoch above 0 as a change of epoch 0 whose dependency
///   is missing, keep it as an orphan, and be sent the same frames again and again, while a new
///   peer would ignore the frames of the old one. It would also read an author key in `to` as an
///   invalid nickname.
/// - `12.0` — the engine's de-branding, described above.
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
pub(crate) const VERSION: &str = "13.0";
