/// ALPN for the blob channel — a raw bidirectional QUIC stream with its own
/// protocol identity, distinct from `GOSSIP_ALPN` and the application's own bridge
/// ALPN, so a mismatched dial is rejected at the QUIC handshake.
pub(crate) const BLOB_ALPN: &[u8] = b"habilis-mesh/blob/1";

/// Length of the bearer-capability secret carried in a blob ticket, and of the
/// auth token opening the fetch stream (the raw secret, or its Argon2id stretch
/// when passworded — same size either way).
pub const SECRET_LEN: usize = 32;

/// Length of the SHA-256 content hash that addresses a blob.
pub const HASH_LEN: usize = 32;

/// Fetch stream close code: the presented bearer secret matched no blob's secret.
pub(crate) const BAD_SECRET: u32 = 1;

/// Fetch stream close code: the requested content hash is not in the store.
pub(crate) const UNKNOWN_BLOB: u32 = 2;
/// The connection's selected path is the relay and the producer's mesh keeps
/// the relay for lookup only.
pub(crate) const RELAY_REFUSED_CODE: u32 = 3;

/// Fetch stream close code: an orderly done from the producer.
pub(crate) const DONE: u32 = 0;
