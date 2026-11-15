use iroh_gossip::proto;
/// Developer log for the mesh-ready milestone. Mirrors the operator
/// `ready` event but on the lifecycle log target (stderr, opt-in via
/// `RUST_LOG`); the operator JSON/human event is unchanged.
///
/// Logs the derived **`TopicId`** (a one-way hash of the seed), never the full
/// mesh id. The id carries the seed and *is* the bearer credential, and this
/// log file is written under a shared path — logging the id would leak full
/// mesh membership to anyone who can read the file. The topic hash is enough
/// to correlate a run without exposing the secret.
pub(crate) fn log_ready(topic: proto::TopicId, name: &str, nickname: &str, network: &str) {
    tracing::info!(target: "habilis_network::lifecycle", ?topic, name, nickname, network, "mesh ready");
}

/// Developer log for graceful departure (mirrors the operator `left`).
pub(crate) fn log_leaving(name: &str) {
    tracing::info!(target: "habilis_network::lifecycle", name, "leaving mesh");
}
