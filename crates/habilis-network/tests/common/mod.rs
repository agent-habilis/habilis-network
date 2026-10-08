//! What the integration tests of the gossip rung share.

/// Whether the engine installs the gossip transport (Phase 6, step 10). While it does not, a test
/// that needs the gossip rung has nothing to measure: it prints SKIPPED and returns, so that
/// `cargo task matrix` and the nightly stay green and say so in the log. The commit that installs
/// the transport sets this to `true` and runs those tests on the host.
pub(crate) const GOSSIP_INSTALLED: bool = false;
