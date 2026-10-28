//! The policy for the co-hosted beacon and directory roles.

/// When a member may co-host (serve) the seed-derived rendezvous — the
/// **beacon** role. Co-hosting a duplicate `rendezvous_id` before the
/// member has meshed registers a second copy on the shared pinned relay
/// and can capture the member's own bootstrap dial → isolation; the
/// policy plus the public probe-before-claim (`beacon::ensure`) keep
/// that from happening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoHostPolicy {
    /// Co-host from t=0 with no probe — the mesh origin (`create`),
    /// which has no peers to collide with, so a beacon exists before any
    /// joiner subscribes.
    Eager,
    /// Co-host from t=0 like [`Eager`](CoHostPolicy::Eager), but
    /// **probe-before-claim** so concurrent claimants on a *shared*
    /// rendezvous don't collide — the directory advertiser, where several
    /// meshes advertising into the same directory share one seed-derived
    /// `rendezvous_id`. The first to start claims (its probe finds nothing);
    /// the rest stay peers and mesh through it, so every advertiser's
    /// ad reaches discoverers.
    EagerProbed,
    /// Co-host once meshed, or speculatively after the empty-mesh
    /// grace (probe-gated in public) — a normal joiner.
    Deferred,
    /// Never co-host — a pure consumer (the `discover` directory
    /// session). It only ever dials an existing beacon.
    Never,
}

/// The co-host policy a directory advertiser runs: co-host the shared
/// rendezvous from t=0 but **probe-before-claim**, so a second advertiser into
/// the same directory defers instead of binding a duplicate (which partitioned
/// the directory in public mode — only one mesh was discoverable).
pub const DIRECTORY_ADVERTISER_COHOST: CoHostPolicy = CoHostPolicy::EagerProbed;
