use super::RungPath;

/// One rung of the default relay ladder: the URL of the relay, and how the rung reaches it.
///
/// # Examples
///
/// Rung 0 of the default ladder is a direct rung.
///
/// ```
/// use habilis_network::{RENDEZVOUS_RELAY_LADDER, RungPath};
///
/// let rung_zero = RENDEZVOUS_RELAY_LADDER[0];
/// assert!(matches!(rung_zero.path(), RungPath::Direct { .. }));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DefaultRung {
    pub(super) url: &'static str,
    pub(super) path: RungPath,
}

impl DefaultRung {
    /// The URL of the relay.
    #[must_use]
    pub fn url(self) -> &'static str {
        self.url
    }

    /// How the rung reaches its relay.
    #[must_use]
    pub fn path(self) -> RungPath {
        self.path
    }
}
