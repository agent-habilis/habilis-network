use std::fmt;

/// Why the local relay did not start.
#[cfg_attr(
    not(feature = "iroh-test-utils"),
    expect(
        unreachable_pub,
        reason = "`net` re-exports it only with `iroh-test-utils`"
    )
)]
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum TestRelayError {
    /// The relay server did not spawn.
    Spawn(iroh_relay::server::SpawnError),
    /// The relay server bound no HTTP address.
    NoHttpAddr,
    /// The local address is not a relay URL.
    BadUrl(iroh::RelayUrlParseError),
}

impl fmt::Display for TestRelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(formatter, "spawning the local relay server: {error}"),
            Self::NoHttpAddr => write!(formatter, "the local relay server bound no HTTP address"),
            Self::BadUrl(error) => write!(
                formatter,
                "the local relay address is not a relay URL: {error}"
            ),
        }
    }
}

impl std::error::Error for TestRelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::BadUrl(error) => Some(error),
            Self::NoHttpAddr => None,
        }
    }
}
