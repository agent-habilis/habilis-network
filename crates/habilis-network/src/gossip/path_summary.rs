/// Which transport paths to a peer are active: direct (IP or a custom
/// transport), the relay, both, or none reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSummary {
    Direct,
    Relay,
    Mixed,
    Unknown,
}

impl PathSummary {
    /// The log label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Mixed => "mixed",
            Self::Unknown => "unknown",
        }
    }
}
