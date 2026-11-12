use crate::protocol::AuthorKey;
use std::{error, fmt};

/// Why [`app_frame`](crate::ops::app_frame) cannot build a frame.
///
/// # Examples
///
/// A frame for a tag that seals its directed body needs the seal key of the addressee. The doc test
/// compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::embed::AppFrameError;
///
/// # fn demo(error: AppFrameError) -> String {
/// error.to_string()
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum AppFrameError {
    /// The tag seals its directed body, and no `PeerInfo` named a seal key for the addressee yet.
    /// The key comes with the first `PeerInfo` of the peer, so a send can be tried again.
    NoSealKey {
        /// The addressee.
        to: AuthorKey,
    },
    /// The seal failed: the sealed body is not a valid message body.
    Seal(String),
}

impl fmt::Display for AppFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSealKey { to } => write!(
                formatter,
                "no seal key is known for {to}: its PeerInfo has not arrived, so the directed body cannot be sealed; try again later"
            ),
            Self::Seal(cause) => write!(formatter, "the body cannot be sealed: {cause}"),
        }
    }
}

impl error::Error for AppFrameError {}
