//! How a directed send ended, and how sure the sender is of it.

use std::{error, fmt};

use crate::transport::pool::SendFault;

/// How a unicast send ended. The sender knows two things about a frame that was not delivered:
/// whether the peer can still take it. A fault before the sender commits the frame is certain:
/// the peer never takes it, and a second send is safe. A fault after the commit is not: the peer
/// can have taken the frame.
///
/// # Examples
///
/// A caller tells a certain failure from an unconfirmed send. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::ops::SendVerdict;
///
/// # fn demo(verdict: SendVerdict) -> &'static str {
/// match verdict {
///     SendVerdict::Delivered => "delivered",
///     SendVerdict::NotDelivered(_) => "not delivered",
///     SendVerdict::Unconfirmed(_) => "not confirmed",
/// }
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::exhaustive_enums,
    reason = "a caller matches every state, so a new state breaks the build of the caller and never passes in a wildcard arm"
)]
pub enum SendVerdict {
    /// The peer took the frame into its loop and said so.
    Delivered,
    /// The peer did not take the frame, and it never will: no dial, no stream, no hold from the
    /// peer, or the peer said no. The text says why.
    NotDelivered(String),
    /// The sender committed the frame and did not hear the end: the peer can have taken it. A second
    /// send of the same message is dropped by the receiver; a new message is a duplicate.
    Unconfirmed(String),
}

impl SendVerdict {
    /// The verdict of a send that ended with `result`. A fault that names its phase keeps it. Any
    /// other error is a fault before the commit, such as a dial that failed.
    pub(crate) fn of(result: anyhow::Result<()>) -> Self {
        let Err(error) = result else {
            return Self::Delivered;
        };
        let reason = format!("{error:#}");
        let named: Option<&Self> = error.downcast_ref();
        if let Some(verdict) = named {
            return verdict.clone();
        }
        let fault: Option<&SendFault> = error.downcast_ref();
        if fault.is_some_and(SendFault::committed) {
            Self::Unconfirmed(reason)
        } else {
            Self::NotDelivered(reason)
        }
    }

    /// The verdict as the error of a send, for a caller that goes on with `?`. [`Self::of`] gives the
    /// verdict back.
    pub(crate) fn into_result(self) -> anyhow::Result<()> {
        match self {
            Self::Delivered => Ok(()),
            failed @ (Self::NotDelivered(_) | Self::Unconfirmed(_)) => {
                Err(anyhow::Error::new(failed))
            }
        }
    }
}

impl fmt::Display for SendVerdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delivered => formatter.write_str("delivered"),
            Self::NotDelivered(reason) => write!(formatter, "not delivered: {reason}"),
            Self::Unconfirmed(reason) => write!(formatter, "not confirmed: {reason}"),
        }
    }
}

impl error::Error for SendVerdict {}
