//! The two classes of traffic a relay carries for us, and the event kinds each owns.

/// The first ephemeral kind of the signalling lane.
pub const SIGNAL_KIND_START: u32 = 20_000;

/// The first ephemeral kind of the data lane. The relay server pins the same
/// number, so a relay can treat the two lanes by kind: it keeps the slow-consumer
/// close for signalling and drops data events on a full queue.
pub const DATA_KIND_START: u32 = 25_000;

/// How many kinds each lane spans. The two lanes fill the ephemeral range
/// 20000..30000 between them.
pub const LANE_KIND_SPAN: u32 = 5_000;

/// A class of traffic. Each lane has its own kind range, its own socket to a
/// relay, and its own health, so a relay that limits the data we send does not
/// stop the signals that set a link up.
///
/// # Examples
///
/// The two lanes never share a kind.
///
/// ```
/// use habilis_network_iroh_nostr_address_lookup::{Lane, kind_for};
///
/// let tag = [7u8; 32];
/// assert_ne!(kind_for(Lane::Signal, &tag), kind_for(Lane::Data, &tag));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Lane {
    /// Rendezvous and signalling: small events that a peer must see.
    Signal,
    /// Payload: batches of datagrams, which a relay may drop under load.
    Data,
}

impl Lane {
    /// The first kind of this lane.
    #[must_use]
    pub fn kind_start(self) -> u32 {
        match self {
            Self::Signal => SIGNAL_KIND_START,
            Self::Data => DATA_KIND_START,
        }
    }
}
