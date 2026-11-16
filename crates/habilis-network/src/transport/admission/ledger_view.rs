use iroh::EndpointId;

/// A read of the ledger of direct connections at one instant.
#[derive(Debug, Clone)]
pub(crate) struct LedgerView {
    /// The endpoint that the table serves, when it is known.
    pub(crate) local: Option<EndpointId>,
    /// The cap `C` on the direct connections.
    pub(crate) cap: usize,
    /// The units that count against the cap now.
    pub(crate) units: usize,
    /// How many units the count is over the cap by.
    pub(crate) over_ceiling: usize,
    /// The peers that hold a connection of any kind.
    pub(crate) connections: usize,
    /// The cap `2C` on all the connections.
    pub(crate) total_cap: usize,
    /// The peers that hold a unicast QUIC connection.
    pub(crate) quic_peers: Vec<EndpointId>,
    /// The peers that hold a session.
    pub(crate) session_peers: Vec<EndpointId>,
    /// The pinned peers that hold their connection.
    pub(crate) pinned: Vec<EndpointId>,
    /// The peers whose connection or session took no unit: they count toward `2C` only.
    pub(crate) extras: Vec<EndpointId>,
}
