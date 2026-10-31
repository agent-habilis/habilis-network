use iroh::EndpointId;

/// The sessions in `live` whose remote is none of `own`. A member's own endpoints
/// attach to its beacon's answerer as well, and no other peer hangs off the beacon
/// through them: counted, they made each split holder defer its shed for the full wait.
pub(crate) fn foreign_sessions(live: &[EndpointId], own: &[EndpointId]) -> Vec<EndpointId> {
    let live_ids = live.iter().copied();
    let remote = live_ids.filter(|id| !own.contains(id));
    remote.collect()
}

/// Who hangs off a beacon's data channel: the sessions on its answerer, the endpoints that
/// are ours, and the number of rounds still negotiating a session.
#[derive(Debug, Default, Clone)]
pub(crate) struct Dependents {
    pub(crate) live: Vec<EndpointId>,
    pub(crate) own: Vec<EndpointId>,
    pub(crate) in_flight: usize,
}

impl Dependents {
    pub(crate) fn count(&self) -> usize {
        foreign_sessions(&self.live, &self.own).len() + self.in_flight
    }

    pub(crate) fn foreign_ids(&self) -> Vec<String> {
        short_ids(&foreign_sessions(&self.live, &self.own))
    }

    pub(crate) fn live_ids(&self) -> Vec<String> {
        short_ids(&self.live)
    }

    pub(crate) fn own_ids(&self) -> Vec<String> {
        short_ids(&self.own)
    }
}

pub(crate) fn short_ids(ids: &[EndpointId]) -> Vec<String> {
    let id_refs = ids.iter();
    let short = id_refs.map(|id| id.fmt_short().to_string());
    short.collect()
}
