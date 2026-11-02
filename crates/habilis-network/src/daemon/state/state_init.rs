use super::MeshSecrets;
use std::sync::Arc;

#[cfg(feature = "host")]
use crate::daemon::state_file::StateFile;
use crate::protocol::identity::Identity;

use iroh::address_lookup::memory;

use crate::{doc, transport};
/// Everything `EventLoopState::new` needs beyond the clock, grouped for the
/// same reason [`MeshSecrets`] is: the argument budget. `now` stays separate
/// because tests pin it to a deterministic instant.
#[derive(Debug)]
pub(crate) struct StateInit {
    #[cfg(feature = "host")]
    pub(crate) state_file: Option<StateFile>,
    // the identity is shared with the loop and its handlers, which hold clones
    pub(crate) identity: Arc<Identity>,
    pub secrets: MeshSecrets,
    /// The `meta` channel's per-peer write gate; `None` leaves it free-form.
    pub per_peer_gate: Option<doc::SelfWriteGate>,
    /// The negotiation-slot table the Router's signal acceptor was built with.
    ///
    /// Taken at construction rather than assigned afterwards, because the cap
    /// only means anything if the dialing and answering sides count against the
    /// *same* table. Defaulting it here and overwriting it later left a second
    /// ceiling briefly existing and enforcing nothing.
    pub(crate) webrtc_admission: transport::SignalAdmission,
    /// The address book of the member endpoint, made by `lookup::address_book` where the
    /// endpoint was built.
    pub(crate) address_book: memory::MemoryLookup,
    /// How far ICE may reach, derived from the mesh's own lookups so it cannot
    /// disagree with them.
    pub(crate) webrtc_ice: transport::IceProfile,
}
