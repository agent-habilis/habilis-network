use super::MeshSecrets;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "host")]
use crate::daemon::state_file::StateFile;
use crate::protocol::identity::Identity;

use iroh::address_lookup::memory;

use crate::transport;
/// The two keys of one run. The session key is made fresh each run: it signs every frame, it is the
/// automerge actor, and it is the seal key. The member key lives in a file and survives a restart: it
/// signs only the proof that the session speaks as the member.
#[derive(Debug, Clone)]
pub(crate) struct RunKeys {
    // shared with the loop and its handlers, which hold clones
    pub(crate) session: Arc<Identity>,
    // shared with the loop and its handlers, which hold clones; none on a platform with no file to keep
    // the key in, where a proof would prove nothing across restarts
    pub(crate) member: Option<Arc<Identity>>,
    /// The run number of this start, which the proof of the session names.
    pub(crate) run: u64,
    /// The member key and the run counter were made by this start, not read from files of an
    /// earlier one.
    #[cfg_attr(
        not(all(unix, feature = "host")),
        expect(dead_code, reason = "only the binding of a host to its owner reads it")
    )]
    pub(crate) member_new: bool,
    /// The lock on `<state>.key.lock`, held for as long as this start lives, so that no second live
    /// start reads the same member key. The lock is an OS lock on the descriptor: it goes when the
    /// process ends, so a crash frees the key. `None` where there is no member key to keep.
    // shared with every clone of the keys: the lock goes when the last one drops
    pub(crate) key_lock: Option<Arc<File>>,
    /// The state path that the member key and the run counter live under, as the setup resolved it:
    /// the explicit state file, or the default path of the mesh. A caller that binds the pair to an
    /// owner reads it, because the explicit state file alone names no pair under the default path.
    #[cfg_attr(
        not(all(unix, feature = "host")),
        expect(dead_code, reason = "only the binding of a host to its owner reads it")
    )]
    pub(crate) keys_state: Option<PathBuf>,
}

/// Everything `EventLoopState::new` needs beyond the clock, grouped for the
/// same reason [`MeshSecrets`] is: the argument budget. `now` stays separate
/// because tests pin it to a deterministic instant.
#[derive(Debug)]
pub(crate) struct StateInit {
    #[cfg(feature = "host")]
    pub(crate) state_file: Option<StateFile>,
    // the keys are shared with the loop and its handlers, which hold clones
    pub(crate) keys: RunKeys,
    /// The frame overhead of this session, with its mesh id and nickname: it sets the body cap of the
    /// shared-state slices.
    pub(crate) frame_overhead: usize,
    pub secrets: MeshSecrets,
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
