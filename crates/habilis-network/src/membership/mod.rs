//! One embedded membership of a mesh: select a mesh, stand it up, send and
//! receive `msg` frames, read the roster, merge the shared state, and leave.
//!
//! The ritual every embedding runs — the C ABI, the browser peer, the chat
//! example, the e2e suites. A tab and a terminal land in the same mesh only if
//! they resolve their options the same way, so that resolution lives here
//! once. Bulk bytes do not ride a membership: they take a stream.

mod join_options;
mod membership_app;
mod membership_event;

pub use crate::daemon::SetupError;
pub use crate::transport::SendError;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub use join_options::blind_new_members;
pub use join_options::{JoinOptions, Membership, depart, join, resolve_kind};
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub use membership_app::Rung;
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
pub use membership_app::UnknownPeer;
pub use membership_app::{
    DEPARTURE_GRACE, INBOUND_CAP, Inbound, MAX_MSG, MSG_TAG, MembershipApp, Request, msg_body,
    msg_fits, parse_to,
};
pub use membership_event::{MembershipEvent, json_sink};
