//! One embedded membership of a mesh: select a mesh, stand it up, send and
//! receive `msg` frames, read the roster, merge the shared state, and leave.
//!
//! The ritual every embedding runs — the C ABI, the browser peer, the chat
//! example, the e2e suites. A tab and a terminal land in the same mesh only if
//! they resolve their options the same way, so that resolution lives here
//! once. Bulk bytes do not ride a membership: they take a stream.

mod app;
mod event;
mod join;

pub use app::{
    DEPARTURE_GRACE, INBOUND_CAP, Inbound, MAX_MSG, MSG_TAG, MembershipApp, Request, msg_body,
    msg_fits, parse_to,
};
pub use event::{MembershipEvent, json_sink};
pub use join::{Membership, Opts, depart, join, resolve_kind};
