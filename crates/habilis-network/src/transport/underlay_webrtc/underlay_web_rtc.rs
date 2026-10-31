//! The `WebRTC` underlay of a multihop node.

use super::allowed::Allowed;
use crate::transport::SignalAdmission;
use iroh::Endpoint;

use iroh::address_lookup::memory;

/// What the event loop keeps of the `WebRTC` leg of the underlay.
#[derive(Debug, Clone)]
pub(crate) struct UnderlayWebRtc {
    pub(crate) handle: habilis_network_iroh_webrtc_transport::WebRtcHandle,
    pub(crate) admission: SignalAdmission,
    pub(crate) endpoint: Endpoint,
    /// The address book of `endpoint`: the sessions of the underlay are named in it.
    pub(crate) book: memory::MemoryLookup,
    pub(crate) allowed: Allowed,
}
