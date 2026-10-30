//! What a send leaves behind to retry: the resend outcome.

use crate::protocol::messages::WireFrame;
use iroh::EndpointId;

/// One message that is ready to go, with the plane its addressing chose.
#[derive(Debug, Clone)]
pub(crate) enum Resend {
    Broadcast(WireFrame),
    Unicast(EndpointId, WireFrame),
}
