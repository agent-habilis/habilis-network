//! A datagram from another member, on its way to iroh.

use bytes::Bytes;
use iroh::EndpointId;

#[derive(Debug, Clone)]
pub(crate) struct InboundPacket {
    pub(crate) from: EndpointId,
    pub(crate) payload: Bytes,
}
