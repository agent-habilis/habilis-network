//! A datagram from another member, on its way to iroh.

use bytes::Bytes;
use iroh::EndpointId;

pub(crate) struct InboundPacket {
    pub(crate) from: EndpointId,
    pub(crate) payload: Bytes,
}
