use iroh::EndpointId;

pub(crate) struct InboundPacket {
    pub(crate) from: EndpointId,
    pub(crate) payload: Vec<u8>,
}
