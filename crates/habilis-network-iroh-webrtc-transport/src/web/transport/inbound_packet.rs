use iroh::EndpointId;

#[derive(Debug, Clone)]
pub(crate) struct InboundPacket {
    pub(crate) from: EndpointId,
    pub(crate) payload: Vec<u8>,
}
