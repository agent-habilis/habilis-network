//! The address of a peer on the multihop transport: the application id of the destination and nothing more.

use iroh::EndpointId;
use iroh_base::CustomAddr;

use crate::MULTIHOP_TRANSPORT_ID;
use crate::app_id::AppId;

/// The address that iroh holds for a peer that is reached by multihop. It names the peer and no way to it: each
/// node picks the next hop of a cell from its own table, so no route is stored in iroh and none can go stale.
/// A packet that reaches this node reports the address of its source in the same form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Destination(AppId);

impl Destination {
    pub(crate) fn new(app_id: AppId) -> Self {
        Self(app_id)
    }

    pub(crate) fn app_id(self) -> AppId {
        self.0
    }

    /// The address as iroh holds it: the transport id, and the 32 bytes of the application id.
    pub(crate) fn encode(self) -> CustomAddr {
        CustomAddr::from_parts(MULTIHOP_TRANSPORT_ID, self.0.get().as_bytes())
    }

    /// The destination of an address of this transport, or `None` for another transport or a wrong length.
    pub(crate) fn decode(address: &CustomAddr) -> Option<Self> {
        if address.id() != MULTIHOP_TRANSPORT_ID {
            return None;
        }
        let bytes: [u8; 32] = address.data().try_into().ok()?;
        let id = EndpointId::from_bytes(&bytes).ok()?;
        Some(Self(AppId::new(id)))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use iroh::endpoint::transports::Addr;
    use iroh::{EndpointId, SecretKey};

    use super::Destination;
    use crate::MULTIHOP_TRANSPORT_ID;
    use crate::app_id::AppId;

    fn app(seed: u8) -> AppId {
        AppId::new(SecretKey::from_bytes(&[seed; 32]).public())
    }

    #[test]
    fn encode_decode_roundtrips() {
        let _guard = ::habilis_network_test_tracing::init();
        let destination = Destination::new(app(1));

        let decoded = Destination::decode(&destination.encode());

        assert_eq!(
            decoded,
            Some(destination),
            "the destination survives the address"
        );
    }

    /// The address holds the 32 bytes of the application id: a golden form, so a change of it is a named decision.
    #[test]
    fn a_destination_encodes_to_fixed_bytes() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut data = String::new();
        for byte in Destination::new(app(1)).encode().data() {
            write!(data, "{byte:02x}").expect("writing to a String cannot fail");
        }

        assert_eq!(
            data, "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            "the address is the application id"
        );
    }

    /// The util crate reads the remote of a path from this address, so the two forms must stay in step.
    #[test]
    fn the_util_crate_reads_the_destination_of_an_encoded_address() {
        let _guard = ::habilis_network_test_tracing::init();
        let destination: EndpointId = SecretKey::from_bytes(&[7; 32]).public();
        let address = Addr::Custom(Destination::new(AppId::new(destination)).encode());

        assert_eq!(
            habilis_network_iroh_transport_util::multihop_remote_of(&address),
            Some(destination),
            "the util crate reads the destination"
        );
    }

    #[test]
    fn an_address_of_another_transport_or_of_a_wrong_length_does_not_decode() {
        let _guard = ::habilis_network_test_tracing::init();
        let other = iroh_base::CustomAddr::from_parts(MULTIHOP_TRANSPORT_ID + 1, &[1; 32]);
        let short = iroh_base::CustomAddr::from_parts(MULTIHOP_TRANSPORT_ID, &[1; 31]);
        let long = iroh_base::CustomAddr::from_parts(MULTIHOP_TRANSPORT_ID, &[1; 33]);

        assert_eq!(Destination::decode(&other), None, "another transport");
        assert_eq!(Destination::decode(&short), None, "31 bytes");
        assert_eq!(Destination::decode(&long), None, "33 bytes");
    }
}
