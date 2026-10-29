//! The error of an endpoint: building one, and dialling a peer's WebRTC signal.

mod endpoint_error;

pub use endpoint_error::EndpointError;

#[cfg(test)]
mod chain_tests {

    use super::EndpointError;

    use std::io;
    use std::io::ErrorKind;
    #[test]
    fn an_internal_cause_keeps_its_chain() {
        let _guard = ::habilis_network_test_tracing::init();
        let io = io::Error::new(ErrorKind::AddrInUse, "Address already in use");
        let cause = anyhow::Error::new(io).context("bind the endpoint");
        let error = anyhow::Error::new(EndpointError::internal(cause));
        let text = format!("{error:#}");
        assert!(
            text.contains("Address already in use"),
            "the io cause of EndpointError is lost: {text}"
        );
    }
}

#[cfg(test)]
mod refusal_tests {
    use iroh::SecretKey;

    use super::EndpointError;

    use std::io;
    /// A refusal names the exchange error it came from, so the log shows both.
    #[test]
    fn a_refusal_keeps_the_exchange_error_as_its_source() {
        let _guard = ::habilis_network_test_tracing::init();
        let remote = SecretKey::from_bytes(&[7; 32]).public();
        let exchange = io::Error::other("connection reset by peer");
        let refusal = EndpointError::CapRefused {
            remote,
            source: Box::new(exchange),
        };
        let text = format!("{:#}", anyhow::Error::new(refusal));
        assert!(text.contains("connection reset by peer"), "{text}");
    }
}
