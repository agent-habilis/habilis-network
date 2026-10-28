//! The error of a blob: fetching one, offering one, and decoding a ticket.

mod blob_error;

pub use blob_error::BlobError;

#[cfg(test)]
mod chain_tests {
    use habilis_network_test_tracing::test;

    use super::BlobError;

    #[test]
    fn an_internal_cause_keeps_its_chain() {
        let io = std::io::Error::new(std::io::ErrorKind::AddrInUse, "Address already in use");
        let cause = anyhow::Error::new(io).context("bind the endpoint");
        let error = anyhow::Error::new(BlobError::internal(cause));
        let text = format!("{error:#}");
        assert!(
            text.contains("Address already in use"),
            "the io cause of BlobError is lost: {text}"
        );
    }
}
