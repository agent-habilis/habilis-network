//! The blob types are built from outside the crate: they are `#[non_exhaustive]`, so a struct literal is refused there.

use std::path::PathBuf;

use habilis_network::iroh::{EndpointAddr, SecretKey};
use habilis_network::net::direct::PayloadPath;
use habilis_network::ops::blob::{BlobDigest, BlobTicket, ContentId, OffloadRequest};
use habilis_network::protocol::{LookupOpts, TicketSecret};
use habilis_network_test_tracing::test;

#[test]
fn an_offload_request_is_built_from_outside_the_crate() {
    let request = OffloadRequest::new(
        PathBuf::from("/data/file.bin"),
        ContentId::new("group-1"),
        PathBuf::from("/data/spool"),
    );
    assert_eq!(request.path, PathBuf::from("/data/file.bin"), "the file");
    assert_eq!(request.spool_dir, PathBuf::from("/data/spool"), "the spool");
    assert!(
        request.password.is_none(),
        "no password until with_password"
    );
}

#[test]
fn a_blob_ticket_is_built_from_outside_the_crate() {
    let address = EndpointAddr::new(SecretKey::from_bytes(&[1; 32]).public());
    let ticket = BlobTicket::new(
        address.clone(),
        TicketSecret::from_bytes([2; 32]),
        BlobDigest::from([3; 32]),
        42,
        LookupOpts::loopback(),
        PayloadPath::DirectOnly,
    );
    assert_eq!(ticket.address, address, "the address");
    assert_eq!(ticket.size, 42, "the size");
    assert!(!ticket.password, "no password until with_password");
    assert!(ticket.with_password(true).password, "with_password sets it");
}
