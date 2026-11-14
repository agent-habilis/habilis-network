//! The fixtures that the tests of the chunk fetch share: a state that holds a value as chunks, and the slice of a
//! peer that names them.

use habilis_network_chunks::{ChunkMap, Root};
use habilis_network_doc::{ChunkPointer, SliceIngest};
use habilis_network_util::clock::Instant;
use iroh::EndpointId;

use crate::daemon::state::EventLoopState;
use crate::doc::wire;
use crate::protocol::identity::Identity;
use crate::protocol::{Channel, MeshId, Message, MessageBody, SymmetricKey};
use crate::testing::{fresh_state, nick, test_key};

/// Bytes that no two chunks of share, `len` long.
pub(crate) fn bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from((index * 31 + index / 7) % 251).expect("a byte"))
        .collect()
}

/// A state that trusts `member` as the endpoint of a member.
pub(crate) fn state_trusting(member: EndpointId) -> EventLoopState {
    let mut state = fresh_state();
    state.proven_endpoints.trust(test_key("member"), member);
    state
}

/// Holds `value` as chunks, and a slice of `peer` that names them. Returns the root and the map.
pub(crate) async fn hold_named_value(
    state: &mut EventLoopState,
    peer: &Identity,
    value: &[u8],
) -> (Root, ChunkMap) {
    let root = state.chunks.put_value(value).await.expect("a value");
    let map = state
        .chunks
        .map(root)
        .await
        .expect("a lookup")
        .expect("a map");
    let size = u64::try_from(value.len()).expect("a size");
    name_root(state, peer, ChunkPointer::new(root, size), 1);
    (root, map)
}

/// Ingests a slice of a peer, with `version`, that names `pointer`.
pub(crate) fn name_root(
    state: &mut EventLoopState,
    peer: &Identity,
    pointer: ChunkPointer,
    version: u64,
) {
    let body = serde_json::json!({"version": version, "value": pointer.to_value()});
    slice_of_peer(state, peer, &body.to_string(), version);
}

/// Ingests a slice of `peer` that names `pointer`, sealed with the key that the mesh key gives the `state` channel.
pub(crate) fn name_root_sealed(
    state: &mut EventLoopState,
    peer: &Identity,
    pointer: ChunkPointer,
    version: u64,
    mesh_key: &SymmetricKey,
) {
    let text = serde_json::json!({"version": version, "value": pointer.to_value()}).to_string();
    let plain = MessageBody::try_new(&text).expect("a body");
    let sealed = wire::encrypt_body(&plain, &mesh_key.derive(b"state-doc")).expect("a sealed body");
    ingest_body(state, peer, sealed, version);
}

/// Holds `value` as chunks of a passworded mesh, and a slice of `peer` that names them, sealed with the key that
/// the mesh key gives the `state` channel. Returns the root.
pub(crate) async fn hold_named_value_sealed(
    state: &mut EventLoopState,
    peer: &Identity,
    value: &[u8],
    mesh_key: &SymmetricKey,
) -> Root {
    let root = state.chunks.put_value(value).await.expect("a value");
    let size = u64::try_from(value.len()).expect("a size");
    let pointer = ChunkPointer::new(root, size);
    let text = serde_json::json!({"version": 1, "value": pointer.to_value()}).to_string();
    let plain = MessageBody::try_new(&text).expect("a body");
    let sealed = wire::encrypt_body(&plain, &mesh_key.derive(b"state-doc")).expect("a sealed body");
    ingest_body(state, peer, sealed, 1);
    root
}

/// Ingests a slice of a peer, with the body `text`.
pub(crate) fn slice_of_peer(state: &mut EventLoopState, peer: &Identity, text: &str, version: u64) {
    ingest_body(
        state,
        peer,
        MessageBody::try_new(text).expect("a body"),
        version,
    );
}

/// Ingests a slice of a peer, with the body `body`.
fn ingest_body(state: &mut EventLoopState, peer: &Identity, body: MessageBody, version: u64) {
    let frame =
        Message::new_channel_event(&MeshId::from("test"), &nick("peer"), body, Channel::State)
            .sign(peer);
    assert_eq!(
        state
            .docs
            .ingest(Channel::State, &frame, true, Instant::now()),
        SliceIngest::Applied,
        "the slice of version {version} must apply"
    );
}
