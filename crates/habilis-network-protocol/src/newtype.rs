//! Tests of the validated string newtypes: each one's wire form, and that its deserialization rejects what `try_new` rejects.

#[cfg(test)]
mod tests {
    use crate::meshes::{MeshId, MeshName};
    use crate::messages::{AppTag, CorrId, MessageBody, MessageId, ShardGroup};
    use crate::nickname_error::Nickname;

    /// Assert that a value serializes as the bare JSON string `raw`.
    fn assert_transparent<T: serde::Serialize>(value: &T, raw: &str) {
        let json = serde_json::to_string(value).expect("serialize");
        assert_eq!(json, format!("{raw:?}"), "not transparent");
    }

    /// The wire form of each newtype must not change. All are
    /// `#[serde(transparent)]`, so each serializes as a bare JSON string
    /// and round-trips through its own validating `Deserialize`.
    #[test]
    fn every_newtype_is_transparent_on_the_wire() {
        let _guard = ::habilis_network_test_tracing::init();
        let uuid = "b3f1c2d4-5e6a-4b8c-9d0e-1f2a3b4c5d6e";
        assert_transparent(
            &Nickname::try_new("lotus-anvil").expect("nick"),
            "lotus-anvil",
        );
        assert_transparent(&MessageId::try_new(uuid).expect("id"), uuid);
        assert_transparent(&MessageBody::try_new("hello").expect("body"), "hello");
        assert_transparent(&AppTag::try_new("app_msg").expect("tag"), "app_msg");
        assert_transparent(&CorrId::try_new("corr-1").expect("corr"), "corr-1");
        assert_transparent(&ShardGroup::parse_uuid(uuid).expect("group"), uuid);
        assert_transparent(
            &MeshName::try_new("kernel-parch").expect("name"),
            "kernel-parch",
        );
    }

    /// Deserialization stays **validating** — the property the hand-written
    /// impls existed for, and the one a `#[serde(transparent)]` derive would
    /// have silently dropped.
    #[test]
    fn deserialization_still_rejects_what_new_rejects() {
        let _guard = ::habilis_network_test_tracing::init();
        let nickname: Result<Nickname, _> = serde_json::from_str("\"has space\"");
        assert!(nickname.is_err(), "a json nickname with a space is refused");
        let message_id: Result<MessageId, _> = serde_json::from_str("\"not-a-uuid\"");
        assert!(
            message_id.is_err(),
            "a json message id that is not a uuid is refused"
        );
        let body: Result<MessageBody, _> = serde_json::from_str("\"\\u0007\"");
        assert!(body.is_err(), "a json message body with a bell is refused");
        let app_tag: Result<AppTag, _> = serde_json::from_str("\"has space\"");
        assert!(app_tag.is_err(), "a json app tag with a space is refused");
        let corr_id: Result<CorrId, _> = serde_json::from_str("\"\"");
        assert!(corr_id.is_err(), "an empty json correlation id is refused");
        let shard_group: Result<ShardGroup, _> = serde_json::from_str("\"not-a-uuid\"");
        assert!(
            shard_group.is_err(),
            "a json shard group that is not a uuid is refused"
        );
        let mesh_id: Result<MeshId, _> = serde_json::from_str("\"!!\"");
        assert!(mesh_id.is_err(), "a json mesh id of punctuation is refused");
    }
}
