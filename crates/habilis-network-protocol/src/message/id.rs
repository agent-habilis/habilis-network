//! [`MessageId`] — a protocol message identifier (UUID v4 string form).
//! The newtype prevents argument-order confusion between `id` and
//! `after`-cursor parameters that carry the same kind of value.

use std::fmt;

use uuid::Uuid;

use crate::newtype::string_newtype;

string_newtype!(
/// A protocol message identifier — UUID v4 string form.
///
/// Construction goes through `new` (validates UUID format) or `random`
/// (mints a fresh v4). The newtype prevents argument-order confusion
/// between `id` and `after`-cursor parameters that carry the same kind
/// of value. Deserialization is **validating** (not the derived
/// transparent one): an inbound id off the wire is run through `new`, so a
/// non-UUID `id` is rejected at `Message::parse` rather than panicking later
/// in `as_uuid_bytes` (the anti-entropy digest path).
    MessageId,
    error = IdError,
    deserialize,
    from_str,
    as_ref,
    borrow,
    test_from,
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdError(String);

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid message id: {:?}", self.0)
    }
}

impl std::error::Error for IdError {}

impl MessageId {
    /// # Errors
    /// The value is not a valid UUID.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        Uuid::parse_str(&value).map_err(|_| IdError(value.clone()))?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn random() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// The id's 16 raw UUID bytes — the compact form packed into an
    /// anti-entropy digest (vs the 36-char string), so far more ids fit
    /// one gossip message. Infallible: a `MessageId` is always a valid
    /// UUID (enforced by `new`).
    pub(crate) fn as_uuid_bytes(&self) -> [u8; 16] {
        Uuid::parse_str(&self.0)
            .expect("MessageId always holds a valid UUID")
            .into_bytes()
    }
}

#[cfg(test)]
mod id_tests {
    use super::MessageId;

    #[test]
    fn new_accepts_uuid_v4() {
        let id = MessageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(id.as_str(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn new_rejects_garbage() {
        assert!(MessageId::new("not-a-uuid").is_err());
        assert!(MessageId::new("").is_err());
        assert!(MessageId::new("550e8400").is_err());
    }

    #[test]
    fn random_produces_valid_id() {
        let first = MessageId::random();
        let second = MessageId::random();
        assert_ne!(first, second);
        MessageId::new(first.as_str()).expect("random must round-trip through new");
    }

    #[test]
    fn from_str_works_for_clap() {
        let id: MessageId = "550e8400-e29b-41d4-a716-446655440000".parse().unwrap();
        assert_eq!(id.as_str(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn serde_transparent_round_trip() {
        let id = MessageId::random();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", id.as_str()));
        let parsed: MessageId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn deserialize_rejects_non_uuid() {
        // The derived transparent Deserialize would accept any string and let
        // `as_uuid_bytes` panic later; the validating impl rejects it here.
        assert!(serde_json::from_str::<MessageId>("\"not-a-uuid\"").is_err());
        assert!(serde_json::from_str::<MessageId>("\"550e8400\"").is_err());
        assert!(serde_json::from_str::<MessageId>("\"\"").is_err());
    }
}
