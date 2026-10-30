//! [`MessageId`] — a protocol message identifier (UUID v4 string form).
//! The newtype prevents argument-order confusion between `id` and
//! `after`-cursor parameters that carry the same kind of value.

use serde::de;
use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use uuid::Uuid;

use std::error;
/// A protocol message identifier — UUID v4 string form.
///
/// Construction goes through `new` (validates UUID format) or `random`
/// (mints a fresh v4). The newtype prevents argument-order confusion
/// between `id` and `after`-cursor parameters that carry the same kind
/// of value. Deserialization is **validating** (not the derived
/// transparent one): an inbound id off the wire is run through `new`, so a
/// non-UUID `id` is rejected at `Message::parse` rather than panicking later
/// in `as_uuid_bytes` (the dedup key path).
///
/// # Examples
///
/// A random message id is a UUID, and its text reads back as a valid id.
///
/// ```
/// use habilis_network_protocol::messages::MessageId;
///
/// let id = MessageId::random();
/// assert!(MessageId::try_new(id.as_str()).is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, ::serde::Serialize)]
#[serde(transparent)]
pub struct MessageId(String);

impl MessageId {
    /// The wrapped string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> ::serde::Deserialize<'de> for MessageId {
    fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
    where
        Decoder: ::serde::Deserializer<'de>,
    {
        let raw = <String as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(&raw).map_err(de::Error::custom)
    }
}

impl FromStr for MessageId {
    type Err = IdError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::try_new(text)
    }
}

impl AsRef<str> for MessageId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for MessageId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl From<&str> for MessageId {
    fn from(text: &str) -> Self {
        Self::try_new(text).expect(concat!(
            "invalid ",
            stringify!(MessageId),
            " in test fixture"
        ))
    }
}

/// A message id text that is not a valid UUID.
///
/// # Examples
///
/// Text that is not a UUID returns this error.
///
/// ```
/// use habilis_network_protocol::messages::MessageId;
///
/// let error = MessageId::try_new("not a uuid").unwrap_err();
/// assert!(!error.to_string().is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct IdError(String);

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid message id: {:?}", self.0)
    }
}

impl error::Error for IdError {}

impl MessageId {
    /// # Errors
    /// The value is not a valid UUID.
    pub fn try_new(value: &str) -> Result<Self, IdError> {
        let value: String = value.to_owned();
        Uuid::parse_str(&value).map_err(|_| IdError(value.clone()))?;
        Ok(Self(value))
    }

    /// A new random id, a version 4 UUID.
    #[must_use]
    pub fn random() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// The id's 16 raw UUID bytes. They are the id half of the input of
    /// [`Message::dedup_key`](crate::Message::dedup_key), which hashes them
    /// with the author's key. Infallible: a `MessageId` is always a valid
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
    fn accepts_uuid_v4() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = MessageId::try_new("550e8400-e29b-41d4-a716-446655440000")
            .expect("the literal is a well-formed UUID, so a MessageId accepts it");
        assert_eq!(
            id.as_str(),
            "550e8400-e29b-41d4-a716-446655440000",
            "a v4 uuid is accepted and kept as written"
        );
    }

    #[test]
    fn rejects_garbage() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            MessageId::try_new("not-a-uuid").is_err(),
            "a non-uuid is refused"
        );
        assert!(MessageId::try_new("").is_err(), "an empty id is refused");
        assert!(
            MessageId::try_new("550e8400").is_err(),
            "a short id is refused"
        );
    }

    #[test]
    fn random_produces_valid_id() {
        let _guard = ::habilis_network_test_tracing::init();
        let first = MessageId::random();
        let second = MessageId::random();
        assert_ne!(first, second, "two random ids differ");
        MessageId::try_new(first.as_str()).expect("random must round-trip through new");
    }

    #[test]
    fn from_str_works_for_clap() {
        let _guard = ::habilis_network_test_tracing::init();
        let id: MessageId = "550e8400-e29b-41d4-a716-446655440000"
            .parse()
            .expect("the literal is a well-formed UUID, so it parses as a MessageId");
        assert_eq!(
            id.as_str(),
            "550e8400-e29b-41d4-a716-446655440000",
            "an id parsed from text keeps its text"
        );
    }

    #[test]
    fn serde_transparent_round_trip() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = MessageId::random();
        let json = serde_json::to_string(&id)
            .expect("a MessageId is a string, which serde_json serializes");
        assert_eq!(
            json,
            format!("\"{}\"", id.as_str()),
            "a message id serializes as a plain json string"
        );
        let parsed: MessageId = serde_json::from_str(&json)
            .expect("the JSON string in this test is a well-formed MessageId");
        assert_eq!(parsed, id, "a message id survives a json round trip");
    }

    #[test]
    fn deserialize_rejects_non_uuid() {
        let _guard = ::habilis_network_test_tracing::init();
        // The derived transparent Deserialize would accept any string and let
        // `as_uuid_bytes` panic later; the validating impl rejects it here.
        let not_uuid: Result<MessageId, _> = serde_json::from_str("\"not-a-uuid\"");
        assert!(not_uuid.is_err(), "a non-uuid json id is refused");
        let short: Result<MessageId, _> = serde_json::from_str("\"550e8400\"");
        assert!(short.is_err(), "a short json id is refused");
        let empty: Result<MessageId, _> = serde_json::from_str("\"\"");
        assert!(empty.is_err(), "an empty json id is refused");
    }
}
