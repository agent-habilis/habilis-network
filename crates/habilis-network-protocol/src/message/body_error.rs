//! [`MessageBody`] — a protocol message body (UTF-8 text). Newlines and
//! tabs are allowed (multi-line snippets); other control characters are
//! rejected. Empty is legal: presence and `PeerInfo` messages use it.

use std::fmt;

/// A protocol message body — UTF-8 text. Newlines and tabs are allowed
/// (multi-line snippets); other control characters are rejected. Empty
/// is legal: presence and `PeerInfo` messages use it.
///
/// Deserialization is **validating** (not the derived transparent one): an
/// inbound body off the wire is run through `new`, so a message carrying
/// control characters (e.g. ANSI/terminal escapes) is rejected at
/// `Message::parse` instead of being embedded byte-for-byte in the surfaced
/// display string.
///
/// # Examples
///
/// A message body is text that holds no control characters.
///
/// ```
/// use habilis_network_protocol::message::MessageBody;
///
/// let body = MessageBody::try_new("hello").expect("a valid body");
/// assert_eq!(body.as_str(), "hello");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, ::serde::Serialize)]
#[serde(transparent)]
pub struct MessageBody(String);

impl MessageBody {
    /// The wrapped string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ::std::fmt::Display for MessageBody {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> ::serde::Deserialize<'de> for MessageBody {
    fn deserialize<Decoder>(deserializer: Decoder) -> ::std::result::Result<Self, Decoder::Error>
    where
        Decoder: ::serde::Deserializer<'de>,
    {
        let raw = <String as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(&raw).map_err(::serde::de::Error::custom)
    }
}

impl ::std::str::FromStr for MessageBody {
    type Err = BodyError;
    fn from_str(text: &str) -> ::std::result::Result<Self, Self::Err> {
        Self::try_new(text)
    }
}

impl ::std::convert::AsRef<str> for MessageBody {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl ::std::convert::From<&str> for MessageBody {
    fn from(text: &str) -> Self {
        Self::try_new(text).expect(concat!(
            "invalid ",
            stringify!(MessageBody),
            " in test fixture"
        ))
    }
}

/// A message body with a control character other than tab or newline.
///
/// # Examples
///
/// A body with a control character returns this error.
///
/// ```
/// use habilis_network_protocol::message::MessageBody;
///
/// let error = MessageBody::try_new("bell\u{7}").unwrap_err();
/// assert!(!error.to_string().is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct BodyError(String);

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "message body must not contain control characters other than tab/newline, got {:?}",
            self.0
        )
    }
}

impl std::error::Error for BodyError {}

impl MessageBody {
    /// Construct a body. Accepts any UTF-8 text; the only restriction is
    /// control characters other than `\t`/`\n`/`\r`.
    ///
    /// # Errors
    /// Returns [`BodyError`] if `value` contains a disallowed control
    /// character (e.g. NUL or other C0/C1 controls).
    pub fn try_new(value: &str) -> Result<Self, BodyError> {
        let value: String = value.to_owned();
        if value
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t' | '\r'))
        {
            return Err(BodyError(value));
        }
        Ok(Self(value))
    }
}

impl AsRef<[u8]> for MessageBody {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod body_tests {
    use super::MessageBody;

    #[test]
    fn accepts_ascii() {
        let _guard = ::habilis_network_test_tracing::init();
        MessageBody::try_new("hello world").unwrap();
        MessageBody::try_new("").unwrap();
        MessageBody::try_new("special chars: !@#$%^&*()").unwrap();
    }

    #[test]
    fn accepts_unicode() {
        let _guard = ::habilis_network_test_tracing::init();
        MessageBody::try_new("héllo").unwrap();
        MessageBody::try_new("emoji 🎉").unwrap();
        MessageBody::try_new("日本語のメッセージ").unwrap();
    }

    #[test]
    fn accepts_newline_and_tab() {
        let _guard = ::habilis_network_test_tracing::init();
        MessageBody::try_new("line one\nline two").unwrap();
        MessageBody::try_new("col1\tcol2").unwrap();
        MessageBody::try_new("crlf\r\nline").unwrap();
    }

    #[test]
    fn rejects_control_chars() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            MessageBody::try_new("nul\0byte").is_err(),
            "a body with a nul byte is refused"
        );
        assert!(
            MessageBody::try_new("bell\u{7}char").is_err(),
            "a body with a bell character is refused"
        );
    }

    #[test]
    fn serde_transparent_round_trip() {
        let _guard = ::habilis_network_test_tracing::init();
        let body = MessageBody::from("hello");
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(
            json, "\"hello\"",
            "a message body serializes as a plain json string"
        );
        let parsed: MessageBody = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, body, "a message body survives a json round trip");
    }

    #[test]
    fn deserialize_rejects_control_chars() {
        let _guard = ::habilis_network_test_tracing::init();
        // The validating Deserialize rejects a body a crafted wire message
        // could otherwise smuggle past `new` (e.g. a NUL or an ANSI escape).
        assert!(
            serde_json::from_str::<MessageBody>("\"evil\\u0000body\"").is_err(),
            "a json body with a nul escape is refused"
        );
        assert!(
            serde_json::from_str::<MessageBody>("\"esc\\u001b[31m\"").is_err(),
            "a json body with an escape sequence is refused"
        );
        // Newline/tab and ordinary text still round-trip.
        assert!(
            serde_json::from_str::<MessageBody>("\"line\\nfeed\"").is_ok(),
            "a json body with a line feed is accepted"
        );
        assert!(
            serde_json::from_str::<MessageBody>("\"\"").is_ok(),
            "an empty json body is accepted"
        );
    }
}
