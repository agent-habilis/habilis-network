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
    use habilis_network_test_tracing::test;

    #[test]
    fn accepts_ascii() {
        MessageBody::try_new("hello world").unwrap();
        MessageBody::try_new("").unwrap();
        MessageBody::try_new("special chars: !@#$%^&*()").unwrap();
    }

    #[test]
    fn accepts_unicode() {
        MessageBody::try_new("héllo").unwrap();
        MessageBody::try_new("emoji 🎉").unwrap();
        MessageBody::try_new("日本語のメッセージ").unwrap();
    }

    #[test]
    fn accepts_newline_and_tab() {
        MessageBody::try_new("line one\nline two").unwrap();
        MessageBody::try_new("col1\tcol2").unwrap();
        MessageBody::try_new("crlf\r\nline").unwrap();
    }

    #[test]
    fn rejects_control_chars() {
        assert!(MessageBody::try_new("nul\0byte").is_err());
        assert!(MessageBody::try_new("bell\u{7}char").is_err());
    }

    #[test]
    fn serde_transparent_round_trip() {
        let body = MessageBody::from("hello");
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(json, "\"hello\"");
        let parsed: MessageBody = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn deserialize_rejects_control_chars() {
        // The validating Deserialize rejects a body a crafted wire message
        // could otherwise smuggle past `new` (e.g. a NUL or an ANSI escape).
        assert!(serde_json::from_str::<MessageBody>("\"evil\\u0000body\"").is_err());
        assert!(serde_json::from_str::<MessageBody>("\"esc\\u001b[31m\"").is_err());
        // Newline/tab and ordinary text still round-trip.
        assert!(serde_json::from_str::<MessageBody>("\"line\\nfeed\"").is_ok());
        assert!(serde_json::from_str::<MessageBody>("\"\"").is_ok());
    }
}
