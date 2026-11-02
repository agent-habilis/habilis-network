//! [`MessageBody`] — a protocol message body (UTF-8 text). Newlines and
//! tabs are allowed (multi-line snippets); other control characters are
//! rejected. Empty is legal: presence and `PeerInfo` messages use it.

use serde::de;
use std::fmt;
use std::str::FromStr;

use std::error;
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
/// use habilis_network_protocol::messages::MessageBody;
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

impl fmt::Display for MessageBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> ::serde::Deserialize<'de> for MessageBody {
    fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
    where
        Decoder: ::serde::Deserializer<'de>,
    {
        let raw = <String as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(&raw).map_err(de::Error::custom)
    }
}

impl FromStr for MessageBody {
    type Err = BodyError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::try_new(text)
    }
}

impl AsRef<str> for MessageBody {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl From<&str> for MessageBody {
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
/// use habilis_network_protocol::messages::MessageBody;
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

impl error::Error for BodyError {}

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
        MessageBody::try_new("hello world")
            .expect("the literal body is ASCII text under the size limit");
        MessageBody::try_new("").expect("an empty body is a valid body");
        MessageBody::try_new("special chars: !@#$%^&*()")
            .expect("the special characters are printable ASCII, which a body accepts");
    }

    #[test]
    fn accepts_unicode() {
        let _guard = ::habilis_network_test_tracing::init();
        MessageBody::try_new("héllo")
            .expect("the literal is valid UTF-8 text, which a body accepts");
        MessageBody::try_new("emoji 🎉")
            .expect("the emoji is valid UTF-8 text, which a body accepts");
        MessageBody::try_new("日本語のメッセージ")
            .expect("the Japanese literal is valid UTF-8 text, which a body accepts");
    }

    #[test]
    fn accepts_newline_and_tab() {
        let _guard = ::habilis_network_test_tracing::init();
        MessageBody::try_new("line one\nline two")
            .expect("a newline is plain text, which a body accepts");
        MessageBody::try_new("col1\tcol2").expect("a tab is plain text, which a body accepts");
        MessageBody::try_new("crlf\r\nline")
            .expect("CR and LF are plain text, which a body accepts");
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
        let json =
            serde_json::to_string(&body).expect("a body is a string, which serde_json serializes");
        assert_eq!(
            json, "\"hello\"",
            "a message body serializes as a plain json string"
        );
        let parsed: MessageBody =
            serde_json::from_str(&json).expect("the JSON literal in this test is a valid body");
        assert_eq!(parsed, body, "a message body survives a json round trip");
    }

    #[test]
    fn deserialize_rejects_control_chars() {
        let _guard = ::habilis_network_test_tracing::init();
        // The validating Deserialize rejects a body a crafted wire message
        // could otherwise smuggle past `new` (e.g. a NUL or an ANSI escape).
        let with_nul: Result<MessageBody, _> = serde_json::from_str("\"evil\\u0000body\"");
        assert!(
            with_nul.is_err(),
            "a json body with a nul escape is refused"
        );
        let with_escape: Result<MessageBody, _> = serde_json::from_str("\"esc\\u001b[31m\"");
        assert!(
            with_escape.is_err(),
            "a json body with an escape sequence is refused"
        );
        // Newline/tab and ordinary text still round-trip.
        let with_line_feed: Result<MessageBody, _> = serde_json::from_str("\"line\\nfeed\"");
        assert!(
            with_line_feed.is_ok(),
            "a json body with a line feed is accepted"
        );
        let empty: Result<MessageBody, _> = serde_json::from_str("\"\"");
        assert!(empty.is_ok(), "an empty json body is accepted");
    }
}
