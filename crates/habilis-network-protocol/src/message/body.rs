//! [`MessageBody`] — a protocol message body (UTF-8 text). Newlines and
//! tabs are allowed (multi-line snippets); other control characters are
//! rejected. Empty is legal: presence and `PeerInfo` messages use it.

use std::fmt;

use crate::newtype::string_newtype;

string_newtype!(
/// A protocol message body — UTF-8 text. Newlines and tabs are allowed
/// (multi-line snippets); other control characters are rejected. Empty
/// is legal: presence and `PeerInfo` messages use it.
///
/// Deserialization is **validating** (not the derived transparent one): an
/// inbound body off the wire is run through `new`, so a message carrying
/// control characters (e.g. ANSI/terminal escapes) is rejected at
/// `Message::parse` instead of being embedded byte-for-byte in the surfaced
/// display string.
    MessageBody,
    error = BodyError,
    deserialize,
    from_str,
    as_ref,
    test_from,
);

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn new(value: impl Into<String>) -> Result<Self, BodyError> {
        let value = value.into();
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
    fn new_accepts_ascii() {
        MessageBody::new("hello world").unwrap();
        MessageBody::new("").unwrap();
        MessageBody::new("special chars: !@#$%^&*()").unwrap();
    }

    #[test]
    fn new_accepts_unicode() {
        MessageBody::new("héllo").unwrap();
        MessageBody::new("emoji 🎉").unwrap();
        MessageBody::new("日本語のメッセージ").unwrap();
    }

    #[test]
    fn new_accepts_newline_and_tab() {
        MessageBody::new("line one\nline two").unwrap();
        MessageBody::new("col1\tcol2").unwrap();
        MessageBody::new("crlf\r\nline").unwrap();
    }

    #[test]
    fn new_rejects_control_chars() {
        assert!(MessageBody::new("nul\0byte").is_err());
        assert!(MessageBody::new("bell\u{7}char").is_err());
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
