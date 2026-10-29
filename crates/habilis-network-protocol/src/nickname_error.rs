use std::fmt;

/// An agent nickname — a "safe UTF-8" identifier.
///
/// 1..=32 Unicode scalar values from any script (letters, marks,
/// numbers, symbols, emoji); see `super::ident` for the exact
/// exclusions (control, whitespace, path separators, bidi formatting,
/// and `<` `>` `#` reserved for the `<nick>`/`#mesh` display forms).
/// The wordlist generator (`Nickname::random`) emits `word-word` pairs.
///
/// Deserialization is **validating** (not the derived transparent one): an
/// inbound `author`/`reply` off the wire is run through `new`, so a message
/// carrying control characters, bidi overrides, a reserved `<`/`>`/`#`, or an
/// over-length nickname is rejected at `Message::parse` instead of reaching
/// the surfaced display string (terminal-injection / `<nick>`/`#mesh`
/// spoofing).
///
/// # Examples
///
/// A nickname checks its text on the way in, and a random one always passes the check.
///
/// ```
/// use habilis_network_protocol::Nickname;
///
/// let nick = Nickname::try_new("alice").expect("a valid nickname");
/// assert_eq!(nick.as_str(), "alice");
///
/// let random = Nickname::random();
/// assert!(Nickname::try_new(random.as_str()).is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, ::serde::Serialize)]
#[serde(transparent)]
pub struct Nickname(String);

impl Nickname {
    /// The wrapped string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ::std::fmt::Display for Nickname {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> ::serde::Deserialize<'de> for Nickname {
    fn deserialize<Decoder>(deserializer: Decoder) -> ::std::result::Result<Self, Decoder::Error>
    where
        Decoder: ::serde::Deserializer<'de>,
    {
        let raw = <String as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(&raw).map_err(::serde::de::Error::custom)
    }
}

impl ::std::str::FromStr for Nickname {
    type Err = NicknameError;
    fn from_str(text: &str) -> ::std::result::Result<Self, Self::Err> {
        Self::try_new(text)
    }
}

impl ::std::convert::AsRef<str> for Nickname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl ::std::borrow::Borrow<str> for Nickname {
    fn borrow(&self) -> &str {
        &self.0
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl ::std::convert::From<&str> for Nickname {
    fn from(text: &str) -> Self {
        Self::try_new(text).expect(concat!(
            "invalid ",
            stringify!(Nickname),
            " in test fixture"
        ))
    }
}

/// Why a nickname was refused: its length, or a character outside the allowed set.
///
/// # Examples
///
/// A rejected nickname returns an error that says why.
///
/// ```
/// use habilis_network_protocol::Nickname;
///
/// let error = Nickname::try_new("").unwrap_err();
/// assert!(!error.to_string().is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum NicknameError {
    /// The nickname is not the right length.
    Length(usize),
    /// The nickname has a character outside the alphabet.
    Charset(String),
}

impl fmt::Display for NicknameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NicknameError::Length(len) => {
                write!(
                    formatter,
                    "nickname must be {}..={} characters, got {len}",
                    super::identifier::MIN_CHARS,
                    super::identifier::MAX_CHARS
                )
            }
            NicknameError::Charset(value) => {
                write!(
                    formatter,
                    "nickname must not contain control characters, whitespace, bidirectional formatting characters, or any of / \\ < > #, got {value:?}"
                )
            }
        }
    }
}

impl std::error::Error for NicknameError {}

impl Nickname {
    /// Validate and construct a nickname.
    ///
    /// # Errors
    /// Returns [`NicknameError`] if `value` is empty, longer than 32
    /// characters, or contains a forbidden scalar (see
    /// `is_forbidden`).
    pub fn try_new(value: &str) -> Result<Self, NicknameError> {
        let value: String = value.to_owned();
        let count = value.chars().count();
        if !(super::identifier::MIN_CHARS..=super::identifier::MAX_CHARS).contains(&count) {
            return Err(NicknameError::Length(count));
        }
        if value.chars().any(super::identifier::is_forbidden) {
            return Err(NicknameError::Charset(value));
        }
        Ok(Self(value))
    }

    /// Generate a random `word-word` nickname from the curated wordlist.
    ///
    /// # Panics
    /// Never in practice: the curated wordlist is a non-empty,
    /// lowercase-ASCII constant, so selection and validation always
    /// succeed.
    #[must_use]
    pub fn random() -> Self {
        Self::try_new(&super::wordlist::random_pair())
            .expect("wordlist combinations are always valid nicknames")
    }
}

#[cfg(test)]
mod tests {
    use super::Nickname;

    #[test]
    fn accepts_valid_nicknames() {
        let _guard = ::habilis_network_test_tracing::init();
        for ok in [
            "a",
            "alice",
            "swift-cedar",
            "alice-bot-7",
            "snake_case",
            "abc123",
            "Alice",    // uppercase
            "1abc",     // leading digit
            "café",     // accents
            "日本語",   // CJK
            "agent-💬", // emoji
            "👨‍👩‍👧",       // ZWJ emoji sequence
            "alice!",   // punctuation symbol
        ] {
            Nickname::try_new(ok).unwrap_or_else(|_| panic!("expected {ok} to validate"));
        }
    }

    #[test]
    fn rejects_empty_and_overlong() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            Nickname::try_new("").is_err(),
            "an empty nickname is refused"
        );
        let too_long = "a".repeat(super::super::identifier::MAX_CHARS + 1);
        assert!(
            Nickname::try_new(&too_long).is_err(),
            "an overlong nickname is refused"
        );
    }

    #[test]
    fn length_cap_counts_characters_not_bytes() {
        let _guard = ::habilis_network_test_tracing::init();
        // 32 multibyte chars (96 bytes) is fine; 33 is not.
        assert!(
            Nickname::try_new(&"あ".repeat(32)).is_ok(),
            "a 32-character nickname of wide characters is accepted"
        );
        assert!(
            Nickname::try_new(&"あ".repeat(33)).is_err(),
            "a 33-character nickname of wide characters is refused"
        );
    }

    #[test]
    fn rejects_unsafe_chars() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            Nickname::try_new("alice bot").is_err(),
            "a space in a nickname is refused"
        ); // space
        assert!(
            Nickname::try_new("alice/bob").is_err(),
            "a slash in a nickname is refused"
        ); // path sep
        assert!(
            Nickname::try_new("alice\\bob").is_err(),
            "a backslash in a nickname is refused"
        ); // path sep
        assert!(
            Nickname::try_new("alice\nbob").is_err(),
            "a newline in a nickname is refused"
        ); // newline
        assert!(
            Nickname::try_new("alice\0bob").is_err(),
            "a nul byte in a nickname is refused"
        ); // NUL
        assert!(
            Nickname::try_new("alice\u{7}bob").is_err(),
            "a bell character in a nickname is refused"
        ); // bell control
        assert!(
            Nickname::try_new("alice\u{202E}bob").is_err(),
            "a right-to-left override in a nickname is refused"
        ); // RLO (bidi override)
        assert!(
            Nickname::try_new("alice\u{200F}bob").is_err(),
            "a right-to-left mark in a nickname is refused"
        ); // RLM (bidi mark)
        assert!(
            Nickname::try_new("alice\u{61C}bob").is_err(),
            "an arabic letter mark in a nickname is refused"
        ); // ALM (Arabic letter mark)
        assert!(
            Nickname::try_new("a<b").is_err(),
            "a less-than sign in a nickname is refused"
        ); // reserved for <nick>
        assert!(
            Nickname::try_new("a>b").is_err(),
            "a greater-than sign in a nickname is refused"
        ); // reserved for <nick>
        assert!(
            Nickname::try_new("a#b").is_err(),
            "a hash sign in a nickname is refused"
        ); // reserved for #mesh
    }

    #[test]
    fn random_always_validates() {
        let _guard = ::habilis_network_test_tracing::init();
        for _ in 0..20 {
            let nickname = Nickname::random();
            Nickname::try_new(nickname.as_str()).expect("random must round-trip");
        }
    }

    #[test]
    fn serde_transparent_round_trip() {
        let _guard = ::habilis_network_test_tracing::init();
        let nickname = Nickname::from("swift-cedar");
        let json = serde_json::to_string(&nickname).unwrap();
        assert_eq!(
            json, "\"swift-cedar\"",
            "a nickname serializes as a plain json string"
        );
        let parsed: Nickname = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, nickname, "a nickname survives a json round trip");
    }

    #[test]
    fn deserialize_rejects_unsafe_nicknames() {
        let _guard = ::habilis_network_test_tracing::init();
        // The validating Deserialize rejects what `new` rejects, so a crafted
        // wire nickname can't bypass the charset/length rules.
        assert!(
            serde_json::from_str::<Nickname>("\"a#b\"").is_err(),
            "a hash in a json nickname is refused"
        ); // reserved
        assert!(
            serde_json::from_str::<Nickname>("\"a<b\"").is_err(),
            "a less-than sign in a json nickname is refused"
        ); // reserved
        assert!(
            serde_json::from_str::<Nickname>("\"a\\u0007b\"").is_err(),
            "a bell in a json nickname is refused"
        ); // bell
        assert!(
            serde_json::from_str::<Nickname>("\"a\\u202Eb\"").is_err(),
            "a right-to-left override in a json nickname is refused"
        ); // RLO bidi
        assert!(
            serde_json::from_str::<Nickname>("\"\"").is_err(),
            "an empty json nickname is refused"
        ); // empty
        let overlong = format!("\"{}\"", "a".repeat(33));
        assert!(
            serde_json::from_str::<Nickname>(&overlong).is_err(),
            "an overlong json nickname is refused"
        );
        // A valid nickname still round-trips.
        assert!(
            serde_json::from_str::<Nickname>("\"swift-cedar\"").is_ok(),
            "a plain json nickname is accepted"
        );
    }
}
