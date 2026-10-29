//! [`MeshId`] — the validated bare `Base58Check` mesh string. Raw strings stay
//! outside the type until their checksum and complete payload have been
//! validated.

use std::fmt;

use super::LockedMesh;

const MIN_LEN: usize = 3;
const MAX_LEN: usize = 512;

/// A mesh identifier — the encoded bare `Base58Check` string.
///
/// Construction validates the length, Base58 charset, checksum, version, and
/// complete payload. Consequently every `MeshId` can be decoded as a [`LockedMesh`](super::LockedMesh).
#[derive(Debug, Clone, PartialEq, Eq, Hash, ::serde::Serialize)]
#[serde(transparent)]
pub struct MeshId(String);

impl MeshId {
    /// The wrapped string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ::std::fmt::Display for MeshId {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> ::serde::Deserialize<'de> for MeshId {
    fn deserialize<Decoder>(deserializer: Decoder) -> ::std::result::Result<Self, Decoder::Error>
    where
        Decoder: ::serde::Deserializer<'de>,
    {
        let raw = <String as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(&raw).map_err(::serde::de::Error::custom)
    }
}

impl ::std::str::FromStr for MeshId {
    type Err = MeshIdError;
    fn from_str(text: &str) -> ::std::result::Result<Self, Self::Err> {
        Self::try_new(text)
    }
}

impl ::std::convert::AsRef<str> for MeshId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl ::std::borrow::Borrow<str> for MeshId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// Why a mesh id text was refused: its length, a character outside the alphabet, or a bad hash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum MeshIdError {
    /// The id is not the right length.
    Length(usize),
    /// The id has a character outside the alphabet.
    Charset(String),
    /// The id does not carry a valid hash.
    InvalidHash,
}

impl fmt::Display for MeshIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MeshIdError::Length(len) => {
                write!(
                    formatter,
                    "mesh id must be {MIN_LEN}..={MAX_LEN} chars, got {len}"
                )
            }
            MeshIdError::Charset(value) => {
                write!(formatter, "mesh id has invalid Base58 char(s): {value:?}")
            }
            MeshIdError::InvalidHash => formatter.write_str("invalid gossip hash"),
        }
    }
}

impl std::error::Error for MeshIdError {}

fn is_base58_char(ch: char) -> bool {
    matches!(ch,
        '1'..='9'
        | 'A'..='H' | 'J'..='N' | 'P'..='Z'
        | 'a'..='k' | 'm'..='z'
    )
}

impl MeshId {
    /// # Errors
    /// The value is empty, over-long, or not valid base58.
    pub fn try_new(value: &str) -> Result<Self, MeshIdError> {
        let value: String = value.to_owned();
        let len = value.len();
        if !(MIN_LEN..=MAX_LEN).contains(&len) {
            return Err(MeshIdError::Length(len));
        }
        if !value.chars().all(is_base58_char) {
            return Err(MeshIdError::Charset(value));
        }
        let _: LockedMesh = value.parse().map_err(|_| MeshIdError::InvalidHash)?;
        Ok(Self(value))
    }
}

impl TryFrom<String> for MeshId {
    type Error = MeshIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(&value)
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl From<&str> for MeshId {
    fn from(label: &str) -> Self {
        if let Ok(id) = Self::try_new(label) {
            return id;
        }
        let mesh = super::Mesh::for_topic(label, super::MeshConfig::loopback())
            .expect("generated test mesh");
        Self::try_new(&mesh.to_string()).expect("generated test mesh id must be valid")
    }
}

#[cfg(test)]
mod mesh_id_tests {
    use super::{LockedMesh, MeshId, MeshIdError};

    fn valid_id() -> String {
        use super::super::{Mesh, MeshConfig, MeshName};
        Mesh::try_new(
            crate::crypto::Seed::new([1u8; 32]),
            MeshName::try_new("test").unwrap(),
            MeshConfig::loopback(),
        )
        .unwrap()
        .to_string()
    }

    #[test]
    fn accepts_well_formed_id() {
        let _guard = ::habilis_network_test_tracing::init();
        MeshId::try_new(&valid_id()).unwrap();
    }

    #[test]
    fn rejects_too_short() {
        let _guard = ::habilis_network_test_tracing::init();
        assert!(
            matches!(MeshId::try_new("a"), Err(MeshIdError::Length(_))),
            "a one-character mesh id is a length error"
        );
    }

    #[test]
    fn rejects_invalid_base58_chars() {
        let _guard = ::habilis_network_test_tracing::init();
        // `0`, `O`, `I`, `l` are not in the Base58 alphabet — and neither is
        // the glyph prefix ids used to carry, so a stale paste lands here too.
        assert!(
            matches!(MeshId::try_new("AbCdEf0xyz"), Err(MeshIdError::Charset(_))),
            "a mesh id with non-base58 characters is a charset error"
        );
        assert!(
            matches!(
                MeshId::try_new("AbCdEf0xyzZZ"),
                Err(MeshIdError::Charset(_))
            ),
            "a longer mesh id with non-base58 characters is a charset error"
        );
    }

    #[test]
    fn serde_transparent_round_trip() {
        let _guard = ::habilis_network_test_tracing::init();
        let id_str = valid_id();
        let id = MeshId::try_new(&id_str).unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(
            json,
            format!("\"{id_str}\""),
            "a mesh id serializes as a plain json string"
        );
        let parsed: MeshId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id, "a mesh id survives a json round trip");
    }

    #[test]
    fn rejects_a_mistyped_hash() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut mistyped = valid_id();
        let replacement = if mistyped.ends_with('1') { "2" } else { "1" };
        mistyped.replace_range(mistyped.len() - 1.., replacement);
        assert_eq!(
            MeshId::try_new(&mistyped),
            Err(MeshIdError::InvalidHash),
            "a mistyped hash is refused as an invalid hash"
        );
    }

    #[test]
    fn serde_rejects_an_invalid_hash() {
        let _guard = ::habilis_network_test_tracing::init();
        let invalid = serde_json::to_string("AbCdEf1234567").unwrap();
        let error = serde_json::from_str::<MeshId>(&invalid).unwrap_err();
        assert!(
            error.to_string().contains("invalid gossip hash"),
            "a json mesh id with an invalid hash names the hash"
        );
    }

    #[test]
    fn every_mesh_id_decodes_as_a_mesh() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = MeshId::try_new(&valid_id()).unwrap();
        let _: LockedMesh = id.as_str().parse().unwrap();
    }

    #[test]
    fn canonical_form_has_no_uri_wrapping() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = valid_id();
        assert!(!id.contains("://"), "got {id}");
        assert!(!id.contains('💬'), "got {id}");
    }
}
