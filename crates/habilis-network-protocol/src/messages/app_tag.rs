//! The application-payload tag of an app frame.

use super::AppTagError;
use serde::de;
use std::fmt;

/// An opaque application-payload tag — the wire discriminant for a
/// [`super::MessageKind::App`] frame (serialized in the `tag` field). The engine never
/// interprets it; the consuming application owns the taxonomy (e.g. an application
/// layer's `app_msg` / `app_status` / `app_req` tags) and dispatches on it.
/// Validated as a short non-empty ASCII slug so a crafted value can't smuggle
/// structure into the routing layer.
///
/// # Examples
///
/// An application tag is a short slug that routes a frame to its handler.
///
/// ```
/// use habilis_network_protocol::messages::AppTag;
///
/// let tag = AppTag::try_new("chat").expect("a valid tag");
/// assert_eq!(tag.as_str(), "chat");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, ::serde::Serialize)]
#[serde(transparent)]
pub struct AppTag(String);

impl AppTag {
    /// The wrapped string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AppTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> ::serde::Deserialize<'de> for AppTag {
    fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
    where
        Decoder: ::serde::Deserializer<'de>,
    {
        let raw = <String as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(&raw).map_err(de::Error::custom)
    }
}

impl AppTag {
    fn validate(raw: &str) -> bool {
        let bytes_ok = raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        !raw.is_empty() && raw.len() <= 32 && bytes_ok
    }

    /// There is no `From<&str>`: a bad literal would panic, so every caller handles the error.
    ///
    /// ```compile_fail
    /// use habilis_network_protocol::AppTag;
    /// let _ = AppTag::from("app_msg");
    /// ```
    ///
    /// ```
    /// use habilis_network_protocol::AppTag;
    /// assert!(AppTag::try_new("app_msg").is_ok());
    /// ```
    ///
    /// # Errors
    /// # Errors
    /// A [`AppTagError::Invalid`] when the tag is empty, longer than 32 bytes, or not
    /// an ASCII slug.
    pub fn try_new(raw: &str) -> Result<Self, AppTagError> {
        let raw: String = raw.to_owned();
        if !Self::validate(&raw) {
            return Err(AppTagError::Invalid);
        }
        Ok(Self(raw))
    }
}
