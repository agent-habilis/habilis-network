//! The application-payload tag of an app frame.

use crate::newtype::string_newtype;

use super::AppTagError;

string_newtype!(
/// An opaque application-payload tag — the wire discriminant for a
/// [`super::MessageKind::App`] frame (serialized in the `tag` field). The engine never
/// interprets it; the consuming application owns the taxonomy (e.g. an application
/// layer's `app_msg` / `app_status` / `app_req` tags) and dispatches on it.
/// Validated as a short non-empty ASCII slug so a crafted value can't smuggle
/// structure into the routing layer.
    AppTag,
    error = &'static str,
    deserialize,
);

impl AppTag {
    fn validate(raw: &str) -> bool {
        !raw.is_empty()
            && raw.len() <= 32
            && raw
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
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
