//! The request and response correlation id of an app frame.

use serde::Deserialize;

use crate::newtype::string_newtype;

use super::CorrIdError;

string_newtype!(
/// An opaque request/response correlation id carried on a directed
/// [`super::MessageKind::App`] frame (the `corr` field). Matched by the engine's
/// pending-call registry to pair a reply with its outstanding call; the app
/// mints and interprets its value (the application layer uses a UUID). Kept generic so
/// the engine correlates without knowing the payload model.
    CorrId,
    error = CorrIdError,
);

impl CorrId {
    fn validate(raw: &str) -> bool {
        !raw.is_empty() && raw.len() <= 64
    }

    /// There is no `From<&str>`: a bad literal would panic, so every caller handles the error.
    ///
    /// ```compile_fail
    /// use habilis_network_protocol::CorrId;
    /// let _ = CorrId::from("aaaa");
    /// ```
    ///
    /// ```
    /// use habilis_network_protocol::CorrId;
    /// assert!(CorrId::try_new("aaaa").is_ok());
    /// ```
    ///
    /// # Errors
    /// # Errors
    /// A [`CorrIdError::Invalid`] when the correlation id is empty or longer than 64
    /// bytes.
    pub fn try_new(raw: &str) -> Result<Self, CorrIdError> {
        let raw: String = raw.to_owned();
        if !Self::validate(&raw) {
            return Err(CorrIdError::Invalid);
        }
        Ok(Self(raw))
    }
}

impl<'de> Deserialize<'de> for CorrId {
    fn deserialize<Decoder>(deserializer: Decoder) -> Result<Self, Decoder::Error>
    where
        Decoder: serde::Deserializer<'de>,
    {
        // The engine stays payload-agnostic (the app enforces its own UUID
        // contract), but a length bound caps DoS at the wire boundary: the app
        // mints a 36-char UUID, so anything empty or wildly larger is a crafted
        // frame, not a correlation id. Mirrors [`AppTag`]'s bounded deserialize.
        let raw = String::deserialize(deserializer)?;
        Self::try_new(&raw).map_err(serde::de::Error::custom)
    }
}
