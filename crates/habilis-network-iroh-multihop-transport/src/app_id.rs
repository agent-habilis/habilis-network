//! The two roles that an endpoint id plays in this transport.
//!
//! A node holds two endpoints with two keys. The application endpoint is the
//! identity that the topology, the routes and the signed link vectors name. The
//! underlay endpoint carries the cells, and a forwarder dials it. Both are an
//! [`EndpointId`](iroh::EndpointId), and a call that mixes them up compiles and
//! dials the wrong key. One type per role stops that at compile time.

use std::fmt;

use iroh::EndpointId;
use serde::{Deserialize, Serialize};

/// The id of the application endpoint of a node.
///
/// ```compile_fail,E0308
/// use habilis_network_iroh_multihop_transport::{AppId, UnderlayId};
///
/// fn dial(_underlay: UnderlayId) {}
///
/// let app: AppId = AppId::new(iroh::SecretKey::from_bytes(&[1; 32]).public());
/// dial(app);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppId(EndpointId);

impl AppId {
    /// The id of the application endpoint that has the id `id`.
    #[must_use]
    pub fn new(id: EndpointId) -> Self {
        Self(id)
    }

    /// The endpoint id.
    #[must_use]
    pub fn get(self) -> EndpointId {
        self.0
    }

    /// The id as a short text for a log line.
    #[must_use]
    pub fn fmt_short(&self) -> impl fmt::Display + '_ {
        self.0.fmt_short()
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The id of the underlay endpoint of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnderlayId(EndpointId);

impl UnderlayId {
    /// The id of the underlay endpoint that has the id `id`.
    #[must_use]
    pub fn new(id: EndpointId) -> Self {
        Self(id)
    }

    /// The endpoint id.
    #[must_use]
    pub fn get(self) -> EndpointId {
        self.0
    }

    /// The id as a short text for a log line.
    #[must_use]
    pub fn fmt_short(&self) -> impl fmt::Display + '_ {
        self.0.fmt_short()
    }
}

impl fmt::Display for UnderlayId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::{AppId, UnderlayId};
    use habilis_network_test_tracing::test;
    use iroh::SecretKey;

    #[test]
    fn a_role_id_has_the_bytes_of_the_endpoint_id_it_wraps() {
        let id = SecretKey::from_bytes(&[7; 32]).public();
        let raw = postcard::to_allocvec(&id).expect("an endpoint id serializes");

        assert_eq!(
            postcard::to_allocvec(&AppId::new(id)).unwrap(),
            raw,
            "an app id has the bytes of the endpoint id it wraps"
        );
        assert_eq!(
            postcard::to_allocvec(&UnderlayId::new(id)).unwrap(),
            raw,
            "an underlay id has the bytes of the endpoint id it wraps"
        );
        assert_eq!(
            postcard::from_bytes::<AppId>(&raw).unwrap().get(),
            id,
            "an app id deserializes from those bytes"
        );
        assert_eq!(
            postcard::from_bytes::<UnderlayId>(&raw).unwrap().get(),
            id,
            "an underlay id deserializes from those bytes"
        );
    }
}
