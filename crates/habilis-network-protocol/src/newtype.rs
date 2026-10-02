//! The shape eight validated string newtypes share.
//!
//! Each of them is a `#[serde(transparent)]` wrapper around a `String` whose
//! only real content is a validation predicate. Written out by hand eight
//! times, the boilerplate had already drifted: the `Deserialize` generic was
//! `DeserializerT` in one file and `D` in the rest, the formatter binding was
//! `formatter` in three and `f` in two.
//!
//! # Why the extras are opt-in
//!
//! The eight are **not** one shape, and a macro emitting the union would be
//! wrong rather than merely wasteful. `AppTag` and `CorrId` carry an
//! unconditional `From<&str>` that panics on bad input; `Nickname`'s is gated
//! to test builds. Emitting one list for all of them would make a panicking
//! conversion reachable in production, and would add public trait impls to
//! types that deliberately lack them. So each caller names what it wants.
//!
//! `new` stays hand-written: the predicate and its error type are the only
//! part of these types that is actually theirs.

/// Declare a validated string newtype.
///
/// Emits the struct, its derives, `as_str` and `Display`. Every extra past
/// `error = ` is opt-in:
///
/// - `deserialize` — validating `Deserialize` routed through `Self::new`, so a
///   value off the wire is rejected at parse rather than reaching a consumer.
/// - `from_str` — `FromStr`, same validation.
/// - `as_ref` / `borrow` — `AsRef<str>` / `Borrow<str>`. `Borrow` is what lets
///   a `HashMap` keyed by the newtype be looked up with a `&str`.
/// - `test_from` — a panicking `From<&str>` for fixtures, gated to test builds.
macro_rules! string_newtype {
    (
        $(#[$meta:meta])*
        $name:ident, error = $error:ty $(, $extra:ident)* $(,)?
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, ::serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// The wrapped string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        $(string_newtype!(@extra $extra, $name, $error);)*
    };

    (@extra deserialize, $name:ident, $error:ty) => {
        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let raw = <String as ::serde::Deserialize>::deserialize(deserializer)?;
                Self::new(raw).map_err(::serde::de::Error::custom)
            }
        }
    };

    (@extra from_str, $name:ident, $error:ty) => {
        impl ::std::str::FromStr for $name {
            type Err = $error;
            fn from_str(text: &str) -> ::std::result::Result<Self, Self::Err> {
                Self::new(text)
            }
        }
    };

    (@extra as_ref, $name:ident, $error:ty) => {
        impl ::std::convert::AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };

    (@extra borrow, $name:ident, $error:ty) => {
        impl ::std::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }
    };

    (@extra test_from, $name:ident, $error:ty) => {
        #[cfg(any(test, feature = "test-fixtures"))]
        impl ::std::convert::From<&str> for $name {
            fn from(text: &str) -> Self {
                Self::new(text).expect(concat!("invalid ", stringify!($name), " in test fixture"))
            }
        }
    };
}

pub(crate) use string_newtype;

#[cfg(test)]
mod tests {
    use crate::mesh::{MeshId, MeshName};
    use crate::message::{AppTag, CorrId, MessageBody, MessageId, ShardGroup};
    use crate::nickname::Nickname;

    /// The macro must not have changed the wire form of any of the eight. All
    /// are `#[serde(transparent)]`, so each serializes as a bare JSON string
    /// and round-trips through its own validating `Deserialize`.
    #[test]
    fn every_newtype_is_transparent_on_the_wire() {
        macro_rules! check {
            ($value:expr, $raw:expr) => {{
                let json = serde_json::to_string(&$value).expect("serialize");
                assert_eq!(json, format!("{:?}", $raw), "not transparent");
            }};
        }

        let uuid = "b3f1c2d4-5e6a-4b8c-9d0e-1f2a3b4c5d6e";
        check!(Nickname::new("lotus-anvil").expect("nick"), "lotus-anvil");
        check!(MessageId::new(uuid).expect("id"), uuid);
        check!(MessageBody::new("hello").expect("body"), "hello");
        check!(AppTag::new("app_msg").expect("tag"), "app_msg");
        check!(CorrId::new("corr-1").expect("corr"), "corr-1");
        check!(ShardGroup::from_uuid_str(uuid).expect("group"), uuid);
        check!(MeshName::new("kernel-parch").expect("name"), "kernel-parch");
    }

    /// Deserialization stays **validating** — the property the hand-written
    /// impls existed for, and the one a `#[serde(transparent)]` derive would
    /// have silently dropped.
    #[test]
    fn deserialization_still_rejects_what_new_rejects() {
        assert!(serde_json::from_str::<Nickname>("\"has space\"").is_err());
        assert!(serde_json::from_str::<MessageId>("\"not-a-uuid\"").is_err());
        assert!(serde_json::from_str::<MessageBody>("\"\\u0007\"").is_err());
        assert!(serde_json::from_str::<AppTag>("\"has space\"").is_err());
        assert!(serde_json::from_str::<CorrId>("\"\"").is_err());
        assert!(serde_json::from_str::<ShardGroup>("\"not-a-uuid\"").is_err());
        assert!(serde_json::from_str::<MeshId>("\"!!\"").is_err());
    }
}
