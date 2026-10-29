//! The two proof types of a message. [`Verified`] says that its signature is valid over these exact
//! bytes. [`Authored`] says who wrote a body that may have been derived from one.

use std::ops::Deref;
use std::sync::Arc;

use serde::{Serialize, Serializer};

use bytes::Bytes;

use super::wire::WireFrame;
use super::{Message, MessageBody, MessageError};
use crate::AuthorKey;

/// A [`Message`] whose signature was made here or checked over its exact bytes.
///
/// Only [`Message::sign`] and [`Message::verify`] make one. It derefs to the message for reads and
/// has no `DerefMut`, so a builder such as [`Message::with_shard`] cannot change it after signing.
///
/// It serializes as the message it holds, so its wire form is the message's. It has no
/// `Deserialize`: a wire message enters as a [`Message`] and must pass [`Message::verify`].
///
/// # Examples
///
/// The doc examples below share one signed wire message, `SIGNED`, and one unsigned one. A message
/// parsed from `SIGNED` is a `Verified` only after `verify`.
///
/// A message that is not signed is not a `Verified`:
///
/// ```compile_fail,E0308
/// use habilis_network_protocol::message::{Message, Verified};
///
/// const UNSIGNED: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;
///
/// fn takes(_: &Verified) {}
///
/// let unsigned = Message::parse(UNSIGNED.as_bytes()).unwrap();
/// takes(&unsigned);
/// ```
///
/// A signed one that has been verified is, so the same call compiles:
///
/// ```
/// use habilis_network_protocol::message::{Message, Verified};
///
/// const SIGNED: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"eeea2aca75b3ef10bd592fe6a835e147def33b203c0bfcf26253edb7b7d06a450e383d6fdd3fb0ef153969d16df0e6d4b97f1a7ca434106378d8f772814ad50e","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;
///
/// fn takes(_: &Verified) {}
///
/// let signed = Message::parse(SIGNED.as_bytes()).unwrap().verify().unwrap();
/// takes(&signed);
/// ```
///
/// The body cannot be assigned through a `Verified`:
///
/// ```compile_fail,E0594
/// use habilis_network_protocol::message::Message;
///
/// const SIGNED: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"eeea2aca75b3ef10bd592fe6a835e147def33b203c0bfcf26253edb7b7d06a450e383d6fdd3fb0ef153969d16df0e6d4b97f1a7ca434106378d8f772814ad50e","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;
///
/// let mut v = Message::parse(SIGNED.as_bytes()).unwrap().verify().unwrap();
/// v.body = v.body.clone();
/// ```
///
/// A builder cannot change it after signing:
///
/// ```compile_fail,E0507
/// use habilis_network_protocol::message::Message;
///
/// const SIGNED: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"eeea2aca75b3ef10bd592fe6a835e147def33b203c0bfcf26253edb7b7d06a450e383d6fdd3fb0ef153969d16df0e6d4b97f1a7ca434106378d8f772814ad50e","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;
///
/// let v = Message::parse(SIGNED.as_bytes()).unwrap().verify().unwrap();
/// let _ = v.with_shard(None);
/// ```
///
/// It has no `Deserialize`, so a wire string does not become one:
///
/// ```compile_fail,E0277
/// use habilis_network_protocol::message::Verified;
///
/// let _: Verified = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct Verified {
    /// Shared, so a copy of the proof (and the view a gate makes of it) is a count bump.
    message: Arc<Message>,
    key: AuthorKey,
}

impl Verified {
    /// Wrap a message whose signature is known to be valid under `key`. Only the message module
    /// calls it, from [`Message::sign`] and [`Message::verify`].
    pub(super) fn new(message: Message, key: AuthorKey) -> Self {
        Self {
            // a copy of the proof and each view share one message
            message: Arc::new(message),
            key,
        }
    }

    /// The key that signed the message. Never absent: a `Verified` has a signature.
    #[must_use]
    pub fn key(&self) -> AuthorKey {
        self.key
    }

    /// The message, without its proof.
    #[must_use]
    pub fn into_message(self) -> Message {
        Arc::unwrap_or_clone(self.message)
    }

    /// The wire bytes of the message: `Message::serialize`, here, so a call on a `Verified` does
    /// not reach the `Serialize` impl, which needs a serializer.
    ///
    /// # Errors
    /// # Errors
    /// A [`MessageError::Source`] when the JSON does not encode, or
    /// [`MessageError::Oversize`] when the bytes pass `MAX_MESSAGE_SIZE`.
    pub fn serialize(&self) -> Result<WireFrame, MessageError> {
        Ok(WireFrame::new(Bytes::from((*self.message).serialize()?)))
    }

    /// The proof that the author is `key`, with the message's own body.
    #[must_use]
    pub fn authored(&self) -> Authored {
        Authored {
            message: Arc::clone(&self.message),
            key: self.key,
        }
    }

    /// The proof that the author is `key`, with a body that `open` derives from this one. `open`
    /// returns `None` when it cannot derive a body, for example a body it cannot decrypt.
    ///
    /// The signature covers the body that arrived, not the derived one, so the result proves the
    /// author and nothing about the derived body.
    #[must_use]
    pub fn open_with(
        &self,
        open: impl FnOnce(&MessageBody) -> Option<MessageBody>,
    ) -> Option<Authored> {
        let body = open(&self.message.body)?;
        Some(self.with_body(body))
    }

    /// The proof with `body` in place of the wire body. It cannot fail: the caller supplies the
    /// body, and the author is the one this proof already names.
    #[must_use]
    pub fn with_body(&self, body: MessageBody) -> Authored {
        let mut message = (*self.message).clone();
        message.body = body;
        Authored {
            // the copy with the new body is shared by the proof and its views
            message: Arc::new(message),
            key: self.key,
        }
    }

    /// The one door around [`Message::verify`]: a `Verified` for a message whose signature was not
    /// checked, claiming `key` as its author. The message gets a signature that does not verify
    /// (see [`Message::with_unverified_key`]). It does not carry a signature: see
    /// [`Verified::fixture_with_signature`] for one that keeps the signature as parsed.
    ///
    /// It exists in unit tests and in any build that enables `test-fixtures`. A release binary must
    /// not enable that feature, because the door would let it forge a proof.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn fixture_unchecked(message: Message, key: AuthorKey) -> Self {
        Self::new(message.with_unverified_key(key), key)
    }

    /// The second door around [`Message::verify`], for tamper-after-sign and replay tests: a `Verified`
    /// over a message that keeps the signer it was parsed with, key and signature both. Its `serialize`
    /// keeps the original signature, so a body edited after signing fails `verify` at the receiver, and
    /// captured bytes can be replayed unchanged.
    ///
    /// It exists in unit tests and in any build that enables `test-fixtures`. A release binary must
    /// not enable that feature.
    ///
    /// # Panics
    ///
    /// If `message` is unsigned: there is no signature to keep.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn fixture_with_signature(message: Message) -> Self {
        let key = message
            .author_key()
            .expect("a fixture with a signature needs a signed message");
        Self::new(message, key)
    }
}

impl Deref for Verified {
    type Target = Message;

    fn deref(&self) -> &Message {
        &self.message
    }
}

mod sealed {
    /// Only the two proofs of this module implement [`super::Proof`], so no outside type can
    /// claim an author key it was not given.
    pub trait Sealed {}

    impl Sealed for super::Verified {}
    impl Sealed for super::Authored {}
}

/// A message whose author is proven: a [`Verified`] wire frame or the [`Authored`] view of one.
/// The gate and the app surface are generic over it, so one function serves both.
///
/// It is sealed: [`Verified`] and [`Authored`] are the only implementors, so a proof can only
/// come from [`Message::sign`] or [`Message::verify`].
///
/// # Examples
///
/// A signed message is a `Proof`, and so is its authored view:
///
/// ```
/// use habilis_network_protocol::message::{Proof, Verified};
///
/// fn takes(_: &impl Proof) {}
///
/// fn check(verified: &Verified) {
///     takes(verified);
///     takes(&verified.authored());
/// }
/// ```
///
/// An outside type cannot implement it:
///
/// ```compile_fail,E0277
/// use habilis_network_protocol::message::{Authored, Proof};
/// use habilis_network_protocol::{AuthorKey, Message, MessageBody};
///
/// struct Outside(Message);
///
/// impl std::ops::Deref for Outside {
///     type Target = Message;
///     fn deref(&self) -> &Message {
///         &self.0
///     }
/// }
///
/// impl Proof for Outside {
///     fn key(&self) -> AuthorKey {
///         unimplemented!()
///     }
///     fn with_body(&self, _body: MessageBody) -> Authored {
///         unimplemented!()
///     }
///     fn authored(&self) -> Authored {
///         unimplemented!()
///     }
/// }
/// ```
pub trait Proof: Deref<Target = Message> + sealed::Sealed {
    /// The key that proved the author of the message.
    fn key(&self) -> AuthorKey;

    /// The proof with `body` in place of the wire body. It cannot fail.
    fn with_body(&self, body: MessageBody) -> Authored;

    /// The proof as an [`Authored`] view, with the wire body.
    fn authored(&self) -> Authored;
}

impl Proof for Verified {
    fn key(&self) -> AuthorKey {
        Verified::key(self)
    }

    fn with_body(&self, body: MessageBody) -> Authored {
        Verified::with_body(self, body)
    }

    fn authored(&self) -> Authored {
        Verified::authored(self)
    }
}

impl Proof for Authored {
    fn key(&self) -> AuthorKey {
        Authored::key(self)
    }

    fn with_body(&self, body: MessageBody) -> Authored {
        Authored::with_body(self, body)
    }

    fn authored(&self) -> Authored {
        self.clone()
    }
}

/// The JSON record of a verified message, for the places that echo or compare it: the IPC echo and
/// the tests. It skips the `MAX_MESSAGE_SIZE` gate of `Message::serialize`, and it is never a wire
/// door: the wire takes a [`WireFrame`](super::WireFrame) from [`Verified::serialize`].
impl Serialize for Verified {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Serialize::serialize(&super::Wire(&self.message), serializer)
    }
}

/// A message whose author is proven. Its body may have been derived from a [`Verified`] one, so
/// its signature is not checked and it has no wire form: it cannot be serialized, and it cannot go
/// back on the wire or into the log.
///
/// The `Deref` to [`Message`] is a read door, not a wire door. `Message` has no public `Serialize`,
/// so `&*authored` does not serialize either: only [`Verified::serialize`] makes a
/// [`WireFrame`](super::WireFrame), and every sender takes one.
///
/// # Examples
///
/// Serializing an `Authored` through `serde_json` does not compile: `Message` has no public `Serialize`,
/// and the `Deref` to it does not give one back:
///
/// ```compile_fail,E0277
/// use habilis_network_protocol::message::Message;
///
/// const SIGNED: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"eeea2aca75b3ef10bd592fe6a835e147def33b203c0bfcf26253edb7b7d06a450e383d6fdd3fb0ef153969d16df0e6d4b97f1a7ca434106378d8f772814ad50e","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;
///
/// let authored = Message::parse(SIGNED.as_bytes())
///     .unwrap()
///     .verify()
///     .unwrap()
///     .authored();
/// let _ = serde_json::to_vec(&*authored);
/// ```
///
/// Calling `serialize` on an `Authored` does not reach the wire, because the message's own method is
/// private to the crate:
///
/// ```compile_fail,E0624
/// use habilis_network_protocol::message::Message;
///
/// const SIGNED: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"eeea2aca75b3ef10bd592fe6a835e147def33b203c0bfcf26253edb7b7d06a450e383d6fdd3fb0ef153969d16df0e6d4b97f1a7ca434106378d8f772814ad50e","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;
///
/// let authored = Message::parse(SIGNED.as_bytes())
///     .unwrap()
///     .verify()
///     .unwrap()
///     .authored();
/// let _ = authored.serialize();
/// ```
///
///
/// ```compile_fail,E0277
/// use habilis_network_protocol::message::Message;
///
/// const SIGNED: &str = r#"{"v":"12.0","id":"00000000-0000-0000-0000-000000000001","type":"app","tag":"app_msg","mesh":"H5G8iUJfx5UprXFmpSGLTLpjKU5AGhjQd4pAacY3NSZ6wy72P9wvAdsu7kgwG6","author":"alice-bot","ts":1700000000,"body":"hello, golden","pubkey":"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"eeea2aca75b3ef10bd592fe6a835e147def33b203c0bfcf26253edb7b7d06a450e383d6fdd3fb0ef153969d16df0e6d4b97f1a7ca434106378d8f772814ad50e","seq":3,"prev":"1111111111111111111111111111111111111111111111111111111111111111","parents":["2222222222222222222222222222222222222222222222222222222222222222"],"ext":{}}"#;
///
/// let authored = Message::parse(SIGNED.as_bytes())
///     .unwrap()
///     .verify()
///     .unwrap()
///     .authored();
/// let _ = serde_json::to_string(&authored);
/// ```
#[derive(Debug, Clone)]
pub struct Authored {
    /// Shared with the [`Verified`] it came from, so a view is a count bump.
    message: Arc<Message>,
    key: AuthorKey,
}

impl Authored {
    /// A proof for `message`, whose author `key` proved. Only [`Verified::authored`],
    /// [`Verified::open_with`] and the reassembly that builds a logical message call it.
    pub(crate) fn new(message: Message, key: AuthorKey) -> Self {
        Self {
            // a copy of the proof and each view share one message
            message: Arc::new(message),
            key,
        }
    }

    /// The key that signed the message this body came from.
    #[must_use]
    pub fn key(&self) -> AuthorKey {
        self.key
    }

    /// The proof with a body that `open` derives from this one, as
    /// [`Verified::open_with`]. The result proves the author only.
    #[must_use]
    pub fn open_with(
        &self,
        open: impl FnOnce(&MessageBody) -> Option<MessageBody>,
    ) -> Option<Authored> {
        let body = open(&self.message.body)?;
        Some(self.with_body(body))
    }

    /// The proof with `body` in place of its body. It cannot fail, as [`Verified::with_body`].
    #[must_use]
    pub fn with_body(&self, body: MessageBody) -> Authored {
        let mut message = (*self.message).clone();
        message.body = body;
        Authored {
            // the copy with the new body is shared by the proof and its views
            message: Arc::new(message),
            key: self.key,
        }
    }
}

impl Deref for Authored {
    type Target = Message;

    fn deref(&self) -> &Message {
        &self.message
    }
}
