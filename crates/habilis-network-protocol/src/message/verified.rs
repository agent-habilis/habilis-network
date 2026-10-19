//! The two proof types of a message. [`Verified`] says that its signature is valid over these exact
//! bytes. [`Authored`] says who wrote a body that may have been derived from one.

use std::ops::Deref;
use std::sync::Arc;

use serde::{Serialize, Serializer};

use super::{Message, MessageBody};
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
            message: Arc::new(message),
            key,
        }
    }

    /// The key that signed the message. Never absent: a `Verified` has a signature.
    #[must_use]
    pub const fn key(&self) -> AuthorKey {
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
    ///
    /// Propagates `Message::serialize` failure.
    pub fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        (*self.message).serialize()
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
            message: Arc::new(message),
            key: self.key,
        }
    }

    /// The one door around [`Message::verify`]: a `Verified` for a message whose signature was not
    /// checked, claiming `key` as its author. The message gets a signature that does not verify
    /// (see [`Message::with_unverified_key`]).
    ///
    /// It exists for the adversarial suite, and `test-fixtures` enables it. A non-test binary must
    /// never enable that feature, because the door would let it forge a proof.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub fn fixture_unchecked(message: Message, key: AuthorKey) -> Self {
        Self::new(message.with_unverified_key(key), key)
    }
}

impl Deref for Verified {
    type Target = Message;

    fn deref(&self) -> &Message {
        &self.message
    }
}

impl Serialize for Verified {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Serialize::serialize(&*self.message, serializer)
    }
}

/// A message whose author is proven. Its body may have been derived from a [`Verified`] one, so
/// its signature is not checked and it has no wire form: it cannot be serialized, and it cannot go
/// back on the wire or into the log.
///
/// The `Deref` to [`Message`] is a read door, not a wire door. The `Serialize` impl of `Message` is
/// still reachable through `&*authored`, so the rule rests on the senders: every sender takes a
/// [`Verified`], and only [`Verified::serialize`] produces wire bytes.
///
/// # Examples
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
            message: Arc::new(message),
            key,
        }
    }

    /// The key that signed the message this body came from.
    #[must_use]
    pub const fn key(&self) -> AuthorKey {
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
