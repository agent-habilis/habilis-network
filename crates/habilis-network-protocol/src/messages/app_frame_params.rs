//! Parameters for building an app frame: its tag, its addressee, its correlation id and its body.

use super::{AppTag, CorrId, MessageBody};
use crate::nickname_error::Nickname;

/// Parameters for [`super::Message::new_app`] (and `habilis_network::ops::send_app`, which
/// shares the same `App` frame shape).
///
/// # Examples
///
/// A broadcast frame has no recipient and no correlation id.
///
/// ```
/// use habilis_network_protocol::messages::{AppFrameParams, AppTag, MessageBody};
///
/// let tag = AppTag::try_new("chat").expect("a valid tag");
/// let body = MessageBody::try_new("hello").expect("a body");
/// let params = AppFrameParams::new(tag, None, None, body);
/// assert!(params.to.is_none());
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AppFrameParams {
    /// The application tag, which routes the frame to its app handler.
    pub tag: AppTag,
    /// The recipient, when the frame is directed.
    pub to: Option<Nickname>,
    /// The correlation id of a request or reply.
    pub corr: Option<CorrId>,
    /// The body the app sends.
    pub body: MessageBody,
}

impl AppFrameParams {
    /// The parts of an app frame: its tag, the addressee and the request id, if any, and the body.
    #[must_use]
    pub fn new(tag: AppTag, to: Option<Nickname>, corr: Option<CorrId>, body: MessageBody) -> Self {
        Self {
            tag,
            to,
            corr,
            body,
        }
    }
}
