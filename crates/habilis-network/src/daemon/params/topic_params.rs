use super::Resolved;
use crate::daemon::setup_error::SetupError;

use crate::protocol::Nickname;

use crate::daemon::setup::SetupKind;

/// The topic intent: a mesh derived deterministically from a shared string,
/// always public. Name + config are derived, not supplied — the string alone
/// determines the mesh.
///
/// # Examples
///
/// A topic request derives the mesh from a string. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::TopicParams;
///
/// # fn demo(params: TopicParams) {
/// let _ = params.resolve();
/// # }
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TopicParams {
    /// The shared string that fixes the mesh. Every peer that passes the same string meets in the same mesh.
    pub string: String,
    /// `None` ⇒ a random `word-word` nickname is minted in `resolve`.
    pub nickname: Option<Nickname>,
}

impl TopicParams {
    /// Derive the mesh from the string (always the public preset) and default
    /// the nickname. A topic never advertises. The empty/whitespace-string
    /// guard lives in [`derive_topic_mesh`](super::derive_topic_mesh), which every frontend (CLI,
    /// in-process) funnels through.
    ///
    /// # Errors
    /// Fails if the string is empty or whitespace-only.
    pub fn resolve(self) -> Result<Resolved, SetupError> {
        let mesh = super::derive_topic_mesh(&self.string)?;
        Ok(Resolved {
            kind: SetupKind::Topic {
                mesh,
                topic_string: self.string,
            },
            author: self.nickname.unwrap_or_else(Nickname::random),
            advertise_directory: None,
        })
    }
}
