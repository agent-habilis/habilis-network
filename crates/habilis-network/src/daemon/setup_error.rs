//! The error of a mesh setup: resolving the join target and bringing the mesh up.

use std::error::Error;
use std::fmt;

use crate::invite::InviteError;
use crate::protocol::UnlockError;
use crate::resolver::ResolveError;
use habilis_network_protocol::ConfigError;

/// Why a mesh cannot be set up.
///
/// The named variants are the causes a caller acts on: the frontends prompt for a
/// password, drop a flag, or print the text that the agent-gossip skills grep for.
/// [`SetupError::Internal`] holds the other causes, which no caller acts on; it
/// keeps their text and their chain.
#[derive(Debug)]
#[non_exhaustive]
pub enum SetupError {
    /// The id needs a password and none was given. A frontend prompts for it.
    PasswordRequired,
    /// The password does not open the id, or the id has none to open.
    Unlock(UnlockError),
    /// The invite carries no password, and one was given. Drop the flag.
    InviteNoPassword,
    /// The invite does not redeem.
    Invite(InviteError),
    /// The mesh id does not resolve.
    Resolve(ResolveError),
    /// The config refuses the mesh.
    Config(ConfigError),
    /// Both a mesh id and a topic were given.
    MeshAndTopic,
    /// The topic string is empty or whitespace.
    EmptyTopic,
    /// A cause no caller acts on. The text and the chain are the cause's own.
    Internal(Box<dyn Error + Send + Sync>),
}

impl SetupError {
    /// Wraps a cause no caller acts on, keeping its text and its chain.
    pub(crate) fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl fmt::Display for SetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordRequired => {
                formatter.write_str("this mesh is password-protected — pass --password")
            }
            Self::Unlock(error) => fmt::Display::fmt(error, formatter),
            Self::InviteNoPassword => {
                formatter.write_str("this invite has no password — drop --password")
            }
            Self::Invite(error) => fmt::Display::fmt(error, formatter),
            Self::Resolve(error) => fmt::Display::fmt(error, formatter),
            Self::Config(error) => fmt::Display::fmt(error, formatter),
            Self::MeshAndTopic => formatter.write_str("pass only one of mesh / topic"),
            Self::EmptyTopic => formatter.write_str("topic string must not be empty"),
            Self::Internal(error) => fmt::Display::fmt(error.as_ref(), formatter),
        }
    }
}

impl Error for SetupError {
    /// The forwarding variants show the wrapped text, so they are their own cause
    /// and name no source; `Internal` shows its cause's text, so it names none either.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::SetupError;
    use crate::protocol::UnlockError;
    use habilis_network_test_tracing::test;

    /// The texts the agent-gossip skills grep the daemon stderr for. Changing one
    /// breaks them, so each is pinned here.
    #[test]
    fn the_grepped_texts_are_pinned() {
        assert_eq!(
            SetupError::PasswordRequired.to_string(),
            "this mesh is password-protected — pass --password"
        );
        assert_eq!(
            SetupError::Unlock(UnlockError::WrongPassword).to_string(),
            "wrong password"
        );
    }
}
