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
/// keeps their text and their chain. A connect timeout to the creator of a mesh (the
/// "creator unreachable" that the gossip-join skill describes) lands in `Internal`.
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
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
    /// The forwarding variants print their inner text, so the chain continues at the inner
    /// error's own source. Naming the inner error here would print its text twice.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        let inner: &dyn Error = match self {
            Self::Unlock(error) => error,
            Self::Invite(error) => error,
            Self::Resolve(error) => error,
            Self::Config(error) => error,
            Self::Internal(error) => &**error,
            Self::PasswordRequired
            | Self::InviteNoPassword
            | Self::MeshAndTopic
            | Self::EmptyTopic => return None,
        };
        inner.source()
    }
}

#[cfg(test)]
mod tests {
    use super::SetupError;
    use crate::protocol::UnlockError;

    /// The texts the agent-gossip skills grep the daemon stderr for. Changing one
    /// breaks them, so each is pinned here.
    #[test]
    fn the_grepped_texts_are_pinned() {
        let _guard = ::habilis_network_test_tracing::init();
        assert_eq!(
            SetupError::PasswordRequired.to_string(),
            "this mesh is password-protected — pass --password",
            "the password-required text is pinned"
        );
        assert_eq!(
            SetupError::Unlock(UnlockError::WrongPassword).to_string(),
            "wrong password",
            "the wrong password text is pinned"
        );
    }
}

#[cfg(test)]
mod chain_tests {

    use super::SetupError;

    #[test]
    fn an_internal_cause_keeps_its_chain() {
        let _guard = ::habilis_network_test_tracing::init();
        let io = std::io::Error::new(std::io::ErrorKind::AddrInUse, "Address already in use");
        let cause = anyhow::Error::new(io).context("bind the endpoint");
        let error = anyhow::Error::new(SetupError::internal(cause));
        let text = format!("{error:#}");
        assert!(
            text.contains("Address already in use"),
            "the io cause of SetupError is lost: {text}"
        );
    }
}
