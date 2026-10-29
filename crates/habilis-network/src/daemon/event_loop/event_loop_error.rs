/// Why the event loop of a mesh stopped with an error.
///
/// [`EventLoopError::Internal`] holds the causes that no caller acts on: the loop ended
/// on a failure of one of its tasks or of its endpoint. It keeps their text and chain.
///
/// # Examples
///
/// The event loop stopped on an internal fault. The doc test compiles it but does not run it.
///
/// ```no_run
/// use habilis_network::runtime::EventLoopError;
///
/// # fn demo(error: &EventLoopError) -> bool {
/// matches!(error, EventLoopError::Internal(_))
/// # }
/// ```
#[derive(Debug)]
#[non_exhaustive]
#[must_use]
pub enum EventLoopError {
    /// A cause no caller acts on. It keeps its text and its chain.
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

impl EventLoopError {
    /// Wraps a cause no caller acts on, keeping its text and its chain.
    pub(super) fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl std::fmt::Display for EventLoopError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(error) => std::fmt::Display::fmt(error.as_ref(), formatter),
        }
    }
}

impl std::error::Error for EventLoopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(error) => error.source(),
        }
    }
}
