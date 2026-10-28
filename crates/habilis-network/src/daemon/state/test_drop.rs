/// Tests only: which inbound frame the drop hook takes.
#[cfg(all(feature = "iroh-test-utils", not(target_arch = "wasm32")))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TestDrop {
    /// The app frame whose body is this text.
    AppBody(String),
    /// A shared-state change.
    StateChange,
}
