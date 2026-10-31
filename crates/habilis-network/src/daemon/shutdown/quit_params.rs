use crate::protocol::MeshName;

/// The mesh name (for the departure log line), the user-facing departure
/// label (the raw topic string for a topic gossip, `#name` otherwise), and
/// whether this quit should hard-exit the process — the plain values
/// `announce_departure` needs beyond the loop state and the shared
/// handler context.
#[derive(Debug, Clone)]
pub(in crate::daemon) struct QuitParams<'name> {
    pub(in crate::daemon) name: &'name MeshName,
    pub(in crate::daemon) leave_label: &'name str,
    pub(in crate::daemon) exit_on_quit: bool,
}
