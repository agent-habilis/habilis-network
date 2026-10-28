/// How [`handle_state_digest`] sent its answer, in frames. `unicast` counts
/// frames handed to a background send, not proof that they arrived, and not
/// the heads frame that closes a point-to-point answer.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Answered {
    pub(crate) unicast: usize,
    pub(crate) broadcast: usize,
}
