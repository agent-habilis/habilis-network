use std::time::Duration;

/// What one fetch may cost before the requester has proved anything.
///
/// Everything up to the bearer-secret check runs on a peer's schedule: the
/// handshake, opening a stream, and sending the 64-byte request. A peer that
/// connects and then stops parks a task for good, and nothing bounded how many
/// such tasks there could be. Injectable so tests need not wait real seconds.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServeLimits {
    /// Deadline covering the whole pre-authentication phase.
    pub(crate) pre_auth: Duration,
    /// Serves in flight at once. A backstop under the deadline: the deadline
    /// is what frees a parked task, this caps how many can park meanwhile.
    pub(crate) max_inflight: usize,
    /// How long the producer waits for the consumer to acknowledge the tail of a file when no
    /// acknowledgement arrives. The producer buffers the whole file and closes the connection only
    /// after the consumer has all of it, so a slow link is never cut. A fixed total time cut a file
    /// that the link needed more than that time to carry. A silent consumer still frees the serve
    /// after this time.
    pub(crate) ack_stall: Duration,
}

impl ServeLimits {
    pub(crate) const DEFAULT: Self = Self {
        // Generous against a slow link, and a legitimate fetcher sends its
        // request immediately after connecting.
        pre_auth: Duration::from_secs(10),
        max_inflight: 64,
        ack_stall: Duration::from_secs(30),
    };
}
