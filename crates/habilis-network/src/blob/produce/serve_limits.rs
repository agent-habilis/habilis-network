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
    /// after this time. The rule counts acknowledgement frames, so it cannot see a live peer that
    /// sends one now and then, and it does not run while the write waits on the flow-control
    /// window. `min_bytes_per_second` bounds both.
    pub(crate) ack_stall: Duration,
    /// The slowest rate, in bytes per second, at which a serve may send a file. The whole send, the
    /// writes and the wait for the last acknowledgement, gets `ack_stall` plus the file size divided
    /// by this rate, and no more. The stall rule counts acknowledgement frames, so it cannot see a
    /// live peer that acknowledges a packet now and then, or one that stops reading and holds the
    /// flow-control window shut. This cap ends such a serve.
    pub(crate) min_bytes_per_second: u64,
}

impl ServeLimits {
    pub(crate) const DEFAULT: Self = Self {
        // Generous against a slow link, and a legitimate fetcher sends its
        // request immediately after connecting.
        pre_auth: Duration::from_secs(10),
        max_inflight: 64,
        ack_stall: Duration::from_secs(30),
        min_bytes_per_second: 64 * 1024,
    };
}
