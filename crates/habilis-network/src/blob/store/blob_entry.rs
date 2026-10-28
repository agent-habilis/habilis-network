use std::collections::HashSet;
use std::path::PathBuf;

use crate::protocol::crypto::TicketSecret;

use crate::blob::ContentId;

/// One spooled blob: the metadata the fetch path needs, plus the spool path to
/// stream from. No bytes are held.
pub(crate) struct BlobEntry {
    pub path: PathBuf,
    pub size: u64,
    /// The value the producer compares a presented token against
    /// (constant-time): the raw bearer secret, or — when the blob is
    /// password-protected — the Argon2id stretch of the ticket's public salt.
    pub secret: TicketSecret,
    /// The public salt the ticket carries (equal to `secret` when not
    /// passworded). Retained so a deduped re-registration mints a ticket that
    /// still matches this entry's compare `secret`.
    pub(super) ticket_secret: TicketSecret,
    /// Whether the minted ticket is password-protected.
    pub(super) password: bool,
    /// Every content group that offloaded these bytes. The spool file goes
    /// only when the last of them is evicted.
    pub(super) owners: HashSet<ContentId>,
    /// Monotonic order of the last registration or claim, for oldest-first
    /// eviction under disk pressure.
    pub(super) seq: u64,
}
