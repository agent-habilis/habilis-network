use crate::protocol::crypto::TicketSecret;

/// The capability inputs for a fresh registration: the public salt the ticket
/// carries, the value the fetch handshake is compared against (equal to the salt
/// when not passworded, its Argon2id stretch otherwise), and the password flag.
pub(crate) struct NewSecret {
    pub ticket_secret: TicketSecret,
    pub compare_secret: TicketSecret,
    pub password: bool,
}
