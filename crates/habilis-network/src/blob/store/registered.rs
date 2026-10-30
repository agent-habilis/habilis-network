use crate::protocol::crypto::TicketSecret;

/// What a registration hands back for building the ticket: the public salt the
/// ticket carries and whether it is password-protected.
#[derive(Debug, Clone)]
pub(crate) struct Registered {
    pub ticket_secret: TicketSecret,
    pub password: bool,
}
