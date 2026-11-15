use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct RosterEntryDto {
    pub(crate) pubkey: String,
    pub(crate) nick: String,
    pub(crate) alive: bool,
    pub(crate) me: bool,
}
