use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct RosterEntryDto {
    pub(crate) pubkey: String,
    pub(crate) nick: String,
    pub(crate) alive: bool,
    pub(crate) me: bool,
}
