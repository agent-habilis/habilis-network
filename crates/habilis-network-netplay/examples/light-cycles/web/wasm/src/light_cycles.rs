use crate::input::Input;
use crate::world::World;
use habilis_network::protocol::AuthorKey;
use habilis_network_netplay::Config;

/// The type-level bundle the session is generic over.
#[derive(Debug)]
pub struct LightCycles;

impl Config for LightCycles {
    type Input = Input;
    type State = World;
    /// The peer's signed public key. Never the nickname — the protocol
    /// treats those as cosmetic and explicitly non-unique.
    type Address = AuthorKey;
}
