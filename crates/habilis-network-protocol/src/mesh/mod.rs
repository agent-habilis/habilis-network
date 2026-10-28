//! The mesh identifier, at two levels:
//!
//! - [`MeshId`] — the validated bare `Base58Check` string. Possession proves
//!   the checksum, version, and full payload structure. Code: `id`.
//! - [`Mesh`] — the *decoded* structure (32-byte seed + name +
//!   [`MeshConfig`]), with the `Base58Check` codec (this file). `MeshId`
//!   is what flows through the wire/CLI; `Mesh` is what `setup_mesh`
//!   derives identity and behavior from.
//!
//! See `docs/mesh-hash.md` for the full byte layout and rationale.
//!
//! Also home to [`MeshName`] (`name`), the lookup allowlist (`lookup`)
//! carried in the id, and the relay-ladder parsing.

mod config_error;

use config_error as error;
mod mesh_id_error;
use mesh_id_error as id;
mod lookup;
mod name_error;
use name_error as name;
mod transport;

pub use error::ConfigError;
pub use id::{MeshId, MeshIdError};
pub use lookup::{
    AdvertiseRequiresReachable, DEFAULT_DIRECTORY, DirectorySelection, Lookup, LookupOpts,
    LookupSet, MeshConfig, OptFlag, RelayChoice, RelayLadder, RelayLadderError, RelaySelection,
    resolve_lookups, validate_advertise,
};
pub use name::{MeshName, NameError};
pub use transport::{Transport, TransportPolicy};

/// Id format version. A single byte reserved so the encoding can evolve;
/// an unknown version is rejected.
const VERSION: u8 = 2;
const SEED_LEN: usize = 32;
/// Wire bound for the encoded name in bytes. `MeshName::try_new` caps the
/// name at `ident::MAX_CHARS` scalar values; each is at most 4 UTF-8
/// bytes, so the encoded form fits this many bytes (and inside the
/// 1-byte length field).
const NAME_MAX_BYTES: usize = super::ident::MAX_CHARS * 4;

mod choice_error;
mod locked_mesh;
#[expect(
    clippy::module_inception,
    reason = "the file is named for its type, Mesh, as O9 asks"
)]
mod mesh;
mod mesh_secret;

pub use choice_error::ChoiceError;
pub use locked_mesh::{LockedMesh, UnlockError};
pub use mesh::Mesh;

#[cfg(test)]
#[path = "tests.rs"]
mod mesh_tests;
