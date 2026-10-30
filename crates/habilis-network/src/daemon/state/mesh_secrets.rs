use crate::protocol::SymmetricKey;

use crate::protocol::crypto;

/// The mesh's secret material, grouped so [`EventLoopState::new`] can take
/// both by value (the stretched key must be owned here so it drops/zeroizes
/// once the per-channel keys are derived) without blowing its argument budget.
#[derive(Default, Debug, Clone)]
pub(crate) struct MeshSecrets {
    pub password: Option<crypto::Password>,
    pub key: Option<SymmetricKey>,
}
