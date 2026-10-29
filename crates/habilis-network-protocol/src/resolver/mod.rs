//! Resolving a join target: a mesh id, or an invite to an invite-only mesh.

mod join_target;
mod join_target_error;
mod resolve;
mod resolve_error;

pub use join_target::JoinTarget;
pub use join_target_error::JoinTargetError;
pub use resolve::resolve;
pub use resolve_error::ResolveError;

#[cfg(test)]
mod tests {
    use super::{JoinTarget, JoinTargetError, resolve};
    use habilis_network_test_tracing::test;

    // The consumer builds its own "use the topic command instead" hint off this
    // variant, so the trimmed input has to survive classification verbatim.
    #[test]
    fn a_non_token_string_is_unrecognized_and_echoes_its_input() {
        let parsed: Result<JoinTarget, _> = "  github.com/alice/proj ".parse();
        let error = parsed.unwrap_err();
        assert_eq!(
            error,
            JoinTargetError::Unrecognized("github.com/alice/proj".to_owned())
        );
        assert!(
            error.to_string().contains("github.com/alice/proj"),
            "got: {error}"
        );
    }

    fn known_mesh_id() -> String {
        use crate::mesh::{Mesh, MeshConfig, MeshName};
        Mesh::try_new(
            crate::crypto::Seed::from_bytes([1u8; 32]),
            MeshName::try_new("test").unwrap(),
            MeshConfig::loopback(),
        )
        .unwrap()
        .to_string()
    }

    #[test]
    fn resolve_passthrough_for_valid_mesh_id() {
        let id = known_mesh_id();
        let target: JoinTarget = id.parse().unwrap();
        let mesh = resolve(&target).unwrap();
        assert_eq!(mesh.to_string(), id);
    }

    #[test]
    fn mistyped_mesh_id_reports_an_invalid_gossip_hash() {
        let mut mistyped = known_mesh_id();
        let replacement = if mistyped.ends_with('1') { "2" } else { "1" };
        mistyped.replace_range(mistyped.len() - 1.., replacement);
        let parsed: Result<JoinTarget, _> = mistyped.parse();
        let error = parsed.unwrap_err();
        assert_eq!(error.to_string(), "invalid gossip hash");
    }

    #[test]
    fn join_target_classifies_valid_id() {
        let id = known_mesh_id();
        let parsed: Result<JoinTarget, _> = id.parse();
        assert!(matches!(parsed, Ok(JoinTarget::Mesh(_))));
    }

    fn invite_only_mesh() -> crate::mesh::Mesh {
        use crate::mesh::{Mesh, MeshConfig, MeshName};
        let mut mesh = Mesh::try_new(
            crate::crypto::Seed::from_bytes([5u8; 32]),
            MeshName::try_new("t").unwrap(),
            MeshConfig::loopback(),
        )
        .unwrap();
        mesh.set_invite();
        mesh
    }

    #[test]
    fn a_bare_invite_only_hash_is_refused_at_unlock_with_a_pointer() {
        // The attack: skip the invite and join with the raw hash. `unlock` must
        // refuse, so no mesh is ever derived without its root.
        let id = invite_only_mesh().to_string();
        let target: JoinTarget = id.parse().unwrap();
        let error = resolve(&target)
            .unwrap()
            .unlock(None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("invite-only"), "got: {error}");
    }

    #[test]
    fn a_minted_invite_classifies_as_invite() {
        let token = crate::invite::mint(
            &invite_only_mesh(),
            Some(std::time::Duration::from_hours(1)),
            None,
        )
        .unwrap();
        let parsed: Result<JoinTarget, _> = token.parse();
        assert!(matches!(parsed, Ok(JoinTarget::Invite(_))));
    }
}
