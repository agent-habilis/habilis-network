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

    // The consumer builds its own "use the topic command instead" hint off this
    // variant, so the trimmed input has to survive classification verbatim.
    use crate::{crypto, invite, meshes};
    use std::time;
    #[test]
    fn a_non_token_string_is_unrecognized_and_echoes_its_input() {
        let _guard = ::habilis_network_test_tracing::init();
        let parsed: Result<JoinTarget, _> = "  github.com/alice/proj ".parse();
        let error = parsed.expect_err("`parsed` fails in this test's fixture");
        assert_eq!(
            error,
            JoinTargetError::Unrecognized("github.com/alice/proj".to_owned()),
            "a non-token string is unrecognized and echoes its input"
        );
        assert!(
            error.to_string().contains("github.com/alice/proj"),
            "got: {error}"
        );
    }

    fn known_mesh_id() -> String {
        use crate::meshes::{Mesh, MeshConfig, MeshName};
        Mesh::try_new(
            crypto::Seed::new([1u8; 32]),
            MeshName::try_new("test").expect("`MeshName::try_new(\"test\")` yields a value in this test's fixture"),
            MeshConfig::loopback(),
        )
        .expect("`Mesh::try_new( crypto::Seed::new([1u8; 32]), MeshName::try_new(\"test\").expect(\"`MeshName::try_new(\\\"test\\\")` yields a value in this test's fixture\"), MeshConfig::loopback(), )` yields a value in this test's fixture")
        .to_string()
    }

    #[test]
    fn resolve_passthrough_for_valid_mesh_id() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = known_mesh_id();
        let target: JoinTarget = id
            .parse()
            .expect("`id.parse()` yields a value in this test's fixture");
        let mesh =
            resolve(&target).expect("`resolve(&target)` yields a value in this test's fixture");
        assert_eq!(mesh.to_string(), id, "a valid mesh id resolves to itself");
    }

    #[test]
    fn mistyped_mesh_id_reports_an_invalid_gossip_hash() {
        let _guard = ::habilis_network_test_tracing::init();
        let mut mistyped = known_mesh_id();
        let replacement = if mistyped.ends_with('1') { "2" } else { "1" };
        mistyped.replace_range(mistyped.len() - 1.., replacement);
        let parsed: Result<JoinTarget, _> = mistyped.parse();
        let error = parsed.expect_err("`parsed` fails in this test's fixture");
        assert_eq!(
            error.to_string(),
            "invalid gossip hash",
            "a mistyped mesh id reports an invalid gossip hash"
        );
    }

    #[test]
    fn join_target_classifies_valid_id() {
        let _guard = ::habilis_network_test_tracing::init();
        let id = known_mesh_id();
        let parsed: Result<JoinTarget, _> = id.parse();
        assert!(
            matches!(parsed, Ok(JoinTarget::Mesh(_))),
            "a valid id classifies as a mesh target"
        );
    }

    fn invite_only_mesh() -> meshes::Mesh {
        use crate::meshes::{Mesh, MeshConfig, MeshName};
        let mut mesh = Mesh::try_new(
            crypto::Seed::new([5u8; 32]),
            MeshName::try_new("t").expect("`MeshName::try_new(\"t\")` yields a value in this test's fixture"),
            MeshConfig::loopback(),
        )
        .expect("`Mesh::try_new( crypto::Seed::new([5u8; 32]), MeshName::try_new(\"t\").expect(\"`MeshName::try_new(\\\"t\\\")` yields a value in this test's fixture\"), MeshConfig::loopback(), )` yields a value in this test's fixture");
        mesh.set_invite();
        mesh
    }

    #[test]
    fn a_bare_invite_only_hash_is_refused_at_unlock_with_a_pointer() {
        let _guard = ::habilis_network_test_tracing::init();
        // The attack: skip the invite and join with the raw hash. `unlock` must
        // refuse, so no mesh is ever derived without its root.
        let id = invite_only_mesh().to_string();
        let target: JoinTarget = id
            .parse()
            .expect("`id.parse()` yields a value in this test's fixture");
        let error: String = resolve(&target)
            .expect("`resolve(&target)` yields a value in this test's fixture")
            .unlock(None)
            .expect_err("unlock refuses a password-protected mesh given no password")
            .to_string();
        assert!(error.contains("invite-only"), "got: {error}");
    }

    #[test]
    fn a_minted_invite_classifies_as_invite() {
        let _guard = ::habilis_network_test_tracing::init();
        let token = invite::mint(
            &invite_only_mesh(),
            Some(time::Duration::from_hours(1)),
            None,
        )
        .expect("`invite::mint(..)` yields a value in this test's fixture");
        let parsed: Result<JoinTarget, _> = token.parse();
        assert!(
            matches!(parsed, Ok(JoinTarget::Invite(_))),
            "a minted invite classifies as an invite target"
        );
    }
}
