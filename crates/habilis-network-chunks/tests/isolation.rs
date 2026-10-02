//! The kill-gate on the seam: this crate must not know what a share is.
//!
//! `habilis-network-chunks` never sees a manifest, a ticket, a mesh, an ALPN or a token.
//! It takes a hash, some bytes and a chunk map. If the trait needs any of those
//! to be useful, the seam is in the wrong place and the crate has quietly
//! become part of the network layer rather than a thing the network layer uses.
//!
//! This is also what keeps the crate *movable*. It is developed here and named
//! for `agent-habilis/habilis-network`, where it is meant to land; an edge into
//! `agent-share` or into the iroh family would block that move, and would do so
//! silently until the day someone tried it.
//!
//! A compile-time check would be better than reading the manifest, but a crate
//! cannot ask "am I linked against X" from inside itself. Reading the manifest
//! is the honest approximation, and it fails loudly the moment someone adds the
//! dependency that would make everything easier and the seam meaningless.

use std::path::Path;

/// Dependency-name prefixes that would mean the seam has collapsed. Prefixes,
/// not exact names: `agent-share` covers every sibling in this workspace,
/// `habilis-network` covers the destination workspace's crates, and `iroh` covers
/// `iroh-base` / `iroh-gossip` / `iroh-io` alike.
///
/// `habilis-network` is forbidden *despite this crate being called `habilis-network-chunks`*.
/// The package's own `name = ` line does not start with the prefix, so the
/// check stays meaningful: it is the dependency edges that matter.
const FORBIDDEN: &[&str] = &["agent-share", "habilis-network", "iroh"];

/// Lines that name the package rather than a dependency. Everything else in a
/// `[dependencies]`-shaped line begins with the crate being depended on.
fn is_metadata(line: &str) -> bool {
    line.starts_with('#')
        || line.starts_with('[')
        || line.starts_with("name")
        || line.starts_with("repository")
        || line.starts_with("description")
}

fn manifest() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("this crate has a Cargo.toml")
}

#[test]
fn the_crate_does_not_know_about_the_network_layer() {
    for line in manifest().lines() {
        let line = line.trim();
        if is_metadata(line) {
            continue;
        }
        for forbidden in FORBIDDEN {
            assert!(
                !line.starts_with(forbidden),
                "habilis-network-chunks must not depend on {forbidden}: found `{line}`.\n\
                 The store takes a hash, some bytes and a chunk map. If it needs \
                 a share to be useful, move the seam rather than the dependency."
            );
        }
    }
}

/// The other half of the rule, in the direction people forget: the crate must
/// stay buildable for the browser, because the browser runs the same store.
///
/// Not a substitute for `cargo check --target wasm32-unknown-unknown`, which CI
/// runs — this only catches a dependency that is *obviously* host-only, before
/// someone waits for a wasm build to tell them.
#[test]
fn no_obviously_host_only_dependency_crept_in() {
    // `tokio` is the one that would slip in most naturally, via someone
    // reaching for `tokio::fs` in a backend. Backends own their I/O; this crate
    // does not.
    for host_only in ["tokio", "interprocess", "memmap2", "nfsserve", "notify"] {
        for line in manifest().lines() {
            let line = line.trim();
            if is_metadata(line) {
                continue;
            }
            assert!(
                !line.starts_with(host_only),
                "habilis-network-chunks must build for wasm32; `{host_only}` is host-only.\n\
                 If a backend needs it, the backend is the place for it."
            );
        }
    }
}

/// bao is what this crate exists to *replace*, and a stray dependency on it
/// would mean someone reached for position-bound hashes again.
///
/// The distinction is the crate's whole premise: BLAKE3 threads a chunk counter
/// into its compression function, so a bao subtree hash is bound to *where* the
/// bytes sit. That is a fine proof of placement and a useless content address —
/// the same 64 `KiB` at two offsets hashes two ways, so nothing ever dedups.
#[test]
fn no_bao_creeps_back_in() {
    for line in manifest().lines() {
        let line = line.trim();
        if is_metadata(line) {
            continue;
        }
        assert!(
            !line.starts_with("bao"),
            "habilis-network-chunks addresses chunks by content, not by position.\n\
             A bao subtree hash is position-bound (BLAKE3's chunk counter), so \
             it can prove placement but can never be a content address."
        );
    }
}
