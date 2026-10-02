# Vendored from agent-habilis/agent-gossip

> **Superseded — see [FORKED.md](FORKED.md).** The engine has since been split
> into separate crates, so the "re-copy the crate directories" update procedure
> below no longer applies. This file is kept for the provenance record and for
> the list of divergences that predate the split.

This directory vendors a subset of the `agent-habilis/agent-gossip` engine as
a self-contained Cargo workspace, so mallorca can build a C static library
(`habilis-network-ffi`) and link it directly without depending on the
upstream repo's full workspace (the `agent-gossip` CLI app, its test
fixtures, examples, etc.).

- **Upstream URL**: https://github.com/agent-habilis/agent-gossip
- **Upstream path**: `agent-gossip/master`
- **Base commit**: `f81b0529ee1b66725295998f15292df1e1ca191c`

## What was vendored

Upstream names, as they were at the time of vendoring — everything has since
been renamed to `habilis-network-*` and split; see [FORKED.md](FORKED.md).

- `crates/agent-habilis-mesh` — the gossip-network engine (verbatim).
- `crates/iroh-multihop-transport` — path dependency of the engine (verbatim).
- `crates/agent-habilis-mesh-ffi` — the C ABI shim, verbatim **except**
  `tests/c_suite.rs` was dropped (it hardcodes paths into upstream's
  `examples/`, which is not vendored here).
- Root `Cargo.lock` and `rust-toolchain.toml`, copied verbatim from the
  upstream workspace root.

Not vendored: `examples/`, `target/`, `.cargo/config.toml`, and any
`agent-gossip` (CLI app) crates — none of these are needed to build the FFI
staticlib.

## Local divergences from upstream

- New workspace root `Cargo.toml` (this directory has no root package
  upstream; only a subset of `[workspace.dependencies]` — the entries the
  three vendored crates actually reference — is carried over).
- `[profile.release]` uses `lto = "thin"`, `codegen-units = 16`,
  `strip = "debuginfo"` instead of upstream's fat LTO / 1 codegen unit
  (build-time tradeoff for the mallorca dev loop). Upstream's
  `panic = "abort"` is deliberately **not** carried over: the FFI crate's
  `catch_unwind` at the C ABI boundary depends on unwinding.
- FFI extension: a `name` field (alongside the existing `nick`) and a
  `mesh_name()` accessor were added to `habilis-network-ffi` (`pipe.rs`,
  `ffi.rs`, `include/mesh.h`, `tests/ffi_smoke.rs`) plus a `staticlib`
  crate-type. These are local-only; not present upstream.

## Updating the vendor

To pull a newer upstream revision, re-copy the three crate directories (and
Cargo.lock / rust-toolchain.toml) from the new commit, re-diff this
`Cargo.toml` against the new upstream root `Cargo.toml`, and reapply the
`name`/`mesh_name()` FFI extension on top.
