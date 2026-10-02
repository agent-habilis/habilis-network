# Vendored packages

Copied from `~/Developer/visage-ui/visage/packages/*` @ `82e7506` + dirty
working tree (same commit and same dirty state `agent-share/web/vendor/`
documents its own copy from — the moonspace package split and the
visage-dom `this`-based context API existed only as uncommitted changes at
copy time, still true here).

- `visage-dom` — required by the other two; the reactive view library
  (generator components, `signal`, `tags`) for the create/join screen, HUD,
  and roster.
- `visage-canvas` — the scene-graph canvas backend for the arena/trail
  rendering.
- `visage-style` — token/theme system, for the per-player color palette.

Copied with `node_modules`, `dist`, and `.git` excluded, same as
`agent-share/web/vendor/`'s own copy.

**Not vendored**, per the plan: `visage-router` (single-page game, no
routing), `visage-webgpu` (2D canvas is the right level of abstraction
here), `visage-tui` (not usable from a native Rust binary — its terminal-
diffing *model* is ported to Rust instead, as `native/visage-rust-tui`).
`moonspace`/`moonspace-dom`/`moonspace-theme` are also skipped for now (the
plan explicitly allows this — "skip these if a leaner example is
preferred"); nothing here depends on them.

## No local patches applied (yet)

`agent-share/web/vendor/README.md` documents several patches it needed on
top of these same packages (`flex` kept unitless, a `UNITLESS` property set
for numeric inline styles like `opacity`, and JSX-runtime support for plain
stateless view functions). None are applied here — they were discovered by
agent-share actually building its app against these packages, and this
example hasn't built its frontend yet (see the plan's "Build web/ frontend"
task). If the same issues surface once that app exists, re-apply the fix
from `agent-share/web/vendor/README.md`'s own notes rather than
rediscovering it.

## Workspace wiring (differs from upstream)

Same as `agent-share/web/vendor/`: the `visage-*` tsconfigs extend
`web/tsconfig.base.json` (same options as upstream's base, minus `types`),
adding `types: ["bun"]` per package, instead of upstream's own
`tsconfig.json`. Per-package `bunfig.toml` files (copied verbatim from
upstream) preload `../../test-setup.ts`, which is `web/test-setup.ts`.

`visage-canvas` and `visage-style` already declare `visage-dom` as a
`workspace:*` dependency in their own `package.json` upstream — unlike
`moonspace-dom` (which agent-share had to patch), nothing here needed
changing for the workspace link to resolve.
