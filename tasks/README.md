# tasks

The workspace task runner. Run `cargo task <task>` from anywhere in the
workspace.

Three jobs:

- The quality gate. Everything `.github/workflows/ci.yml` runs lives in
  `src/gate.rs` as data (`STEPS`), so you can run the gate locally with
  `cargo task ci` and narrow it to one crate with `-p`.
- `cargo task e2e`. The browser tests of the WebRTC crate need a long
  preamble, and each step fails without naming its cause. The runner does
  the preamble and names the causes.
- `cargo task benchmark`. Bulk throughput over the transports: habilis-network over
  WebRTC in every pairing (Chrome↔Chrome, Chrome↔native, Safari
  Technology Preview↔native, STP↔Chrome, native↔native) against plain iroh
  and a bare data channel. Results and their reading are
  in `docs/perf/benchmark.md`.

If the gate and the workflow disagree, the workflow wins: CI is what
gates the branch.
