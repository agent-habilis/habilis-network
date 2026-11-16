#!/usr/bin/env bun
// Build the app binary of one benchmark arm in a clean worktree, and record how it was made.
//
// usage: bun scripts/perf/build-arm.ts <arm> <app worktree> [<engine worktree>]
//
// The app worktree is a checkout of agent-gossip. Without an engine worktree the binary uses the
// engine rev that the app pins. With one, the engine crates come from that worktree, through
// `cargo --config` on the command line: no [patch] table is written to any file.
//
// Output, in ~/bench-results/baseline/: <arm>/agent-gossip (the binary) and <arm>.json (arm, the
// shas and dirty flags of both worktrees, the override, the binary sha256, the version text, the
// toolchain, the host load at the start of the build, the build time).

import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, loadavg } from "node:os";
import path from "node:path";

const [arm = "", app = "", engineArg = ""] = process.argv.slice(2);
if (!arm || !app) {
  console.error("usage: build-arm.ts <arm> <app worktree> [<engine worktree>]");
  process.exit(2);
}
// Cargo reads the patch paths from the app worktree, so a relative engine path is resolved here, against
// the folder of the call.
const engine = engineArg ? path.resolve(engineArg) : "";
const ENGINE_URL = "https://github.com/agent-habilis/habilis-network";

function run(cmd: string[], cwd: string, env: Record<string, string> = {}): { code: number; out: string } {
  const proc = Bun.spawnSync(cmd, { cwd, env: { ...process.env, ...env }, stdout: "pipe", stderr: "pipe" });
  return { code: proc.exitCode ?? 1, out: proc.stdout.toString() + proc.stderr.toString() };
}

// An override makes cargo rewrite Cargo.lock. That is not a source change, so the dirty flag ignores it.
const describe = (dir: string) => ({
  sha: run(["git", "rev-parse", "HEAD"], dir).out.trim(),
  dirty: run(["git", "status", "--porcelain", "--", ".", ":!Cargo.lock"], dir).out.trim() !== "",
});

// The engine crates that the app resolves from the engine git source.
const lock = readFileSync(path.join(app, "Cargo.lock"), "utf8");
const crates = [
  ...new Set(
    [...lock.matchAll(/name = "([^"]+)"\nversion = "[^"]+"\nsource = "git\+https:\/\/github\.com\/agent-habilis\/habilis-network[^"]*"/g)].map(
      (found) => found[1] ?? "",
    ),
  ),
].sort();

const overrides = engine
  ? crates.flatMap((name) => ["--config", `patch."${ENGINE_URL}".${name}.path="${path.join(engine, "crates", name)}"`])
  : [];

// BENCH_TARGET lets two arms of one app share a target folder: only the crates that differ rebuild.
const target = process.env.BENCH_TARGET ?? path.join(homedir(), "bench-build", `${arm}-target`);
const env = { CARGO_TARGET_DIR: target };
const cargo = ["cargo", ...overrides, "build", "--release", "-p", "agent-gossip", "--bin", "agent-gossip"];
const load = loadavg()[0] ?? 0;
const started = Date.now();
// An override makes cargo rewrite Cargo.lock; every way out puts it back, so the next arm starts from the commit.
const restoreLock = () => run(["git", "checkout", "--", "Cargo.lock"], app);
function fail(message: string): never {
  restoreLock();
  console.error(message);
  process.exit(1);
}
const build = run(cargo, app, env);
if (build.code !== 0) fail(build.out.split("\n").slice(-30).join("\n"));
const seconds = Math.round((Date.now() - started) / 1000);

// One copy of the engine must be in the graph: the override replaced the pinned one.
const tree = run(["cargo", ...overrides, "tree", "-i", "habilis-network"], app, env).out;
const copies = [...tree.matchAll(/^habilis-network v\S+ \(([^)]*)\)/gm)].map((found) => found[1]);
if (new Set(copies).size !== 1) fail(`expected one habilis-network copy, found: ${copies.join(" | ") || tree}`);
// A git copy here means that cargo did not take the override: the binary has the engine that the app pins.
if (engine && !copies.every((copy) => copy?.startsWith(path.join(engine, "crates")))) {
  fail(`the engine override was not applied: habilis-network comes from ${copies.join(" | ")}`);
}

const lockRewritten = run(["git", "status", "--porcelain", "--", "Cargo.lock"], app).out.trim() !== "";
const record_app = { path: app, ...describe(app), lock_rewritten_by_override: lockRewritten };
// The worktree is ours: put the lock file back, so that the next arm starts from the commit.
if (lockRewritten) restoreLock();

const dir = path.join(homedir(), "bench-results", "baseline");
mkdirSync(path.join(dir, arm), { recursive: true });
const binary = path.join(dir, arm, "agent-gossip");
copyFileSync(path.join(target, "release", "agent-gossip"), binary);
const sha256 = new Bun.CryptoHasher("sha256").update(readFileSync(binary)).digest("hex");
const record = {
  arm,
  app: record_app,
  engine: engine ? { path: engine, ...describe(engine) } : null,
  override: overrides.filter((arg) => arg !== "--config"),
  engine_copies: copies,
  binary,
  sha256,
  version: run([binary, "--version"], dir).out.trim(),
  toolchain: run(["rustc", "--version"], app).out.trim(),
  load1_at_start: load,
  build_seconds: seconds,
};
writeFileSync(path.join(dir, `${arm}.json`), JSON.stringify(record, null, 2) + "\n");
console.log(JSON.stringify(record, null, 2));
