// Tests of scripts/style-check/style-check.ts. Each case plants a file in a scratch git repository
// and runs the check there. A rule that the check does not catch, or a clean file that it refuses,
// fails here.

import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, expect, test } from "bun:test";

const here = path.dirname(fileURLToPath(import.meta.url));
const work = mkdtempSync(path.join(tmpdir(), "style-check-"));
afterAll(() => rmSync(work, { recursive: true, force: true }));

// Plant `content` at `file` in a fresh repository with `allow` as its allow list, then run the check.
function check(file: string, content: string, allow = ""): { status: number; out: string } {
  const repo = mkdtempSync(path.join(work, "repo-"));
  mkdirSync(path.join(repo, "scripts", "style-check"), { recursive: true });
  copyFileSync(path.join(here, "style-check.ts"), path.join(repo, "scripts", "style-check", "style-check.ts"));
  writeFileSync(path.join(repo, "scripts", "style-check", "style-check.allow"), `${allow}\n`);
  mkdirSync(path.dirname(path.join(repo, file)), { recursive: true });
  writeFileSync(path.join(repo, file), `${content}\n`);
  spawnSync("git", ["init", "-q"], { cwd: repo });
  const proc = spawnSync(process.execPath, [path.join(repo, "scripts", "style-check", "style-check.ts")], {
    cwd: repo,
    encoding: "utf8",
  });
  return { status: proc.status ?? -1, out: `${proc.stdout ?? ""}${proc.stderr ?? ""}` };
}

const expectExit = (file: string, content: string, expected: number, allow = "") => {
  const run = check(file, content, allow);
  expect(run.status, run.out).toBe(expected);
};

const violation = "fn f() { let _ = std::panic::catch_unwind(|| 1); }";

// Each rule catches its plain form.
test("poison: path form", () => {
  expectExit("src/a.rs", "fn f(m: &M) { m.lock().unwrap_or_else(std::sync::PoisonError::into_inner); }", 1);
});
test("poison: closure form", () => {
  expectExit("src/a.rs", "fn f(m: &M) { m.lock().unwrap_or_else(|e| e.into_inner()); }", 1);
});
test("poison: renamed import", () => {
  expectExit("src/a.rs", "use std::sync::PoisonError as Pe;", 1);
});
test("poison: turbofish", () => {
  expectExit("src/a.rs", "fn f() { let _ = PoisonError::<u8>::into_inner; }", 1);
});
test("feature: plain", () => {
  expectExit("src/a.rs", "#![feature(never_type)]", 1);
});
test("feature: behind cfg_attr", () => {
  expectExit("src/a.rs", "#![cfg_attr(nightly, feature(coroutines))]", 1);
});
test("catch_unwind", () => {
  expectExit("src/a.rs", "fn f() { let _ = std::panic::catch_unwind(|| 1); }", 1);
});
test("ctor: attribute", () => {
  expectExit("src/a.rs", "#[ctor]\nfn init() {}", 1);
});
test("ctor: path attribute", () => {
  expectExit("src/a.rs", "#[ctor::ctor]\nfn init() {}", 1);
});
test("block doc: outer", () => {
  expectExit("src/a.rs", "/** old style */\nfn f() {}", 1);
});
test("block doc: inner", () => {
  expectExit("src/a.rs", "/*! crate doc */", 1);
});

// A clean file passes, and so does a string that only looks like a block doc comment.
test("clean file", () => {
  expectExit("src/a.rs", "fn f() {}", 0);
});
test("string with /**", () => {
  expectExit("src/a.rs", 'const G: &str = "src/**";', 0);
});
test("doc comment with ///", () => {
  expectExit("src/a.rs", "/// A doc comment.\nfn f() {}", 0);
});

// The allow list.
test("file name with a space", () => {
  expectExit("c/src/a b.rs", violation, 1);
});
test("allowed, exact count", () => {
  expectExit("src/a.rs", violation, 0, "catch_unwind|src/a.rs|1|a boundary");
});
test("allowed, count exceeded", () => {
  expectExit("src/a.rs", `${violation}\n${violation}`, 1, "catch_unwind|src/a.rs|1|a boundary");
});
test("allowed, count too high (stale)", () => {
  expectExit("src/a.rs", violation, 1, "catch_unwind|src/a.rs|2|a boundary");
});
test("allowed, file has no match (stale)", () => {
  expectExit("src/a.rs", "fn f() {}", 1, "catch_unwind|src/a.rs|1|a boundary");
});
test("two rows for one file", () => {
  expectExit("src/a.rs", violation, 1, "catch_unwind|src/a.rs|1|one\ncatch_unwind|src/a.rs|1|two");
});
test("comment and blank lines in the list", () => {
  expectExit("src/a.rs", violation, 0, "# a comment\n\ncatch_unwind|src/a.rs|1|a boundary");
});
