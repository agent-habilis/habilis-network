// Tests of scripts/naming/naming.ts. Each case plants files in a scratch git repository, with its
// own allow list, and runs the check there. A name the check misses, or a clean file it refuses,
// fails here.

import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, expect, test } from "bun:test";

const here = path.dirname(fileURLToPath(import.meta.url));
const work = mkdtempSync(path.join(tmpdir(), "naming-"));
afterAll(() => rmSync(work, { recursive: true, force: true }));

// Plant each file in a fresh repository and then run the check. `allow` is a file the check must ignore; it is written only when a test passes one.
function check(files: Record<string, string>, allow = ""): { status: number; out: string } {
  const repo = mkdtempSync(path.join(work, "repo-"));
  mkdirSync(path.join(repo, "scripts", "naming"), { recursive: true });
  copyFileSync(path.join(here, "naming.ts"), path.join(repo, "scripts", "naming", "naming.ts"));
  if (allow) writeFileSync(path.join(repo, "scripts", "naming", "naming.allow"), `${allow}\n`);
  for (const [file, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(repo, file)), { recursive: true });
    writeFileSync(path.join(repo, file), `${content}\n`);
  }
  spawnSync("git", ["init", "-q"], { cwd: repo });
  const proc = spawnSync(process.execPath, [path.join(repo, "scripts", "naming", "naming.ts")], {
    cwd: repo,
    encoding: "utf8",
  });
  return { status: proc.status ?? -1, out: `${proc.stdout ?? ""}${proc.stderr ?? ""}` };
}

const expectExit = (files: Record<string, string>, expected: number, allow = "") => {
  const run = check(files, allow);
  expect(run.status, run.out).toBe(expected);
};

const file = "crates/x/src/a.rs";

test("a new_<x> constructor with no plain new is refused", () => {
  expectExit({ [file]: "impl A {\n    pub fn new_with_id(id: u8) -> Self { A(id) }\n}" }, 1);
});

test("a plain new beside new_<x> is clean", () => {
  expectExit({ [file]: "impl A {\n    pub fn new() -> Self { A(0) }\n    pub fn new_with_id(id: u8) -> Self { A(id) }\n}" }, 0);
});

test("no allow lookup: a counted new_<x> still fails", () => {
  expectExit({ [file]: "impl A {\n    pub fn new_with_id(id: u8) -> Self { A(id) }\n}" }, 1, `ctor_name|${file}|1|a fixture`);
});

test("a from_<x> fn with no impl From is refused", () => {
  expectExit({ [file]: "impl A {\n    pub fn from_bytes(b: u8) -> Self { A(b) }\n}" }, 1);
});

test("a from_<x> fn beside an impl From is clean", () => {
  expectExit({ [file]: "impl From<u8> for A {\n    fn from(b: u8) -> Self { A(b) }\n}\nimpl A {\n    pub fn from_bytes(b: u8) -> Self { A(b) }\n}" }, 0);
});

test("no allow lookup: a counted from_<x> fn still fails", () => {
  expectExit({ [file]: "impl A {\n    pub fn from_bytes(b: u8) -> Self { A(b) }\n}" }, 1, `from_name|${file}|1|a fixture`);
});

test("a fn from_str is the FromStr method, not a constructor, and is clean", () => {
  expectExit({ [file]: "impl std::str::FromStr for A {\n    type Err = u8;\n    fn from_str(s: &str) -> Result<Self, u8> { Ok(A(s.len() as u8)) }\n}" }, 0);
});

test("an impl From written with a path counts as an impl From", () => {
  expectExit({ [file]: "impl ::std::convert::From<u8> for A {\n    fn from(b: u8) -> Self { A(b) }\n}\nimpl A {\n    pub fn from_bytes(b: u8) -> Self { A(b) }\n}" }, 0);
});
