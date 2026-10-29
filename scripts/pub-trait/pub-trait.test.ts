// Tests of scripts/pub-trait/pub-trait.ts. Each case plants files in a scratch git repository, with
// and runs the check there. A trait the check misses, or a clean file it
// refuses, fails here.

import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, expect, test } from "bun:test";

const here = path.dirname(fileURLToPath(import.meta.url));
const work = mkdtempSync(path.join(tmpdir(), "pub-trait-"));
afterAll(() => rmSync(work, { recursive: true, force: true }));

// Plant each file in a fresh repository, then run the check. `allow` is a file the check must ignore; it is written only when a test passes one.
function check(files: Record<string, string>, allow = ""): { status: number; out: string } {
  const repo = mkdtempSync(path.join(work, "repo-"));
  mkdirSync(path.join(repo, "scripts", "pub-trait"), { recursive: true });
  copyFileSync(path.join(here, "pub-trait.ts"), path.join(repo, "scripts", "pub-trait", "pub-trait.ts"));
  if (allow) writeFileSync(path.join(repo, "scripts", "pub-trait", "pub-trait.allow"), `${allow}\n`);
  for (const [file, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(repo, file)), { recursive: true });
    writeFileSync(path.join(repo, file), `${content}\n`);
  }
  spawnSync("git", ["init", "-q"], { cwd: repo });
  const proc = spawnSync(process.execPath, [path.join(repo, "scripts", "pub-trait", "pub-trait.ts")], {
    cwd: repo,
    encoding: "utf8",
  });
  return { status: proc.status ?? -1, out: `${proc.stdout ?? ""}${proc.stderr ?? ""}` };
}

const expectExit = (files: Record<string, string>, expected: number, allow = "") => {
  const run = check(files, allow);
  expect(run.status, run.out).toBe(expected);
};

const trait = "pub trait Sink {}";

test("a new pub trait is refused", () => {
  expectExit({ "crates/x/src/a.rs": trait }, 1);
});

test("no allow lookup: a pub trait that a row names still fails", () => {
  expectExit({ "crates/x/src/a.rs": trait }, 1, "crates/x/src/a.rs|1|a generic bound");
});

test("a crate-private trait is clean", () => {
  expectExit({ "crates/x/src/a.rs": "pub(crate) trait Sink {}" }, 0);
});

// A trait that a crate file uses as a bound, a dyn object or a supertrait is justified, with no row.
test("a pub trait used as a dyn object is clean", () => {
  expectExit({ "crates/x/src/a.rs": trait, "crates/x/src/b.rs": "fn f(s: &dyn Sink) { let _ = s; }" }, 0);
});

test("a pub trait used as a generic bound is clean", () => {
  expectExit({ "crates/x/src/a.rs": trait, "crates/x/src/b.rs": "fn f<T: Sink>(s: T) { let _ = s; }" }, 0);
});

test("a pub trait used in a where clause is clean", () => {
  expectExit({ "crates/x/src/a.rs": trait, "crates/x/src/b.rs": "fn f<T>(s: T) where T: Sink { let _ = s; }" }, 0);
});

test("a pub trait used as an impl bound is clean", () => {
  expectExit({ "crates/x/src/a.rs": trait, "crates/x/src/b.rs": "fn f(s: impl Sink) { let _ = s; }" }, 0);
});

test("a pub trait used as a supertrait is clean", () => {
  expectExit(
    { "crates/x/src/a.rs": trait, "crates/x/src/b.rs": "pub trait Proof: Sink {}", "crates/x/src/c.rs": "fn f<T: Proof>(t: T) { let _ = t; }" },
    0,
  );
});

test("a field of a type with the trait's name is not a use", () => {
  expectExit({ "crates/x/src/a.rs": trait, "crates/x/src/b.rs": "struct S { sink: Sink }" }, 1);
});
