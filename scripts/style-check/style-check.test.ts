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

// A type lifetime is named for what it borrows. A single letter is allowed on a fn.
test("lifetime: single letter on a struct", () => {
  expectExit("src/a.rs", "pub struct Frame<'a>(&'a [u8]);", 1);
});
test("lifetime: single letter on an enum", () => {
  expectExit("src/a.rs", "enum Keying<'a> { Shared(&'a u8) }", 1);
});
test("lifetime: descriptive name on a struct", () => {
  expectExit("src/a.rs", "pub struct Frame<'frame>(&'frame [u8]);", 0);
});
test("lifetime: serde de on a struct", () => {
  expectExit("src/a.rs", "struct Visitor<'de>(PhantomData<&'de ()>);", 0);
});
test("lifetime: single letter on a fn", () => {
  expectExit("src/a.rs", "fn first<'a>(x: &'a [u8]) -> &'a u8 { &x[0] }", 0);
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

// The anyhow_pub rule: a public signature that returns anyhow, in a library file.
const anyhowFixture = [
  "pub fn a() -> anyhow::Result<()> { Ok(()) }",
  "pub fn b(",
  "    x: u8,",
  ") -> anyhow::Result<",
  "    u8,",
  "> {",
  "    Ok(x)",
  "}",
  "pub(crate) fn c() -> anyhow::Result<()> { Ok(()) }",
  "pub trait T {",
  "    fn d(&self) -> anyhow::Result<()>;",
  "}",
  "impl std::str::FromStr for X {",
  "    type Err = anyhow::Error;",
  "    fn from_str(_: &str) -> Result<Self, Self::Err> { unimplemented!() }",
  "}",
  "use anyhow::Result;",
  "pub fn g() -> Result<u8> { Ok(1) }",
  "#[cfg(test)]",
  "mod tests {",
  "    pub fn e() -> anyhow::Result<()> { Ok(()) }",
  "}",
].join("\n");
const anyhowMain = "pub fn m() -> anyhow::Result<()> { Ok(()) }";
test("anyhow_pub: the Result import counts when a public fn returns the bare alias", () => {
  expectExit("crates/demo/src/lib.rs", "use anyhow::Result;\npub fn e() -> Result<u8> { Ok(1) }", 1);
});
test("anyhow_pub: the Result import does not count without a public bare-alias fn", () => {
  expectExit("crates/demo/src/lib.rs", "use anyhow::Result;\npub(crate) fn f() -> Result<u8> { Ok(1) }\nfn g() -> Result<u8> { Ok(1) }", 0);
});
test("anyhow_pub: five public forms, not the pub(crate), the test module, or the binary", () => {
  expectExit("crates/demo/src/lib.rs", anyhowFixture, 1);
  expectExit("crates/demo/src/main.rs", anyhowMain, 0);
});
test("anyhow_pub: the exact count is allowed", () => {
  expectExit("crates/demo/src/lib.rs", anyhowFixture, 0, "anyhow_pub|crates/demo/src/lib.rs|5|fixture");
});
test("anyhow_pub: one more than allowed fails", () => {
  expectExit("crates/demo/src/lib.rs", anyhowFixture.replace("#[cfg(test)]", "pub fn z() -> anyhow::Result<()> { Ok(()) }\n#[cfg(test)]"), 1, "anyhow_pub|crates/demo/src/lib.rs|5|fixture");
});
test("anyhow_pub: a stale count fails", () => {
  expectExit("crates/demo/src/lib.rs", anyhowFixture, 1, "anyhow_pub|crates/demo/src/lib.rs|6|fixture");
});

// The advisor's review of the anyhow_pub rule: one case per hole, each failing on the old rule.
test("anyhow_pub: a bare Result fn counts beside the import, once per fn", () => {
  expectExit("crates/demo/src/lib.rs", "use anyhow::Result;\npub fn f() -> Result<u8> { Ok(1) }\npub fn g() -> Result<u8> { Ok(2) }", 0, "anyhow_pub|crates/demo/src/lib.rs|2|fixture");
});
test("anyhow_pub: a test module strips only its own body", () => {
  expectExit("crates/demo/src/lib.rs", "#[cfg(test)]\nmod tests {\n    fn t() {}\n}\npub fn late() -> anyhow::Result<()> { Ok(()) }", 0, "anyhow_pub|crates/demo/src/lib.rs|1|fixture");
});
test("anyhow_pub: a commented-out signature does not count", () => {
  expectExit("crates/demo/src/lib.rs", "// pub fn f() -> anyhow::Result<()> { Ok(()) }", 0);
});
test("anyhow_pub: the error may be second, and the alias may sit in a Future", () => {
  expectExit("crates/demo/src/lib.rs", "pub fn f() -> Result<(), anyhow::Error> { Ok(()) }\npub trait T {\n    fn g(&self) -> impl Future<Output = anyhow::Result<()>>;\n}", 0, "anyhow_pub|crates/demo/src/lib.rs|2|fixture");
});
test("anyhow_pub: an Option of the alias counts", () => {
  expectExit("crates/demo/src/lib.rs", "pub fn f() -> Option<anyhow::Result<()>> { None }", 0, "anyhow_pub|crates/demo/src/lib.rs|1|fixture");
});
test("anyhow_pub: a pub trait inside an inline module counts", () => {
  expectExit("crates/demo/src/lib.rs", "pub mod m {\n    pub trait T {\n        fn d(&self) -> anyhow::Result<()>;\n    }\n}", 0, "anyhow_pub|crates/demo/src/lib.rs|1|fixture");
});
test("anyhow_pub: an extern C fn counts", () => {
  expectExit("crates/demo/src/lib.rs", "pub extern \"C\" fn f() -> anyhow::Result<()> { Ok(()) }", 0, "anyhow_pub|crates/demo/src/lib.rs|1|fixture");
});
test("anyhow_pub: a use-as alias counts through its fns", () => {
  expectExit("crates/demo/src/lib.rs", "use anyhow::Result as AResult;\npub fn f() -> AResult<()> { Ok(()) }\npub fn g() -> AResult<u8> { Ok(1) }", 0, "anyhow_pub|crates/demo/src/lib.rs|2|fixture");
});
test("anyhow_pub: a type alias of the alias counts through its fns", () => {
  expectExit("crates/demo/src/lib.rs", "pub type Res<T> = anyhow::Result<T>;\npub fn f() -> Res<()> { Ok(()) }", 0, "anyhow_pub|crates/demo/src/lib.rs|1|fixture");
});
test("anyhow_pub: a macro body that names its fn counts", () => {
  expectExit("crates/demo/src/lib.rs", "macro_rules! m {\n    ($name:ident) => {\n        pub fn $name() -> anyhow::Result<()> { Ok(()) }\n    };\n}", 0, "anyhow_pub|crates/demo/src/lib.rs|1|fixture");
});
