// Tests of scripts/lint-ratchet.ts. Each case runs the ratchet on a saved clippy run (--from-json)
// against a baseline, and checks the exit code. A count that the ratchet misses fails here.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, expect, test } from "bun:test";

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "lint-ratchet.ts");
const fixtures = path.join(here, "fixtures");
const work = mkdtempSync(path.join(tmpdir(), "lint-ratchet-"));

afterAll(() => rmSync(work, { recursive: true, force: true }));

function ratchet(args: string[]): { status: number; out: string } {
  const proc = spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  return { status: proc.status ?? -1, out: `${proc.stdout ?? ""}${proc.stderr ?? ""}` };
}

function write(name: string, content: string): string {
  const file = path.join(work, name);
  writeFileSync(file, content, "utf8");
  return file;
}

const lines = (file: string) => readFileSync(file, "utf8").split("\n").filter((l) => l.length > 0);

const base = path.join(fixtures, "base.json");
const extra = path.join(fixtures, "extra.json");
const kinds = path.join(fixtures, "kinds.json");
const empty = write("empty", "");

// The baseline of the base run: one finding per lint and crate, as --update writes it.
const baseBaseline = path.join(work, "base.baseline");
ratchet(["--from-json", base, "--baseline", baseBaseline, "--update"]);

// A baseline that is one finding short for habilis-network.
const fewer = write(
  "fewer.baseline",
  "missing_docs|habilis-network|2\nclippy::exhaustive_enums|habilis-network-protocol|1\n",
);

test("equal counts pass", () => {
  // The duplicate lines in base.json count once, and the test, example, task and unknown-lint
  // lines are ignored.
  const run = ratchet(["--from-json", base, "--baseline", baseBaseline]);
  expect(run.status).toBe(0);
});

test("one more finding fails", () => {
  const plus = write("base-plus.json", readFileSync(base, "utf8") + lines(extra)[0] + "\n");
  const run = ratchet(["--from-json", plus, "--baseline", baseBaseline]);
  expect(run.status).toBe(1);
  expect(run.out).toContain("New finding");
});

test("one fewer finding fails", () => {
  const run = ratchet(["--from-json", base, "--baseline", fewer]);
  expect(run.status).toBe(1);
  expect(run.out).toContain("Lower the baseline");
});

test("duplicate span counts once", () => {
  const dup = write(
    "dup.json",
    lines(base)
      .filter((l) => l.includes("crates/habilis-network/src/a.rs") && !l.includes("needless_return"))
      .join("\n") + "\n",
  );
  const dupBaseline = write("dup.baseline", "missing_docs|habilis-network|1\n");
  const run = ratchet(["--from-json", dup, "--baseline", dupBaseline]);
  expect(run.status).toBe(0);
});

test("tests, examples, tasks ignored", () => {
  const ignored = write(
    "ignored.json",
    lines(base)
      .filter((l) => /tests\/|examples\/|tasks\//.test(l))
      .join("\n") + "\n",
  );
  const run = ratchet(["--from-json", ignored, "--baseline", empty]);
  expect(run.status).toBe(0);
});

test("unknown lint ignored", () => {
  const unknown = write(
    "unknown.json",
    lines(base)
      .filter((l) => l.includes("needless_return"))
      .join("\n") + "\n",
  );
  const run = ratchet(["--from-json", unknown, "--baseline", empty]);
  expect(run.status).toBe(0);
});

test("new crate without baseline fails", () => {
  const newcrate = lines(extra).filter((l) => l.includes("habilis-network-newcrate"));
  const combined = write("base-newcrate.json", readFileSync(base, "utf8") + newcrate.join("\n") + "\n");
  const run = ratchet(["--from-json", combined, "--baseline", baseBaseline]);
  expect(run.status).toBe(1);
  expect(run.out).toContain("habilis-network-newcrate");
});

test("update then compare passes", () => {
  const rt = path.join(work, "rt.baseline");
  ratchet(["--from-json", base, "--baseline", rt, "--update"]);
  const run = ratchet(["--from-json", base, "--baseline", rt]);
  expect(run.status).toBe(0);
});

test("missing_docs for a struct field is ignored", () => {
  const field = write("field.json", lines(kinds).filter((l) => l.includes("struct field")).join("\n") + "\n");
  const run = ratchet(["--from-json", field, "--baseline", empty]);
  expect(run.status).toBe(0);
});

test("missing_docs for a variant is ignored", () => {
  const variant = write("variant.json", lines(kinds).filter((l) => l.includes("a variant")).join("\n") + "\n");
  const run = ratchet(["--from-json", variant, "--baseline", empty]);
  expect(run.status).toBe(0);
});

test("missing_docs for a function counts", () => {
  const fn = write("function.json", lines(kinds).filter((l) => l.includes("a function")).join("\n") + "\n");
  const run = ratchet(["--from-json", fn, "--baseline", empty]);
  expect(run.status).toBe(1);
  expect(run.out).toContain("New finding");
});

test("missing_docs for a method counts", () => {
  const method = write("method.json", lines(kinds).filter((l) => l.includes("a method")).join("\n") + "\n");
  const run = ratchet(["--from-json", method, "--baseline", empty]);
  expect(run.status).toBe(1);
  expect(run.out).toContain("New finding");
});
