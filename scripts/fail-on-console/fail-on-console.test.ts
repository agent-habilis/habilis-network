import { expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const preload = join(import.meta.dir, "fail-on-console.ts");

// Runs a fixture suite in a child bun process, with the preload that bunfig.toml names.
function runSuite(source: string) {
  const dir = mkdtempSync(join(tmpdir(), "fail-on-console-"));
  try {
    writeFileSync(join(dir, "fixture.test.ts"), source);
    const child = Bun.spawnSync(["bun", "test", "--preload", preload, "fixture.test.ts"], {
      cwd: dir,
      stdout: "pipe",
      stderr: "pipe",
    });
    return { code: child.exitCode, output: `${child.stdout}${child.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const header = `import { afterAll, beforeAll, expect, test } from "bun:test";\n`;
const clean = `test("clean", () => { expect(1).toBe(1); });\n`;

test("a clean suite passes", () => {
  const run = runSuite(header + clean);
  expect(run.code).toBe(0);
});

test("a console.warn in a test fails the test", () => {
  const run = runSuite(header + `test("warns", () => { console.warn("in a test"); });\n`);
  expect(run.code).not.toBe(0);
  expect(run.output).toContain("console.warn: in a test");
});

test("a console.warn at module load fails the first test", () => {
  const run = runSuite(header + `console.warn("at module load");\n` + clean);
  expect(run.code).not.toBe(0);
  expect(run.output).toContain("console.warn: at module load");
});

test("a console.error in beforeAll fails the first test", () => {
  const run = runSuite(
    header + `beforeAll(() => { console.error("in beforeAll"); });\n` + clean,
  );
  expect(run.code).not.toBe(0);
  expect(run.output).toContain("console.error: in beforeAll");
});

test("a console.warn in afterAll fails the suite", () => {
  const run = runSuite(header + `afterAll(() => { console.warn("in afterAll"); });\n` + clean);
  expect(run.code).not.toBe(0);
  expect(run.output).toContain("console.warn: in afterAll");
});
