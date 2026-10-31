#!/usr/bin/env bun
// `macro_rules!` and proc macros are refused. Every one fails the check.
// `macro-rules.test.ts` plants one file of each kind.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const MACRO = /\bmacro_rules!|#\[proc_macro(_attribute|_derive)?\]/g;
const SCOPE = /^crates\/.*\.rs$/;

// The files git knows that sit under crates/: tracked, or new and not ignored.
function listFiles(): string[] {
  const proc = spawnSync("git", ["ls-files", "-z", "-co", "--exclude-standard"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  return (proc.stdout ?? "").split("\0").filter((file) => SCOPE.test(file));
}

function countIn(file: string): number {
  const text = readFileSync(path.join(ROOT, file), "utf8");
  return text.match(MACRO)?.length ?? 0;
}

function main(): number {
  const problems: string[] = [];
  for (const file of listFiles()) {
    const count = countIn(file);
    if (count > 0) {
      problems.push(`macro-rules: ${file}: ${count} macro_rules! not allowed. Write a fn, a generic or a trait.`);
    }
  }
  for (const problem of problems.sort()) console.log(problem);
  return problems.length > 0 ? 1 : 0;
}

process.exit(main());
