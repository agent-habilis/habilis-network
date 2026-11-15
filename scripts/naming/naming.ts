#!/usr/bin/env bun
// Naming rules of the Rust style guide that no lint checks (issue #29). Each rule is a per-file
// proxy, and every file that breaks one fails the check.
//   ctor_name: a file with `fn new_<x>` and no plain `fn new` (N10: `new` or `new_with_foo`).
//   from_name: a file with `fn from_<x>` and no `impl From<` (N12: `from_foo` pairs with a From).
// `naming.test.ts` plants one file of each kind.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const rules: Record<string, (src: string) => boolean> = {
  ctor_name: (src) => /\bfn new_\w+\s*[(<]/.test(src) && !/\bfn new\s*[(<]/.test(src),
  from_name: (src) => /\bfn from_(?!str\b)\w+\s*[(<]/.test(src) && !/impl(<[^>]*>)? (?:[\w:]*::)?From</.test(src),
};

const HINT: Record<string, string> = {
  ctor_name: "a constructor named new_<x> needs a plain new in the same file",
  from_name: "a fn named from_<x> needs an impl From in the same file",
};

// The Rust files git knows, tracked or not yet, minus what .gitignore hides.
function listFiles(): string[] {
  const proc = spawnSync("git", ["ls-files", "-z", "-co", "--exclude-standard"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  return (proc.stdout ?? "").split("\0").filter((file) => file.endsWith(".rs"));
}

function main(): number {
  const problems: string[] = [];
  for (const file of listFiles()) {
    const src = readFileSync(path.join(ROOT, file), "utf8");
    for (const [rule, hits] of Object.entries(rules)) {
      if (hits(src)) problems.push(`naming: [${rule}] ${file}: ${HINT[rule] ?? ""}.`);
    }
  }
  for (const problem of problems.sort()) console.log(problem);
  return problems.length > 0 ? 1 : 0;
}

process.exit(main());
