#!/usr/bin/env bun
// A `pub trait` is refused unless a crate file uses it as a generic bound, a dyn object, an impl
// bound or a supertrait. Every other one fails the check. `pub-trait.test.ts` plants one file of each kind.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const TRAIT = /^\s*pub trait\b/gm;
const SCOPE = /^crates\/.*\.rs$/;

// The files git knows that sit under crates/: tracked, or new and not ignored.
function listFiles(): string[] {
  const proc = spawnSync("git", ["ls-files", "-z", "-co", "--exclude-standard"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  return (proc.stdout ?? "").split("\0").filter((file) => SCOPE.test(file));
}

// A trait is justified when some crate file uses it as a generic bound, a dyn object, an impl
// bound or a supertrait. A trait that nothing uses that way is code organization, and is counted.
function usedAsBound(name: string, texts: string[]): boolean {
  const uses = [
    new RegExp(`\\bdyn\\s+${name}\\b`),
    new RegExp(`\\bimpl\\s+(?:[^{;=]*\\+\\s*)?${name}\\b`),
    new RegExp(`<[^>\\n]*\\b\\w+\\s*:\\s*[^>\\n]*\\b${name}\\b`),
    new RegExp(`\\bwhere\\b[^{;]*\\b\\w+\\s*:\\s*[^{;]*\\b${name}\\b`),
    new RegExp(`\\bpub trait\\s+\\w+\\s*:\\s*[^{]*\\b${name}\\b`),
  ];
  return texts.some((text) => uses.some((use) => use.test(text)));
}

function unjustifiedIn(file: string, texts: string[]): number {
  const text = readFileSync(path.join(ROOT, file), "utf8");
  const names = [...text.matchAll(/^\s*pub trait\s+(\w+)/gm)].map((m) => m[1]!);
  return names.filter((name) => !usedAsBound(name, texts)).length;
}

function main(): number {
  const problems: string[] = [];
  const files = listFiles();
  const texts = files.map((file) => readFileSync(path.join(ROOT, file), "utf8"));
  for (const file of files) {
    const count = unjustifiedIn(file, texts);
    if (count > 0) {
      problems.push(`pub-trait: ${file}: ${count} pub trait not used as a bound, a dyn object or a supertrait. Define it only for one of those, or make it private.`);
    }
  }
  for (const problem of problems.sort()) console.log(problem);
  return problems.length > 0 ? 1 : 0;
}

process.exit(main());
