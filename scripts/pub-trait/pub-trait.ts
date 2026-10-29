#!/usr/bin/env bun
// A `pub trait` is justified when a crate file uses it as a generic bound, a dyn object, an impl bound
// or a supertrait. Any other `pub trait` is refused unless `pub-trait.allow` names its file with the
// exact count and a reason.
// `pub-trait.test.ts` plants one file of each kind.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const allowFile = process.env.PUB_TRAIT_ALLOW || "scripts/pub-trait/pub-trait.allow";

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

function readAllow(): { allowed: Map<string, number>; problems: string[] } {
  const allowed = new Map<string, number>();
  const problems: string[] = [];
  const file = path.join(ROOT, allowFile);
  if (!existsSync(file)) return { allowed, problems };
  for (const line of readFileSync(file, "utf8").split("\n")) {
    if (/^\s*(#|$)/.test(line)) continue;
    const [target = "", count = ""] = line.split("|");
    if (allowed.has(target)) {
      problems.push(`pub-trait: ${allowFile} has two rows for ${target}. Merge them.`);
    }
    allowed.set(target, Number(count));
  }
  return { allowed, problems };
}

function main(): number {
  const { allowed, problems } = readAllow();
  const found = new Map<string, number>();
  const files = listFiles();
  const texts = files.map((file) => readFileSync(path.join(ROOT, file), "utf8"));
  for (const file of files) {
    const count = unjustifiedIn(file, texts);
    if (count > 0) found.set(file, count);
  }
  for (const [file, count] of [...found].sort()) {
    const expected = allowed.get(file);
    if (expected === undefined) {
      problems.push(
        `pub-trait: ${file}: ${count} pub trait not allowed. Define it only for a generic bound, a dyn object, an extension trait or a sealed trait, then add a row to ${allowFile} with the reason.`,
      );
    } else if (expected !== count) {
      problems.push(`pub-trait: ${file}: ${count} pub trait found, ${expected} allowed. Set the count in ${allowFile}.`);
    }
  }
  for (const file of [...allowed.keys()].sort()) {
    if (!found.has(file)) {
      problems.push(`pub-trait: ${file}: stale row. No pub trait is left in it. Remove it from ${allowFile}.`);
    }
  }
  for (const problem of problems) console.log(problem);
  return problems.length > 0 ? 1 : 0;
}

process.exit(main());
