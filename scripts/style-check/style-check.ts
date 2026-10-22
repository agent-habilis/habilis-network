#!/usr/bin/env bun
// Rules of the Google Rust Style Guide (issue #29) that no compiler lint checks.
// Each rule is one pattern. A match fails the check unless `style-check.allow` names the file with
// at least that many matching lines. A new match in an allowed file raises the count, so it fails
// too. A count that is higher than the matches fails as well: lower it when you remove an exception.
// `style-check.test.ts` plants a violation for each rule and for each way the allow list can break.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const allowFile = process.env.STYLE_CHECK_ALLOW || "scripts/style-check/style-check.allow";

type Rule = { name: string; pattern: RegExp; glob: string; why: string };

const RULES: Rule[] = [
  {
    name: "poison",
    pattern: /PoisonError|unwrap_or_else\([|][^|]*[|][^)]*into_inner/,
    glob: "*.rs",
    why: 'Never reach inside a poisoned mutex. Use .expect("...") and let the panic spread.',
  },
  {
    name: "feature",
    pattern: /^\s*#!?\[(cfg_attr\([^\]]*, *)?feature\(/,
    glob: "*.rs",
    why: "No unstable features. The light-cycles example is the one exception, with its own toolchain.",
  },
  {
    name: "catch_unwind",
    pattern: /catch_unwind/,
    glob: "*.rs",
    why: "Do not call panic::catch_unwind in first-party code. A boundary with C is the exception.",
  },
  {
    name: "ctor",
    pattern: /#\[(ctor::)?ctor\]|use ctor([^_a-zA-Z0-9]|$)/,
    glob: "*.rs",
    why: "Do not run code before main().",
  },
  {
    name: "block_doc",
    pattern: /^\s*\/\*[*!]($|[^*/])/,
    glob: "*.rs",
    why: "Document with /// and //!, not with /** */ or /*! */.",
  },
];

// The files git knows, tracked or not yet, minus what .gitignore hides: the same list `git ls-files
// -co --exclude-standard` gives. -z keeps a file name with a space whole.
function listFiles(glob: string): string[] {
  const proc = spawnSync("git", ["ls-files", "-z", "-co", "--exclude-standard", "--", glob], {
    cwd: ROOT,
    encoding: "utf8",
  });
  return (proc.stdout ?? "").split("\0").filter((file) => file.length > 0);
}

// Count the matching lines of each file. A file with no match is left out, as the old check did.
function scan(rule: Rule): Map<string, number> {
  const counts = new Map<string, number>();
  for (const file of listFiles(rule.glob)) {
    if (!existsSync(path.join(ROOT, file))) continue;
    const lines = readFileSync(path.join(ROOT, file), "utf8").split("\n");
    const count = lines.filter((line) => rule.pattern.test(line)).length;
    if (count > 0) counts.set(file, count);
  }
  return counts;
}

type Allowed = Map<string, { count: number; reason: string }>;

// The allow list: `rule|file|count|reason`. Blank lines and `#` comments are skipped.
function readAllow(shownAs: string): { allowed: Allowed; problems: string[] } {
  const allowed: Allowed = new Map();
  const problems: string[] = [];
  const file = path.join(ROOT, shownAs);
  if (!existsSync(file)) return { allowed, problems };
  for (const line of readFileSync(file, "utf8").split("\n")) {
    if (/^\s*(#|$)/.test(line)) continue;
    const [rule, target, count, ...reason] = line.split("|");
    const key = `${rule}|${target}`;
    if (allowed.has(key)) {
      problems.push(`style-check: ${shownAs} has two rows for [${rule}] ${target}. Merge them.`);
    }
    allowed.set(key, { count: Number(count) || 0, reason: reason.join("|") });
  }
  return { allowed, problems };
}

function main(): number {
  const { allowed, problems } = readAllow(allowFile);
  const found = new Map<string, number>(); // key: rule|file
  for (const rule of RULES) {
    for (const [file, count] of scan(rule)) found.set(`${rule.name}|${file}`, count);
  }
  const why = new Map(RULES.map((rule) => [rule.name, rule.why]));

  for (const [key, count] of [...found].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    const [rule, file] = key.split("|");
    const limit = allowed.get(key)?.count ?? 0;
    if (count > limit) {
      problems.push(
        `style-check: [${rule}] ${file}: ${count} matching line(s), ${limit} allowed. ${why.get(rule)}`,
      );
    }
  }
  for (const [key, entry] of [...allowed].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    const have = found.get(key) ?? 0;
    if (have < entry.count) {
      const [rule, file] = key.split("|");
      problems.push(
        `style-check: [${rule}] ${file}: ${have} matching line(s), ${entry.count} allowed. Lower the count in ${allowFile}.`,
      );
    }
  }
  for (const problem of problems) console.log(problem);
  return problems.length > 0 ? 1 : 0;
}

process.exit(main());
