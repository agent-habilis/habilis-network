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

// A rule is a per-line `pattern`, or a whole-file `scan` for a form that rustfmt can split across lines.
// `skip` leaves a file out of the count.
type Rule = {
  name: string;
  pattern?: RegExp;
  scan?: (text: string) => number;
  skip?: RegExp;
  glob: string;
  why: string;
};

// The public signatures that return anyhow. A `pub fn` whose signature up to `{` or `;` names
// `anyhow::Result` or `anyhow::Error` (the match may run across lines). A `pub trait` body that
// declares such a method. A `FromStr` or `TryFrom` impl with anyhow as its error. A `use` of
// anyhow's `Result` that sits beside a public `Result<T>` fn, which would hide anyhow behind the alias. The `#[cfg(test)] mod tests` tail
// is cut first, because tests keep anyhow.
const ANYHOW_FN = /\bpub (?:const |async |unsafe )*fn \w+[^{;]*?->\s*(?:::)?anyhow::(?:Result|Error)\b/g;
const ANYHOW_TRAIT_FN = /\bfn \w+[^{;]*?->\s*(?:::)?anyhow::(?:Result|Error)\b[^;{]*;/g;
const ANYHOW_TRAIT = /^pub trait[\s\S]*?^}/gm;
const ANYHOW_ERR = /\btype (?:Err|Error)\s*=\s*(?:::)?anyhow::Error\b/g;
const ANYHOW_USE = /^\s*use (?:::)?anyhow::\{?[^;]*\bResult\b/gm;
// A public fn that returns the one-argument alias `Result<T>`. Only such a fn hides anyhow
// behind the import, so the import counts only beside one.
const BARE_RESULT_FN = /\bpub (?:const |async |unsafe )*fn \w+[^{;]*?->\s*Result<(?:[^<>,]|<[^<>]*>)*>/g;
function countAnyhowPub(text: string): number {
  const body = text.replace(/#\[cfg\(test\)\]\s*\n\s*mod tests\b[\s\S]*$/, "");
  const traits = [...body.matchAll(ANYHOW_TRAIT)].map((m) => m[0]).join("\n");
  const aliasImports = [...body.matchAll(BARE_RESULT_FN)].length > 0 ? [...body.matchAll(ANYHOW_USE)].length : 0;
  return (
    [...body.matchAll(ANYHOW_FN)].length +
    [...traits.matchAll(ANYHOW_TRAIT_FN)].length +
    [...body.matchAll(ANYHOW_ERR)].length +
    aliasImports
  );
}

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
    why: "No unstable features. The light-cycles example is the one exception. The project toolchain is a nightly, so only this rule stops a new #![feature].",
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
  {
    name: "lifetime",
    pattern: /\b(struct|enum|trait)\s+\w+<[^>{]*'[a-z](?![A-Za-z0-9_])/,
    glob: "*.rs",
    why: "Name a type lifetime for what it borrows ('frame, not 'a). The guide allows one letter only on a fn.",
  },
  {
    name: "anyhow_pub",
    scan: countAnyhowPub,
    skip: /(^|\/)(main\.rs|bin\/)|^(?!crates\/[^/]+\/src\/)/,
    glob: "crates/**/*.rs",
    why: "A public signature returns a typed error, not anyhow. A binary, a CLI and a private helper may keep anyhow.",
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
    if (rule.skip?.test(file)) continue;
    const text = readFileSync(path.join(ROOT, file), "utf8");
    const count = rule.scan
      ? rule.scan(text)
      : text.split("\n").filter((line) => rule.pattern?.test(line)).length;
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
    const [rule = "", file = ""] = key.split("|");
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
