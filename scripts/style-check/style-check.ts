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

// The public signatures that return anyhow. Comments and `#[cfg(test)] mod` bodies are cut
// first. A `pub fn` (also `pub extern "C" fn`, and a `$name` in a macro body) counts when its
// return type names `anyhow::Result` or `anyhow::Error` anywhere, or a bare one-argument
// `Result<T>` in a file that imports anyhow's `Result`, or an alias of either. A method of a
// `pub trait` counts the same way, at any indent. A `FromStr` or `TryFrom` impl with anyhow as
// its error counts once.
const ANYHOW_ERR = /\btype (?:Err|Error)\s*=\s*(?:::)?anyhow::Error\b/g;
const PUB_FN = /\bpub (?:const |async |unsafe |extern(?: "")? )*fn (\$?\w+)/g;
const TRAIT_FN = /\bfn (\$?\w+)/g;
const PUB_TRAIT = /\bpub trait\b[^{;]*\{/g;
const ANYHOW_USE_AS = /\buse (?:::)?anyhow::Result as (\w+)\s*;/g;
const ANYHOW_USE_BARE = /^\s*use (?:::)?anyhow::\{?[^;]*\bResult\b(?!\s+as\b)[^;]*;/m;
const ANYHOW_MODULE_ALIAS = /\buse (?:::)?anyhow as (\w+)\s*;/g;
const ANYHOW_TYPE_ALIAS = /\btype (\w+)(?:<[^=]*>)?\s*=\s*(?:::)?anyhow::Result\b/g;

/** Text with line comments and block comments blanked, so a commented-out signature counts nothing. */
function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, "");
}

/** Text with the body of each string literal blanked, so a string that holds a signature counts nothing. */
function blankStrings(text: string): string {
  return text.replace(/"(?:[^"\\\n]|\\.)*"/g, "\"\"");
}

/** The index of the `}` that closes the `{` at `open`. */
function closeBrace(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}" && --depth === 0) return i;
  }
  return text.length - 1;
}

/** `text` with the body of every `#[cfg(test)] mod name { ... }` removed, and nothing else. */
function stripTestModules(text: string): string {
  const pattern = /#\[cfg\(test\)\]\s*\n\s*mod \w+\s*\{/;
  let out = text;
  for (let m = pattern.exec(out); m; m = pattern.exec(out)) {
    const open = m.index + m[0].length - 1;
    out = out.slice(0, m.index) + out.slice(closeBrace(out, open) + 1);
  }
  return out;
}

/** The return type after the parameter list at `from`: up to `{`, `;` or `where`. */
function returnType(text: string, from: number): string {
  let depth = 0;
  let i = from;
  for (; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")" && --depth === 0) break;
  }
  const arrow = /^\s*->/.exec(text.slice(i + 1));
  if (!arrow) return "";
  const rest = text.slice(i + 1 + arrow[0].length);
  const end = rest.search(/[{;]|\bwhere\b/);
  return (end < 0 ? rest : rest.slice(0, end)).trim();
}

/** Whether `ret` has `name` with exactly one top-level type argument, as in `Result<T>`. */
function isBareOneArg(ret: string, name: string): boolean {
  const at = new RegExp(`(?:^|[^\\w:])${name}<`).exec(ret);
  if (!at) return false;
  let angle = 0;
  let nested = 0;
  let commas = 0;
  for (let i = at.index + at[0].length - 1; i < ret.length; i++) {
    const c = ret[i];
    if (c === "<") angle++;
    else if (c === ">" && --angle === 0) return commas === 0;
    else if (c === "(" || c === "[") nested++;
    else if (c === ")" || c === "]") nested--;
    else if (c === "," && angle === 1 && nested === 0) commas++;
  }
  return false;
}

function countAnyhowPub(raw: string): number {
  const text = stripTestModules(blankStrings(stripComments(raw)));
  const bare = new Set<string>();
  if (ANYHOW_USE_BARE.test(text)) bare.add("Result");
  for (const [, name] of text.matchAll(ANYHOW_USE_AS)) if (name) bare.add(name);
  for (const [, name] of text.matchAll(ANYHOW_TYPE_ALIAS)) if (name) bare.add(name);
  const modules = [...text.matchAll(ANYHOW_MODULE_ALIAS)].flatMap(([, name]) => (name ? [name] : []));
  const anyhowRet = (ret: string): boolean =>
    /\banyhow::(?:Result|Error)\b/.test(ret) ||
    modules.some((module) => new RegExp(`\\b${module}::(?:Result|Error)\\b`).test(ret)) ||
    [...bare].some((name) => isBareOneArg(ret, name));
  let count = [...text.matchAll(ANYHOW_ERR)].length;
  for (const m of text.matchAll(PUB_FN)) {
    if (anyhowRet(returnType(text, m.index! + m[0].length))) count++;
  }
  for (const m of text.matchAll(PUB_TRAIT)) {
    const open = m.index! + m[0].length - 1;
    const body = text.slice(open, closeBrace(text, open));
    for (const f of body.matchAll(TRAIT_FN)) {
      if (anyhowRet(returnType(body, f.index! + f[0].length))) count++;
    }
  }
  return count;
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
    name: "glob",
    pattern: /^\s*(pub(\([^)]*\))?\s+)?use\s[^;]*(::\*|\{\s*\*|,\s*\*)/,
    glob: "*.rs",
    why: "Import each name. No glob import: not `use super::*` in a test module, not a `pub use` facade, not a third-party prelude. Clippy exempts the first two, so only this rule stops them.",
  },
  {
    name: "operator",
    pattern: /^\s*impl(<[^>]*>)?\s+(std::ops::|ops::)?(Add|Sub|Mul|Div|Rem|Neg|Not|Index|IndexMut|BitAnd|BitOr|BitXor|Shl|Shr)(Assign)?\b/,
    glob: "crates/**/*.rs",
    why: "An operator overload has a math or logic meaning only (a frame advances by frames, a flag set joins flags). Any other use needs a line in style-check.allow with a reason.",
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
