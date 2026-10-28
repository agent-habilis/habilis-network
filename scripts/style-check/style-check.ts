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

// The closing bracket of the `(` at `open`, skipping nested brackets. Strings are blanked first.
function closeParen(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const ch = text[i] ?? "";
    if ("([{".includes(ch)) depth++;
    else if (")]}".includes(ch) && --depth === 0) return i;
  }
  return text.length - 1;
}

// The number of arguments of a macro call, from the text between its brackets. A trailing comma adds none.
function argCount(args: string): number {
  let depth = 0;
  let commas = 0;
  for (const ch of args) {
    if ("([{".includes(ch)) depth++;
    else if (")]}".includes(ch)) depth--;
    else if (ch === "," && depth === 0) commas++;
  }
  const last = args.slice(args.lastIndexOf(",") + 1).trim();
  if (args.trim() === "") return 0;
  return last === "" ? commas : commas + 1;
}

// The asserts with no message: assert! needs a condition and a message, assert_eq! and assert_ne! need
// two values and a message. A macro with a message already counts as one argument more.
function countAssertsNoMessage(raw: string): number {
  const text = blankStrings(stripComments(raw));
  const pattern = /\bassert(_eq|_ne)?!\s*\(/g;
  let count = 0;
  for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
    const open = m.index + m[0].length - 1;
    const args = text.slice(open + 1, closeParen(text, open));
    if (argCount(args) < (m[1] ? 3 : 2)) count++;
  }
  return count;
}

// The index of the bracket that closes the `(` at `open`. A string literal is skipped whole, so a
// bracket inside a message does not close the call.
function closeCall(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const ch = text[i] ?? "";
    if (ch === '"') {
      for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === "\\") i++;
    } else if ("([{".includes(ch)) depth++;
    else if (")]}".includes(ch) && --depth === 0) return i;
  }
  return text.length - 1;
}

// The top-level arguments of a macro call, trimmed. A string literal is one piece of its argument.
function callArgs(args: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (let i = 0; i < args.length; i++) {
    const ch = args[i] ?? "";
    if (ch === '"') {
      const start = i;
      for (i++; i < args.length && args[i] !== '"'; i++) if (args[i] === "\\") i++;
      cur += args.slice(start, i + 1);
      continue;
    }
    if ("([{".includes(ch)) depth++;
    else if (")]}".includes(ch)) depth--;
    if (ch === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  if (cur.trim() !== "") out.push(cur.trim());
  return out;
}

// The asserts whose message only repeats the condition: `assert!(x, "x")`. Letters and digits are
// compared, so spacing and case do not hide a copy.
function countAssertsRepeatingCondition(raw: string): number {
  const text = stripComments(raw);
  const pattern = /\bassert!\s*\(/g;
  const key = (s: string) => s.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
  let count = 0;
  for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
    const open = m.index + m[0].length - 1;
    const args = callArgs(text.slice(open + 1, closeCall(text, open)));
    const message = args[1]?.match(/^"(.*)"$/s)?.[1];
    if (args.length === 2 && message !== undefined && key(message) === key(args[0] ?? "")) count++;
  }
  return count;
}

// The statements with a method chain of five or more calls. A statement ends at a `;`, a `{` or a `}`
// outside a string, so a chain cannot hide across a block. Comments and strings are blanked first.
const CHAIN_LIMIT = 5;
function countLongChains(raw: string): number {
  const text = blankStrings(stripComments(raw));
  let count = 0;
  for (const stmt of text.split(/[;{}]/)) {
    const calls = stmt.match(/\.\s*\w+\s*(?:::<[^>]*>\s*)?\(/g);
    if (calls && calls.length >= CHAIN_LIMIT) count++;
  }
  return count;
}

// The `let` bindings with no type whose value is a generic-return call that ends the statement:
// `let x = s.parse()?;`, `let x = v.into();`. The reader sees no type in the code, so the type is named.
function countUntypedGenericLets(raw: string): number {
  const text = blankStrings(stripComments(raw));
  let count = 0;
  for (const m of text.matchAll(/\blet\s+(?:mut\s+)?\w+\s*=\s*([^;]*);/g)) {
    if (/\.(?:parse|into|try_into)\(\)(?:\?|\.expect\([^()]*\)|\.unwrap\(\))?\s*$/.test(m[1] ?? "")) count++;
  }
  return count;
}

// The turbofish of collect and parse: `.collect::<T>()`, `.parse::<T>()`. A typed `let` names the type
// on the variable instead, so the reader finds it at the binding (P2). A `_` the compiler forces stays.
function countTurbofish(raw: string): number {
  const text = blankStrings(stripComments(raw));
  return text.match(/\.(?:collect|parse)::<(?!_>)[^;]*?>\(/g)?.length ?? 0;
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

/** The parameter list that starts at `from`, from its `(` to the matching `)`. */
function paramsOf(text: string, from: number): string {
  let depth = 0;
  let i = from;
  for (; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")" && --depth === 0) break;
  }
  return text.slice(from, i + 1);
}

/** Public fns that take a `dyn` trait object as a parameter. A generic `T: Trait` is the library form. */
function countDynParams(raw: string): number {
  const text = stripTestModules(blankStrings(stripComments(raw)));
  let count = 0;
  for (const m of text.matchAll(PUB_FN)) {
    if (/\bdyn\b/.test(paramsOf(text, m.index! + m[0].length))) count++;
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
    name: "pub_const_fn",
    pattern: /^\s*pub(\([^)]*\))?\s+const\s+fn\b/,
    glob: "crates/**/*.rs",
    why: "Mark a public fn const only if it will stay const (a const context, a newtype accessor, or a trivial accessor). A new one needs a row in style-check.allow with that reason.",
  },
  {
    name: "manual_eq_ord",
    pattern: /^\s*(?:unsafe\s+)?impl\b.*\b(?:Eq|Ord|PartialOrd)\s+for\b/,
    glob: "*.rs",
    why: "A hand-written Eq, Ord or PartialOrd must keep the law: Eq reflexive, Ord total. The compiler checks a derive, not a manual impl, so each one needs a row and a reason.",
  },
  {
    name: "manual_hash",
    pattern: /^\s*(?:unsafe\s+)?impl\b.*\bHash\s+for\b/,
    glob: "*.rs",
    why: "A hand-written Hash must agree with Eq: equal values hash alike. The compiler does not check that for a manual impl, so each one needs a row and a reason.",
  },
  {
    name: "assert_no_message",
    scan: countAssertsNoMessage,
    glob: "crates/**/*.rs",
    why: "An assert names what it checks: a message that adds the value, or the reason, so a failure reads without the source (P13).",
  },
  {
    name: "assert_repeats_condition",
    scan: countAssertsRepeatingCondition,
    glob: "crates/**/*.rs",
    why: "An assert message says why, not what: a message that only repeats the condition adds nothing (P14).",
  },
  {
    name: "long_chain",
    scan: countLongChains,
    glob: "crates/**/*.rs",
    why: "A statement with a chain of five or more calls is hard to read in one pass: name the middle step (P15).",
  },
  {
    name: "untyped_generic_let",
    scan: countUntypedGenericLets,
    glob: "crates/**/*.rs",
    why: "A let that takes its type from parse, into or try_into names the type (P4). The reader sees no type otherwise.",
  },
  {
    name: "turbofish_collect_parse",
    scan: countTurbofish,
    glob: "crates/**/*.rs",
    why: "Name the type on the variable, not in a turbofish, for collect and parse (P2). A `_` that the compiler forces is allowed.",
  },
  {
    name: "anyhow_pub",
    scan: countAnyhowPub,
    skip: /(^|\/)(main\.rs|bin\/)|^(?!crates\/[^/]+\/src\/)/,
    glob: "crates/**/*.rs",
    why: "A public signature returns a typed error, not anyhow. A binary, a CLI and a private helper may keep anyhow.",
  },
  {
    name: "dyn_param",
    scan: countDynParams,
    skip: /(^|\/)(main\.rs|bin\/)|^(?!crates\/[^/]+\/src\/)/,
    glob: "crates/**/*.rs",
    why: "A library fn takes a generic (T: Trait or impl Trait), not a dyn Trait parameter. A counted row is a trait object that stays, with its reason.",
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
