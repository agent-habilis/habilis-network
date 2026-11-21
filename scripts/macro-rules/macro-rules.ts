#!/usr/bin/env bun
// `macro_rules!` and proc macros are refused. Every one fails the check.
// `macro-rules.test.ts` plants one file of each kind.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const MACRO_RULES = /\bmacro_rules\s*!/g;
const ATTRIBUTE_START = /#\s*!?\s*\[/g;
// A proc macro attribute, alone or nested in a `cfg_attr`. A path into the crate (`proc_macro::`) is no attribute.
const PROC_MACRO = /\bproc_macro(?:_attribute|_derive)?\b(?!\s*::)/;

// The text with each comment, string and char literal blanked, so that a quoted macro does not count.
function codeOnly(text: string): string {
  const out = text.split("");
  const blank = (from: number, to: number) => {
    for (let i = from; i < to; i++) if (out[i] !== "\n") out[i] = " ";
  };
  let i = 0;
  while (i < text.length) {
    const rest = text.slice(i);
    let end = i + 1;
    if (rest.startsWith("//")) {
      const newline = text.indexOf("\n", i);
      end = newline < 0 ? text.length : newline;
    } else if (rest.startsWith("/*")) {
      let depth = 0;
      for (end = i; end < text.length; end++) {
        if (text.startsWith("/*", end)) depth++, end++;
        else if (text.startsWith("*/", end) && --depth === 0) {
          end += 2;
          break;
        }
      }
    } else if (/^b?r#*"/.test(rest) && !/\w/.test(text[i - 1] ?? "")) {
      const open = rest.match(/^b?r(#*)"/)!;
      const hashes = open[1] ?? "";
      const close = text.indexOf(`"${hashes}`, i + open[0].length);
      end = close < 0 ? text.length : close + 1 + hashes.length;
    } else if (text[i] === '"') {
      for (end = i + 1; end < text.length && text[end] !== '"'; end++) if (text[end] === "\\") end++;
      end++;
    } else if (/^'(?:\\.[^']*|[^\\'])'/.test(rest)) {
      end = i + rest.match(/^'(?:\\.[^']*|[^\\'])'/)![0].length;
    } else {
      i++;
      continue;
    }
    blank(i, end);
    i = end;
  }
  return out.join("");
}

// The text of the attribute that opens at `from`, to its matching `]`.
function attributeAt(code: string, from: number): string {
  let depth = 0;
  for (let i = from; i < code.length; i++) {
    if (code[i] === "[") depth++;
    else if (code[i] === "]" && --depth === 0) return code.slice(from, i + 1);
  }
  return code.slice(from);
}
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
  const code = codeOnly(readFileSync(path.join(ROOT, file), "utf8"));
  let count = code.match(MACRO_RULES)?.length ?? 0;
  for (const start of code.matchAll(ATTRIBUTE_START)) {
    const open = start.index! + start[0].length - 1;
    if (PROC_MACRO.test(attributeAt(code, open))) count++;
  }
  return count;
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
