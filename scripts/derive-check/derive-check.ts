#!/usr/bin/env bun
// Two derive rules the compiler and clippy do not check. A `pub struct` whose fields are all `pub`
// must implement Debug (R12). An error type whose fields are all Copy-able must implement Copy (R13).
// `derive-check.test.ts` plants one case of each kind.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export type Violation = { file: string; line: number; name: string; rule: "R12" | "R13" };

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const COPY_FIELD = /^(bool|u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|f32|f64|char|Duration|\(\))$/;

// The derive list above a declaration. An attribute may run over several lines, so each block is
// read from its `#[` line down to its closing `]`.
function derivesAbove(lines: string[], index: number): Set<string> {
  const derives = new Set<string>();
  let i = index - 1;
  while (i >= 0 && /\]\s*$/.test(lines[i]!)) {
    let start = i;
    while (start >= 0 && !/^\s*#\[/.test(lines[start]!)) start--;
    if (start < 0) break;
    const attr = lines.slice(start, i + 1).join("\n");
    const d = attr.match(/derive\(([\s\S]*?)\)\]/);
    if (d) for (const name of d[1]!.split(",")) derives.add(name.trim());
    i = start - 1;
  }
  return derives;
}

function bodyOf(lines: string[], index: number): string[] {
  const indent = lines[index]!.match(/^\s*/)![0];
  const body: string[] = [];
  for (let i = index + 1; i < lines.length; i++) {
    if (lines[i]!.startsWith(`${indent}}`) && lines[i]!.match(/^\s*/)![0].length === indent.length) break;
    body.push(lines[i]!);
  }
  return body;
}

export function findViolations(files: { path: string; text: string }[]): Violation[] {
  const manual = new Map<string, Set<string>>();
  for (const { text } of files) {
    for (const m of text.matchAll(/impl(?:<[^>]*>)? (?:[\w:]+::)?(Debug|Copy)(?:<[^>]*>)? for (\w+)/g)) {
      const set = manual.get(m[2]!) ?? new Set<string>();
      set.add(m[1]!);
      manual.set(m[2]!, set);
    }
  }
  const out: Violation[] = [];
  for (const { path: file, text } of files) {
    const lines = text.split("\n");
    lines.forEach((line, index) => {
      const decl = line.match(/^(\s*)pub (struct|enum) (\w+)/);
      if (!decl) return;
      const name = decl[3]!;
      const derives = derivesAbove(lines, index);
      const has = (trait: string) => derives.has(trait) || (manual.get(name)?.has(trait) ?? false);
      const body = bodyOf(lines, index);
      if (decl[2] === "struct" && /\{\s*$/.test(line)) {
        const fields = body.filter((l) => /^\s*\w+:\s/.test(l) || /^\s*pub\s/.test(l));
        const allPub = fields.length > 0 && fields.every((l) => /^\s*pub(\([^)]*\))? /.test(l));
        if (allPub && !has("Debug")) out.push({ file, line: index + 1, name, rule: "R12" });
      }
      if (/^Error$|Error$/.test(name) && !has("Copy")) {
        const fieldTypes = body.map((l) => l.trim().replace(/,$/, "")).filter((l) => l && !l.startsWith("//") && !l.startsWith("#"));
        // A unit variant (`Gone`) carries no value, so it is Copy-able like `()`.
        const payloads = fieldTypes.map((l) => (l.includes(":") ? l.split(":").slice(1).join(":").trim() : /^\w+$/.test(l) ? "()" : l.replace(/^\w+\((.*)\)$/, "$1").trim()));
        if (payloads.length > 0 && payloads.every((t) => COPY_FIELD.test(t))) out.push({ file, line: index + 1, name, rule: "R13" });
      }
    });
  }
  return out;
}

if (import.meta.main) {
  const listed = spawnSync("git", ["ls-files", "crates"], { cwd: ROOT, encoding: "utf8" }).stdout.split("\n").filter((f) => f.endsWith(".rs"));
  const files = listed.map((p) => ({ path: p, text: readFileSync(path.join(ROOT, p), "utf8") }));
  const violations = findViolations(files);
  for (const v of violations) console.log(`derive-check: [${v.rule}] ${v.file}:${v.line} ${v.name} is missing ${v.rule === "R12" ? "Debug" : "Copy"}`);
  console.log(`derive-check: ${violations.length} violation(s)`);
  process.exit(violations.length === 0 ? 0 : 1);
}
