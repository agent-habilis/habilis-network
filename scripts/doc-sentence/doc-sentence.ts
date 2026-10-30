#!/usr/bin/env bun
// Doc sentence case (D5). A doc paragraph starts each sentence with a capital letter, a digit, or
// a code span. `doc-sentence.test.ts` plants one paragraph of each kind.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const DOC_LINE = /^\s*\/\/[\/!](?: (.*))?$/;
const ABBREVIATION = /(?:^|[\s(])(?:e\.g|i\.e|etc|vs|approx|a\.k\.a)$/i;
// Brand, crate and product names that are written in lowercase, so a sentence may start with them.
const BRANDS = new Set(["iroh", "noq", "str0m", "mDNS", "macOS", "postcard", "tracing", "automerge", "v1"]);

// The doc paragraphs of a file, as [first line number, text]. A fenced code block is not prose.
export function paragraphs(src: string): [number, string][] {
  const out: [number, string][] = [];
  let current: string[] = [];
  let start = 0;
  let fenced = false;
  const flush = () => {
    if (current.length) out.push([start, current.join(" ")]);
    current = [];
  };
  src.split("\n").forEach((line, index) => {
    const match = DOC_LINE.exec(line);
    if (!match) return flush();
    const text = match[1] ?? "";
    if (text.trimStart().startsWith("```")) {
      fenced = !fenced;
      return flush();
    }
    if (fenced || text.trim() === "") return flush();
    if (current.length === 0) start = index + 1;
    current.push(text.trim());
  });
  flush();
  return out;
}

// Each sentence start that is a lowercase letter, with its word. Code spans and markdown links are
// blanked first, so `foo_bar` and [`Name`] never count as prose.
// Each entry is the word and the text before it, joined by a NUL byte.
export function lowercaseStarts(text: string): string[] {
  const prose = text
    .replace(/`[^`]*`/g, "CODE")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1");
  const starts: string[] = [];
  // An ellipsis (`...`) continues a sentence, so only a single end mark starts one.
  const pattern = /(?:^|(?<!\.)[.!?]\s+)([A-Za-z]\w*)/g;
  for (const match of prose.matchAll(pattern)) {
    const before = prose.slice(0, match.index ?? 0);
    if (ABBREVIATION.test(before)) continue;
    const word = match[1] ?? "";
    if (prose.startsWith(`${word}.`, match.index ?? 0) && word.length === 1) continue;
    if (/^[a-z]/.test(word) && !BRANDS.has(word)) starts.push(`${word}\u0000${before.slice(-40)}${word}`);
  }
  return starts;
}

export function scan(src: string): [number, string][] {
  return paragraphs(src).flatMap(([line, text]) =>
    lowercaseStarts(text).map((hit): [number, string] => [line, hit.split("\u0000")[0] ?? ""]),
  );
}

async function main(): Promise<number> {
  const proc = spawnSync("git", ["ls-files", "-z", "-co", "--exclude-standard", "crates"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  const files = (proc.stdout ?? "").split("\0").filter((file) => /\.rs$/.test(file));
  let total = 0;
  for (const file of files) {
    const src = readFileSync(path.join(ROOT, file), "utf8");
    for (const [line, word] of scan(src)) {
      console.log(`doc-sentence: ${file}:${line}: sentence starts with lowercase "${word}". Capitalize it (D5).`);
      total++;
    }
  }
  return total > 0 ? 1 : 0;
}

if (import.meta.main) process.exit(await main());
