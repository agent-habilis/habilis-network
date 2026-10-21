#!/usr/bin/env bun
/**
 * Ratchet for the lints that still have old findings.
 *
 * The lints are missing_docs, clippy::exhaustive_enums and clippy::exhaustive_structs. A count
 * above the baseline fails, because it is a new finding. A count below the baseline fails too, so
 * the baseline only tightens.
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const LINTS = [
  "missing_docs",
  "clippy::exhaustive_enums",
  "clippy::exhaustive_structs",
] as const;

// Struct fields and variants may stay without docs. The Google Rust Style Guide says that a
// variant with a clear name needs no doc, and that a doc which only repeats a field name is worse
// than none. Every other missing_docs finding counts.
export const UNDOCUMENTED_OK = [
  "missing documentation for a struct field",
  "missing documentation for a variant",
];

const CLIPPY = [
  "cargo",
  "clippy",
  "--workspace",
  "--all-targets",
  "--all-features",
  "--keep-going",
  "--message-format=json",
  "--",
  "--cap-lints",
  "warn",
  "-W",
  "missing_docs",
  "-W",
  "clippy::exhaustive_enums",
  "-W",
  "clippy::exhaustive_structs",
];

// Only library source counts. Tests, examples and benches are not in crates/<crate>/src/.
const SRC = /^crates\/([^/]+)\/src\//;

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const DEFAULT_BASELINE = path.join(ROOT, "scripts", "lint-ratchet", "lint-ratchet.baseline");

const HEADER = `# Count of findings per lint and crate, under crates/<crate>/src/.
# Written by \`bun scripts/lint-ratchet/lint-ratchet.ts --update\`. Lower a count when a finding
# goes away. A count above this file is a new finding and fails CI.
`;

/** Counts keyed by "lint|crate". */
export type Counts = Map<string, number>;

const key = (lint: string, crate: string) => `${lint}|${crate}`;

const split = (k: string): [string, string] => {
  const at = k.indexOf("|");
  return [k.slice(0, at), k.slice(at + 1)];
};

const byLintThenCrate = (a: string, b: string) => {
  const [aLint, aCrate] = split(a);
  const [bLint, bCrate] = split(b);
  if (aLint !== bLint) return aLint < bLint ? -1 : 1;
  if (aCrate !== bCrate) return aCrate < bCrate ? -1 : 1;
  return 0;
};

/** Count the findings in clippy JSON lines, one per (lint, file, line, column). */
export function findings(lines: string[]): Counts {
  const seen = new Set<string>();
  const counts: Counts = new Map();
  for (const line of lines) {
    if (!line.trim()) continue;
    const obj = JSON.parse(line);
    if (obj.reason !== "compiler-message") continue;
    const message = obj.message;
    const code: string | undefined = message.code?.code;
    if (!code || !(LINTS as readonly string[]).includes(code)) continue;
    const text: string = message.message ?? "";
    if (code === "missing_docs" && UNDOCUMENTED_OK.some((prefix) => text.startsWith(prefix))) {
      continue;
    }
    const span = (message.spans ?? []).find((s: { is_primary?: boolean }) => s.is_primary);
    if (!span) continue;
    const match = SRC.exec(String(span.file_name).replaceAll("\\", "/"));
    if (!match) continue;
    // The lib target and the test target both report a source file. Count it once.
    const dedupe = [code, span.file_name, span.line_start, span.column_start].join("\u0000");
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    const k = key(code, match[1]);
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return counts;
}

/** Run clippy on the workspace and return its JSON lines. Exit if it did not finish. */
export function clippyLines(): string[] {
  const proc = spawnSync(CLIPPY[0], CLIPPY.slice(1), {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 1 << 30,
  });
  const lines = (proc.stdout ?? "").split("\n").filter((line) => line.length > 0);
  const finished = lines
    .filter((line) => line.includes('"build-finished"'))
    .map((line) => JSON.parse(line));
  if (finished.length === 0 || !finished[finished.length - 1].success) {
    process.stderr.write((proc.stderr ?? "").slice(-4000));
    console.log("lint-ratchet: clippy did not finish, so the counts are not known");
    process.exit(2);
  }
  return lines;
}

export function readBaseline(file: string): Counts {
  const counts: Counts = new Map();
  if (!existsSync(file)) return counts;
  for (const raw of readFileSync(file, "utf8").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [lint, crate, count] = line.split("|");
    counts.set(key(lint, crate), Number(count));
  }
  return counts;
}

export function writeBaseline(file: string, counts: Counts): void {
  const rows = [...counts.keys()]
    .filter((k) => (counts.get(k) ?? 0) > 0)
    .sort(byLintThenCrate)
    .map((k) => `${k}|${counts.get(k)}\n`);
  writeFileSync(file, HEADER + rows.join(""), "utf8");
}

export function compare(current: Counts, baseline: Counts): string[] {
  const problems: string[] = [];
  const keys = new Set([...current.keys(), ...baseline.keys()]);
  for (const k of [...keys].sort(byLintThenCrate)) {
    const [lint, crate] = split(k);
    const now = current.get(k) ?? 0;
    const then = baseline.get(k) ?? 0;
    if (now > then) {
      problems.push(
        `lint-ratchet: [${lint}] ${crate}: ${now} finding(s), baseline ${then}. ` +
          "New finding(s): fix them, or write the item so the lint does not fire.",
      );
    } else if (now < then) {
      problems.push(
        `lint-ratchet: [${lint}] ${crate}: ${now} finding(s), baseline ${then}. ` +
          "Lower the baseline with: bun scripts/lint-ratchet/lint-ratchet.ts --update",
      );
    }
  }
  return problems;
}

export function totals(counts: Counts): string {
  const parts = LINTS.map((lint) => {
    let sum = 0;
    for (const [k, n] of counts) if (split(k)[0] === lint) sum += n;
    return `${lint} ${sum}`;
  });
  return `lint-ratchet: totals: ${parts.join(", ")}`;
}

function main(argv: string[]): number {
  let update = false;
  let fromJson: string | undefined;
  let baseline = DEFAULT_BASELINE;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--update") update = true;
    else if (arg === "--from-json") fromJson = argv[++i];
    else if (arg === "--baseline") baseline = argv[++i];
    else {
      console.error(`lint-ratchet: unknown argument ${arg}`);
      return 2;
    }
  }

  const lines = fromJson
    ? readFileSync(fromJson, "utf8").split("\n")
    : clippyLines();

  const current = findings(lines);
  console.log(totals(current));

  if (update) {
    writeBaseline(baseline, current);
    console.log(`lint-ratchet: baseline written to ${baseline}`);
    return 0;
  }

  const problems = compare(current, readBaseline(baseline));
  for (const problem of problems) console.log(problem);
  return problems.length > 0 ? 1 : 0;
}

if (import.meta.main) {
  process.exit(main(process.argv.slice(2)));
}
