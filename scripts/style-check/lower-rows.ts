#!/usr/bin/env bun
// Lower the rows of scripts/style-check/style-check.allow to the counts that the check prints.
// A row whose count the check lowers is set to the new count, and a row that reaches zero is removed.
// It never raises a count and never adds a row: a file that has more hits than its row stays an error
// for the author to fix by hand. Run it after a rename or a move, then commit the allow file.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const ALLOW = process.env.STYLE_CHECK_ALLOW || "scripts/style-check/style-check.allow";

export function lowerRows(allow: string, output: string): { text: string; raised: string[] } {
  const found = new Map<string, number>();
  const raised: string[] = [];
  for (const m of output.matchAll(/\[(\w+)\] (\S+): (\d+) matching line\(s\), (\d+) allowed/g)) {
    const [, rule, file, have, allowed] = m;
    if (Number(have) > Number(allowed)) raised.push(`${rule} ${file}`);
    else found.set(`${rule}|${file}`, Number(have));
  }
  const kept: string[] = [];
  for (const line of allow.split("\n")) {
    const [rule, file, , ...reason] = line.split("|");
    const key = `${rule}|${file}`;
    if (reason.length > 0 && found.has(key)) {
      const count = found.get(key)!;
      if (count === 0) continue;
      kept.push(`${rule}|${file}|${count}|${reason.join("|")}`);
    } else kept.push(line);
  }
  // Two rows for one rule and file come from a merge: keep the lower count.
  const lowest = new Map<string, number>();
  for (const line of kept) {
    const [rule, file, count, ...reason] = line.split("|");
    if (reason.length > 0) lowest.set(`${rule}|${file}`, Math.min(Number(count), lowest.get(`${rule}|${file}`) ?? Infinity));
  }
  const seen = new Set<string>();
  const unique = kept.flatMap((line) => {
    const [rule, file, , ...reason] = line.split("|");
    if (reason.length === 0) return [line];
    const key = `${rule}|${file}`;
    if (seen.has(key)) return [];
    seen.add(key);
    return [`${key}|${lowest.get(key)}|${reason.join("|")}`];
  });
  return { text: unique.join("\n"), raised };
}

if (import.meta.main) {
  const run = spawnSync(process.execPath, ["scripts/style-check/style-check.ts"], { encoding: "utf8" });
  const { text, raised } = lowerRows(readFileSync(ALLOW, "utf8"), `${run.stdout}${run.stderr}`);
  writeFileSync(ALLOW, text);
  if (raised.length > 0) {
    console.error(`lower-rows: these files have more hits than their row, fix them by hand:\n${raised.join("\n")}`);
    process.exit(2);
  }
  console.log("lower-rows: rows lowered");
}
