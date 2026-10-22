#!/usr/bin/env bun
// Scripts are written in TypeScript and run with Bun (AGENTS.md, "Scripts"). This check fails on a
// shell or Python script that the repository holds: a file with a .sh, .bash or .py extension, or a
// file with no extension whose first line is a shell or Python shebang.
// `script-language.allow` names a file that may stay, with a reason. A row that matches nothing is
// stale and fails too. `script-language.test.ts` plants one script of each kind.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const allowFile = process.env.SCRIPT_LANGUAGE_ALLOW || "scripts/script-language/script-language.allow";

const EXTENSION = /\.(sh|bash|py)$/;
const SHEBANG = /^#!\s*\/(usr\/bin\/env\s+)?(usr\/)?bin\/(env\s+)?(sh|bash|zsh|python[0-9.]*)\b/;

// The files git knows: tracked, or new and not ignored. -z keeps a file name with a space whole.
function listFiles(): string[] {
  const proc = spawnSync("git", ["ls-files", "-z", "-co", "--exclude-standard"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  return (proc.stdout ?? "").split("\0").filter((file) => file.length > 0);
}

// The rule each file breaks, if any. A file with no extension is read for its shebang.
function violationOf(file: string): string | undefined {
  if (EXTENSION.test(file)) return "extension";
  if (path.extname(file) !== "" || !existsSync(path.join(ROOT, file))) return undefined;
  const firstLine = readFileSync(path.join(ROOT, file), "utf8").split("\n")[0] ?? "";
  return SHEBANG.test(firstLine) ? "shebang" : undefined;
}

function readAllow(): { allowed: Map<string, string>; problems: string[] } {
  const allowed = new Map<string, string>();
  const problems: string[] = [];
  const file = path.join(ROOT, allowFile);
  if (!existsSync(file)) return { allowed, problems };
  for (const line of readFileSync(file, "utf8").split("\n")) {
    if (/^\s*(#|$)/.test(line)) continue;
    const [rule, target] = line.split("|");
    const key = `${rule}|${target}`;
    if (allowed.has(key)) {
      problems.push(`script-language: ${allowFile} has two rows for [${rule}] ${target}. Merge them.`);
    }
    allowed.set(key, line);
  }
  return { allowed, problems };
}

function main(): number {
  const { allowed, problems } = readAllow();
  const found = new Set<string>();
  for (const file of listFiles()) {
    const rule = violationOf(file);
    if (!rule) continue;
    const key = `${rule}|${file}`;
    found.add(key);
    if (!allowed.has(key)) {
      problems.push(
        `script-language: [${rule}] ${file}: a shell or Python script. Write it in TypeScript and run it with Bun, or add a row to ${allowFile} with a reason.`,
      );
    }
  }
  for (const key of [...allowed.keys()].sort()) {
    if (!found.has(key)) {
      const [rule, file] = key.split("|");
      problems.push(`script-language: [${rule}] ${file}: stale row. Nothing matches it. Remove it from ${allowFile}.`);
    }
  }
  for (const problem of problems) console.log(problem);
  return problems.length > 0 ? 1 : 0;
}

process.exit(main());
