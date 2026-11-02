#!/usr/bin/env bun
// Shell, Python and JavaScript scripts are refused, so every script is TypeScript run with Bun.
// `script-language.test.ts` plants one file of each kind.

import { spawnSync } from "node:child_process";
import { closeSync, existsSync, openSync, readFileSync, readSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const EXTENSION = /\.(sh|bash|zsh|ksh|dash|fish|py|js|mjs|cjs)$/;
const INTERPRETER = /^(sh|bash|zsh|ksh|dash|fish|python[0-9.]*|node|nodejs|deno)$/;

// The interpreter a shebang line names: `#!/usr/bin/env -S bash -e` and `#!/usr/local/bin/bash`
// both give `bash`. Words after `env` that are flags or NAME=value belong to `env`, not to it.
function interpreterOf(firstLine: string): string | undefined {
  if (!firstLine.startsWith("#!")) return undefined;
  const words = firstLine.slice(2).trim().split(/\s+/);
  let command = path.basename(words[0] ?? "");
  let rest = words.slice(1);
  if (command === "env") {
    rest = rest.filter((word) => !word.startsWith("-") && !word.includes("="));
    command = path.basename(rest[0] ?? "");
  }
  return command;
}

// The files git knows: tracked, or new and not ignored. -z keeps a file name with a space whole.
function listFiles(): string[] {
  const proc = spawnSync("git", ["ls-files", "-z", "-co", "--exclude-standard"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  return (proc.stdout ?? "").split("\0").filter((file) => file.length > 0);
}

// The first bytes of a file are enough for a shebang line, and a binary file is never read whole.
function readHead(file: string): string {
  const fd = openSync(file, "r");
  try {
    const buffer = Buffer.alloc(256);
    const length = readSync(fd, buffer, 0, buffer.length, 0);
    return buffer.toString("utf8", 0, length);
  } finally {
    closeSync(fd);
  }
}

// The rule each file breaks, if any. Any file is read for its shebang, whatever its extension.
function violationOf(file: string): string | undefined {
  if (EXTENSION.test(file)) return "extension";
  if (!existsSync(path.join(ROOT, file))) return undefined;
  const firstLine = readHead(path.join(ROOT, file)).split("\n")[0] ?? "";
  return INTERPRETER.test(interpreterOf(firstLine) ?? "") ? "shebang" : undefined;
}

function main(): number {
  const problems: string[] = [];
  for (const file of listFiles()) {
    const rule = violationOf(file);
    if (rule) {
      problems.push(`script-language: [${rule}] ${file}: a shell, Python or JavaScript script. Write it in TypeScript and run it with Bun.`);
    }
  }
  for (const problem of problems.sort()) console.log(problem);
  return problems.length > 0 ? 1 : 0;
}

process.exit(main());
