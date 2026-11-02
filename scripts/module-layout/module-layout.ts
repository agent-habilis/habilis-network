#!/usr/bin/env bun
// Module layout (issue #29, O9). A leaf source file is named after its primary public type: the
// file `frame_cache.rs` holds `FrameCache`. A leaf file with public types, none of which is named
// after the file, is a hit. A leaf with no public type is fine. `module-layout.test.ts` plants one
// file of each kind.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const SCOPE = /\.rs$/;
const SKIP = /\/build\.rs$/;
const ROOT_FILE = /(^|\/)(mod|lib|main)\.rs$/;
const CHILD_MOD = /^\s*(pub(\([a-z]+\))? )?mod \w+;/m;
const PUB_TYPE = /^pub(?:\([a-z]+\))? (?:struct|enum|trait|union|type) (\w+)/gm;

// The Rust files git knows, minus the tests, benches, examples and build scripts.
function listFiles(): string[] {
  const proc = spawnSync("git", ["ls-files", "-z", "-co", "--exclude-standard"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  return (proc.stdout ?? "").split("\0").filter((file) => SCOPE.test(file) && !SKIP.test(file));
}

// `frame_cache` for `FrameCache`: the snake_case of a type name, so `HTTPClient` names `http_client`.
// A digit before a capital may split the word (`sha256_hash`) or not (`P2PSession` names `p2p_session`).
function snakes(camel: string): string[] {
  const split = (digitsSplit: boolean) =>
    camel
      .replace(digitsSplit ? /([a-z0-9])([A-Z])/g : /([a-z])([A-Z])/g, "$1_$2")
      .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
      .toLowerCase();
  return [split(true), split(false)];
}

// The public types of a leaf file, read before its `#[cfg(test)]` module. A type whose snake_case
// name is the file name is a match, so the file is fine.
function leafHit(file: string, src: string): string | undefined {
  const base = path.basename(file, ".rs");
  if (ROOT_FILE.test(file) || CHILD_MOD.test(src)) return undefined;
  const body = src.split(/^#\[cfg\(test\)\]/m)[0] ?? "";
  const types = [...body.matchAll(PUB_TYPE)].map((m) => m[1] ?? "");
  if (types.length === 0) return undefined;
  if (types.some((name) => snakes(name).includes(base))) return undefined;
  return `leaf file named for none of its public types (${types.join(", ")}). Rename it`;
}

// A mod.rs or lib.rs holds module declarations and re-exports. Up to 20 lines of definitions are
// small core glue (O13). More is a hit (O11): the items move into leaf files.
const DEFINITION = /^(pub(\([^)]*\))? )?(unsafe )?(struct|enum|trait|union|fn|impl|const|static|type)\b/m;
const GLUE_LINES = 20;
function nonLeafHit(file: string, src: string): string | undefined {
  if (!/(^|\/)(mod|lib)\.rs$/.test(file)) return undefined;
  const body = src.split(/^#\[cfg\(test\)\]/m)[0] ?? "";
  if (!DEFINITION.test(body)) return undefined;
  const lines = body.split("\n").filter((line) => line.trim() !== "" && !/^\s*(\/\/|(pub(\([^)]*\))? )?(mod|use) )/.test(line));
  return lines.length > GLUE_LINES ? "mod.rs or lib.rs defines items. Move them into a leaf file" : undefined;
}

async function main(): Promise<number> {
  const problems: string[] = [];
  for (const file of listFiles()) {
    const src = readFileSync(path.join(ROOT, file), "utf8");
    const hit = leafHit(file, src) ?? nonLeafHit(file, src);
    if (hit !== undefined) problems.push(`module-layout: ${file}: ${hit}.`);
  }
  for (const problem of problems.sort()) console.log(problem);
  return problems.length > 0 ? 1 : 0;
}

process.exit(await main());
