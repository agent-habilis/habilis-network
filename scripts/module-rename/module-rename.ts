#!/usr/bin/env bun
// Renames one module of a crate and rewrites every path that names it.
//
//   bun scripts/module-rename/module-rename.ts --crate habilis-network-protocol --from mesh --to meshes
//
// Run it from the repo root on a clean tree. It moves `src/<from>/` to `src/<to>/`, rewrites the
// paths in the tracked text files, and prints what it changed. The rewrite is pure text: a
// compile after it is the check.

import { spawnSync } from "node:child_process";
import { renameSync } from "node:fs";

export type RenameOptions = { crate: string; from: string; to: string };

// Rewrites the text of one tracked file. `file` is repo-relative: the rules depend on where it lives.
export function renameInText(text: string, file: string, o: RenameOptions): string {
  const ident = o.crate.replaceAll("-", "_");
  const srcPrefix = `crates/${o.crate}/src/`;
  const inCrate = file.startsWith(srcPrefix);
  const inFromDir = file.startsWith(`${srcPrefix}${o.from}/`);
  const { from, to } = o;
  let out = text;
  // Other crates name the module through the crate's re-export or its own name.
  out = out.replace(new RegExp(`(?<![A-Za-z0-9_])(${ident}|protocol)::${from}(?![A-Za-z0-9_])`, "g"), `$1::${to}`);
  if (inCrate) {
    // Inside the module's own directory, `mesh::`, `super::` and `mod mesh;` name its children, so they stay.
    out = out.replace(new RegExp(`(?<![A-Za-z0-9_])crate::${from}(?![A-Za-z0-9_])`, "g"), `crate::${to}`);
    if (!inFromDir) {
      out = out.replace(new RegExp(`(?<![A-Za-z0-9_])(super|self)::${from}(?![A-Za-z0-9_])`, "g"), `$1::${to}`);
      out = out.replace(new RegExp(`((?:pub(?:\\(crate\\))? )?mod )${from};`, "g"), `$1${to};`);
      out = out.replace(new RegExp(`(?<![\\w:])${from}::`, "g"), `${to}::`);
      // `use crate::{a, mesh}`: the module named inside a use group.
      out = out.replace(/use (crate|super|self)::\{([^}]*)\}/g, (group, root, items) =>
        group.replace(items, items.replace(new RegExp(`(?<![\\w:])${from}(?=[,\\s}]|$)`, "g"), to)),
      );
    }
    // The module's own `mod.rs` carried a `module_inception` expect for its child; the rename ends that.
    if (inFromDir && file.endsWith("/mod.rs")) {
      out = out.replace(/#\[expect\(\n\s*clippy::module_inception,\n\s*reason = "[^"]*"\n\s*\)\]\n/, "");
    }
  }
  // A use group of the crate's own items, in any file: `pub use habilis_network_protocol::{identity, mesh}`.
  out = out.replace(new RegExp(`(use (?:[\\w]+::)*?(?:protocol|${ident}|crate|super|self)::\\{)([^}]*)\\}`, "g"), (_m, head: string, items: string) =>
    `${head}${items.replace(new RegExp(`(?<![\\w:])${from}(?=[,\\s}]|$)`, "g"), to)}}`,
  );
  // A file that imports the module by name (`use ...::meshes;`) names it bare in its body: `mesh::X`.
  if (new RegExp(`^\\s*(pub(?:\\(crate\\))? )?use [^;]*(?<![\\w])${to}(?![\\w])[^;]*;`, "m").test(out)) {
    out = out.replace(new RegExp(`(?<![\\w:])${from}::`, "g"), `${to}::`);
  }
  // Paths written as files, in docs and the glossary.
  out = out.replace(new RegExp(`(crates/${o.crate}/src/)${from}(?=/|\\b)`, "g"), `$1${to}`);
  return out;
}

async function main(argv: string[]): Promise<void> {
  const get = (flag: string): string => {
    const i = argv.indexOf(flag);
    if (i < 0 || !argv[i + 1]) throw new Error(`missing ${flag}`);
    return argv[i + 1]!;
  };
  const o: RenameOptions = { crate: get("--crate"), from: get("--from"), to: get("--to") };
  const files = spawnSync("git", ["ls-files"], { encoding: "utf8" }).stdout.split("\n").filter(Boolean);
  const targets = files.filter((f) => /\.(rs|md)$/.test(f) && f !== "CHANGELOG.md");
  let changed = 0;
  for (const file of targets) {
    const before = await Bun.file(file).text();
    const after = renameInText(before, file, o);
    if (after !== before) {
      await Bun.write(file, after);
      changed++;
    }
  }
  renameSync(`crates/${o.crate}/src/${o.from}`, `crates/${o.crate}/src/${o.to}`);
  console.log(`renamed ${o.from} to ${o.to}: rewrote ${changed} files`);
}

if (import.meta.main) {
  await main(process.argv.slice(2));
}
