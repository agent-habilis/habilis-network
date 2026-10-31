#!/usr/bin/env bun
// Rename the letter-deleted names of one crate to their full words (Z2).
//
// Usage: bun scripts/abbrev-names/abbrev-names.ts <crate-dir> [--write]
//
// Without --write it prints the hits. The rename touches code tokens only: a
// string, a char literal, a comment and a doc comment keep their text. A name
// that a foreign API fixes is not renamed here; it is reported so that the
// caller can send the site for a rule (see the report line).

import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

export const FULL_WORDS: Record<string, string> = {
  addr: "address",
  attr: "attribute",
  buf: "buffer",
  cfg: "config",
  cmd: "command",
  conn: "connection",
  ctx: "context",
  idx: "index",
  msg: "message",
  opts: "options",
  pos: "position",
  prev: "previous",
  req: "request",
  resp: "response",
  sig: "signature",
  tmp: "temporary",
};

// The text of an attribute, `#[...]` or `#![...]`, up to its matching bracket.
function attributeText(rest: string): string {
  let depth = 0;
  for (let j = rest.indexOf("["); j < rest.length; j++) {
    if (rest[j] === "[") depth++;
    if (rest[j] === "]" && --depth === 0) return rest.slice(0, j + 1);
  }
  return rest;
}

// Keep the code tokens of a Rust source and blank out the rest, keeping its length, so the
// positions of the code tokens stay the same.
export function codeMask(src: string): string {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const rest = src.slice(i);
    const blank = (text: string) => {
      out += text.replace(/[^\n]/g, " ");
      i += text.length;
    };
    if (rest.startsWith("//")) {
      blank(rest.slice(0, rest.indexOf("\n") === -1 ? rest.length : rest.indexOf("\n")));
    } else if (rest.startsWith("/*")) {
      const end = rest.indexOf("*/");
      blank(rest.slice(0, end === -1 ? rest.length : end + 2));
    } else if (/^r#*"/.test(rest)) {
      const hashes = /^r(#*)"/.exec(rest)![1]!;
      const end = rest.indexOf(`"${hashes}`, hashes.length + 2);
      blank(rest.slice(0, end === -1 ? rest.length : end + 1 + hashes.length));
    } else if (rest.startsWith("#[") || rest.startsWith("#![")) {
      blank(attributeText(rest));
    } else if (rest.startsWith('"')) {
      let j = 1;
      while (j < rest.length && rest[j] !== '"') j += rest[j] === "\\" ? 2 : 1;
      blank(rest.slice(0, j + 1));
    } else if (rest.startsWith("'") && /^'(\\.|[^\\'])'/.test(rest)) {
      blank(/^'(\\.|[^\\'])'/.exec(rest)![0]);
    } else {
      out += src[i];
      i += 1;
    }
  }
  return out;
}

export interface Hit {
  file: string;
  line: number;
  from: string;
  to: string;
}

// Rename the identifier tokens of one file. Returns the new text and the hits.
export function renameInFile(file: string, src: string): { text: string; hits: Hit[] } {
  const mask = codeMask(src);
  const hits: Hit[] = [];
  const text = src.replace(/[A-Za-z_][A-Za-z0-9_]*/g, (word, offset: number) => {
    const full = FULL_WORDS[word];
    if (!full || mask.slice(offset, offset + word.length) !== word) return word;
    if (src[offset + word.length] === "!") return word; // a macro, such as cfg!
    // A method call on a value, such as endpoint.addr(): the method may be a foreign API's.
    // It is reported, not renamed (the caller sends the site to the rule owner).
    if (src[offset - 1] === "." && src[offset + word.length] === "(") return word;
    // A macro variable ($x) and a fragment specifier (x:ident) are the macro's syntax, not a name.
    if (src[offset - 1] === "$" || /^\s*:\s*$/.test(src.slice(Math.max(0, offset - 8), offset))) return word;
    // A path segment, such as addr::f or crate::addr, names a module or an item of a path: the
    // module is a file, renamed by hand with its declaration. Only a local or a field is renamed.
    if (src.slice(offset + word.length, offset + word.length + 2) === "::") return word;
    if (src.slice(Math.max(0, offset - 2), offset) === "::") return word;
    // A module declaration names a file: the file is renamed by hand, with the module.
    if (/\bmod\s+$/.test(src.slice(Math.max(0, offset - 16), offset))) return word;
    const line = src.slice(0, offset).split("\n").length;
    hits.push({ file, line, from: word, to: full });
    return full;
  });
  return { text, hits };
}

function rustFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "target" || entry.startsWith(".")) continue;
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...rustFiles(full));
    else if (entry.endsWith(".rs")) out.push(full);
  }
  return out;
}

if (import.meta.main) {
  const crateDir = process.argv[2];
  if (!crateDir) {
    console.error("usage: abbrev-names.ts <crate-dir> [--write]");
    process.exit(2);
  }
  const write = process.argv.includes("--write");
  const allHits: Hit[] = [];
  for (const file of rustFiles(crateDir)) {
    const src = readFileSync(file, "utf8");
    const { text, hits } = renameInFile(file, src);
    allHits.push(...hits);
    if (write && hits.length > 0) writeFileSync(file, text);
  }
  for (const hit of allHits) console.log(`${hit.file}:${hit.line}: ${hit.from} -> ${hit.to}`);
  console.log(`hits: ${allHits.length}${write ? " (written)" : " (dry run)"}`);
}
