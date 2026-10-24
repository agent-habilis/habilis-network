// Rewrites the hits of clippy::absolute_paths into a `use` of the parent module, so that
// `std::sync::atomic::AtomicBool` becomes `use std::sync::atomic;` and `atomic::AtomicBool`.
// Input is clippy's JSON (one message per line). The script only edits; the caller runs rustfmt.
//
// Usage: bun scripts/absolute-paths/absolute-paths.ts --root <dir> <clippy.json>...

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

export type Hit = { file: string; start: number; end: number; line: number; expected?: string | undefined };
export type Refusal = { line: number; reason: string };
export type FileResult = { text: string; refusals: Refusal[]; uses: string[]; replaced: number; suggested: number };
export type Suggestion = { file: string; start: number; end: number; text: string; expected?: string | undefined };

// `code[i]` is 1 for a byte of code, 0 for a comment or the inside of a literal.
type Bytes = Buffer;

type Attr = { norm: string };

type Segment = {
  start: number;
  end: number;
  attrs: Attr[];
  innerAttr: boolean;
  open: number; // index of the first top-level `{`, or -1
  isUse: boolean;
  useText: string; // the use tree, code bytes only
  decl: { kind: string; name: string } | null;
  modName: string | null; // `mod NAME {`
};

type Module = {
  id: number;
  parent: number;
  depth: number;
  from: number;
  to: number; // index of the closing `}`, or the file length for the root
  open: number; // index of the opening `{`, or -1 for the root
  segs: Segment[];
};

type Plan = {
  hit: { start: number; end: number; line: number };
  bare: string;
  parent: string;
  item: string;
  mod: number;
  key: string; // the cfg chain of the hit, see KEY_SEP
};

type Edit = { start: number; end: number; text: string };

// Separates the cfg attributes of one chain inside a key. A cfg attribute has spaces in it.
const KEY_SEP = "\u0001";
const DECL_KEYWORDS = new Set(["mod", "fn", "struct", "enum", "union", "type", "trait", "const", "static"]);
const DECL_SKIP = new Set(["fn", "mut", "unsafe", "async", "extern"]);

export function collectHits(jsonText: string): Hit[] {
  const seen = new Set<string>();
  const hits: Hit[] = [];
  for (const raw of jsonText.split("\n")) {
    if (raw.trim() === "") continue;
    let msg: unknown;
    try {
      msg = JSON.parse(raw);
    } catch {
      continue;
    }
    const message = (msg as { message?: { code?: { code?: string }; spans?: unknown[] } }).message;
    if (message?.code?.code !== "clippy::absolute_paths") continue;
    for (const span of (message.spans ?? []) as Array<Record<string, unknown>>) {
      if (span.is_primary !== true) continue;
      const hit: Hit = {
        file: String(span.file_name),
        start: Number(span.byte_start),
        end: Number(span.byte_end),
        line: Number(span.line_start),
        expected: highlighted(span),
      };
      const key = `${hit.file}:${hit.start}:${hit.end}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push(hit);
    }
  }
  return hits;
}

// The compiler lints whose machine-applicable suggestions this script takes: the redundant prefix of a
// path (unused_qualifications) and an import nothing uses (unused_imports). They come from the same run.
const SUGGESTED_LINTS = new Set(["unused_qualifications", "unused_imports"]);

// The text a span covers, rebuilt from the lines that clippy's JSON gives for it, by code point.
function spanText(span: Record<string, unknown>): string | undefined {
  const lines = span.text as Array<{ text: string; highlight_start: number; highlight_end: number }> | undefined;
  if (lines === undefined || lines.length === 0) return undefined;
  const cut = (s: string, from: number, to: number) => Array.from(s).slice(from, to).join("");
  if (lines.length === 1) {
    const only = lines[0]!;
    return cut(only.text, only.highlight_start - 1, only.highlight_end - 1);
  }
  const first = lines[0]!;
  const last = lines[lines.length - 1]!;
  const middle = lines.slice(1, -1).map((l) => l.text);
  return [cut(first.text, first.highlight_start - 1, Infinity), ...middle, cut(last.text, 0, last.highlight_end - 1)].join("\n");
}

export function collectSuggestions(jsonText: string): Suggestion[] {
  const seen = new Set<string>();
  const out: Suggestion[] = [];
  for (const raw of jsonText.split("\n")) {
    if (raw.trim() === "") continue;
    let msg: unknown;
    try {
      msg = JSON.parse(raw);
    } catch {
      continue;
    }
    const message = (msg as { message?: { code?: { code?: string }; children?: unknown[] } }).message;
    const code = message?.code?.code;
    if (code === undefined || !SUGGESTED_LINTS.has(code)) continue;
    for (const child of (message?.children ?? []) as Array<{ spans?: Array<Record<string, unknown>> }>) {
      for (const span of child.spans ?? []) {
        if (span.suggestion_applicability !== "MachineApplicable") continue;
        if (typeof span.suggested_replacement !== "string") continue;
        const s: Suggestion = {
          file: String(span.file_name),
          start: Number(span.byte_start),
          end: Number(span.byte_end),
          text: span.suggested_replacement,
          expected: spanText(span),
        };
        const key = `${s.file}:${s.start}:${s.end}:${s.text}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(s);
      }
    }
  }
  return out;
}

// ---- lexing: mark the bytes that are code, not comments and not literal contents ----

// The text clippy highlighted for a span, by code point, as its JSON gives it.
function highlighted(span: Record<string, unknown>): string | undefined {
  const line = (span.text as Array<{ text: string; highlight_start: number; highlight_end: number }> | undefined)?.[0];
  if (line === undefined) return undefined;
  return Array.from(line.text).slice(line.highlight_start - 1, line.highlight_end - 1).join("");
}

function isIdent(c: number | undefined): boolean {
  if (c === undefined) return false;
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f || c >= 0x80;
}

function isWs(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
}

function utf8Len(first: number): number {
  if (first < 0x80) return 1;
  if (first >= 0xf0) return 4;
  if (first >= 0xe0) return 3;
  return 2;
}

export function codeMask(b: Bytes): Uint8Array {
  const n = b.length;
  const m = new Uint8Array(n).fill(1);
  let i = 0;
  while (i < n) {
    const c = b[i]!;
    if (c === 0x2f && b[i + 1] === 0x2f) {
      let j = i;
      while (j < n && b[j] !== 0x0a) j++;
      m.fill(0, i, j);
      i = j;
      continue;
    }
    if (c === 0x2f && b[i + 1] === 0x2a) {
      let depth = 0;
      let j = i;
      while (j < n) {
        if (b[j] === 0x2f && b[j + 1] === 0x2a) {
          depth++;
          j += 2;
        } else if (b[j] === 0x2a && b[j + 1] === 0x2f) {
          depth--;
          j += 2;
          if (depth === 0) break;
        } else j++;
      }
      m.fill(0, i, j);
      i = j;
      continue;
    }
    const rawPrefix = c === 0x72 ? 1 : c === 0x62 && b[i + 1] === 0x72 ? 2 : 0;
    if (rawPrefix > 0 && !isIdent(b[i - 1])) {
      let j = i + rawPrefix;
      let hashes = 0;
      while (b[j] === 0x23) {
        hashes++;
        j++;
      }
      if (b[j] === 0x22) {
        j++;
        while (j < n) {
          if (b[j] === 0x22) {
            let k = 0;
            while (k < hashes && b[j + 1 + k] === 0x23) k++;
            if (k === hashes) {
              j += 1 + hashes;
              break;
            }
          }
          j++;
        }
        m.fill(0, i, j);
        i = j;
        continue;
      }
    }
    if (c === 0x22 || (c === 0x62 && b[i + 1] === 0x22)) {
      let j = c === 0x22 ? i + 1 : i + 2;
      while (j < n && b[j] !== 0x22) j += b[j] === 0x5c ? 2 : 1;
      j++;
      m.fill(0, i, j);
      i = j;
      continue;
    }
    if (c === 0x27) {
      if (b[i + 1] === 0x5c) {
        let j = i + 2;
        while (j < n && b[j] !== 0x27) j++;
        j++;
        m.fill(0, i, j);
        i = j;
        continue;
      }
      const len = utf8Len(b[i + 1] ?? 0);
      if (b[i + 1 + len] === 0x27) {
        m.fill(0, i, i + 2 + len);
        i += 2 + len;
        continue;
      }
    }
    i++;
  }
  return m;
}

// ---- segments: the items of one brace level ----

function skipNonCode(b: Bytes, m: Uint8Array, i: number, to: number): number {
  let k = i;
  while (k < to && (m[k] === 0 || isWs(b[k]!))) k++;
  return k;
}

function matchClose(b: Bytes, m: Uint8Array, open: number): number {
  let depth = 0;
  for (let i = open; i < b.length; i++) {
    if (m[i] === 0) continue;
    if (b[i] === 0x7b) depth++;
    if (b[i] === 0x7d) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return b.length;
}

// The first identifiers of a segment, skipping punctuation such as `(crate)`.
function headWords(b: Bytes, m: Uint8Array, from: number, to: number, limit: number): string[] {
  const out: string[] = [];
  let i = from;
  while (i < to && out.length < limit) {
    if (m[i] === 0) {
      i++;
      continue;
    }
    const c = b[i]!;
    if (c === 0x7b || c === 0x3b || c === 0x3d) break;
    if (!isIdent(c)) {
      i++;
      continue;
    }
    let j = i;
    while (j < to && m[j] === 1 && isIdent(b[j])) j++;
    out.push(Buffer.from(b.subarray(i, j)).toString("utf8"));
    i = j;
  }
  return out;
}

function lineOf(b: Bytes, idx: number): number {
  let line = 1;
  for (let i = 0; i < idx; i++) if (b[i] === 0x0a) line++;
  return line;
}

function parseSegments(b: Bytes, m: Uint8Array, from: number, to: number): Segment[] {
  const segs: Segment[] = [];
  let i = from;
  for (;;) {
    i = skipNonCode(b, m, i, to);
    if (i >= to) break;
    const start = i;
    let depth = 0;
    let open = -1;
    let end = -1;
    let j = i;
    while (j < to) {
      if (m[j] === 0) {
        j++;
        continue;
      }
      const c = b[j];
      if (c === 0x28 || c === 0x5b) depth++;
      else if (c === 0x29 || c === 0x5d) depth--;
      else if (c === 0x7b) {
        if (depth === 0 && open < 0) open = j;
        depth++;
      } else if (c === 0x7d) {
        depth--;
        const k = skipNonCode(b, m, j + 1, to);
        if (depth === 0 && !continuesItem(b, m, k, to)) {
          end = k < to && b[k] === 0x3b ? k + 1 : j + 1;
          break;
        }
      } else if (c === 0x2c && depth === 0) {
        end = j + 1;
        break;
      } else if (c === 0x3b && depth === 0) {
        end = j + 1;
        break;
      }
      j++;
    }
    if (end < 0) end = to;
    segs.push(makeSegment(b, m, start, end, open));
    i = end;
  }
  return segs;
}

function makeSegment(b: Bytes, m: Uint8Array, start: number, end: number, open: number): Segment {
  const attrs: Attr[] = [];
  let innerAttr = false;
  let i = start;
  for (;;) {
    i = skipNonCode(b, m, i, end);
    if (i >= end || b[i] !== 0x23) break;
    let j = i + 1;
    if (b[j] === 0x21) {
      innerAttr = true;
      j++;
    }
    j = skipNonCode(b, m, j, end);
    let depth = 0;
    let k = j;
    for (; k < end; k++) {
      if (m[k] === 0) continue;
      if (b[k] === 0x5b) depth++;
      if (b[k] === 0x5d) {
        depth--;
        if (depth === 0) break;
      }
    }
    const raw = Buffer.from(b.subarray(i, k + 1)).toString("utf8");
    attrs.push({ norm: raw.replace(/\s+/g, " ") });
    i = k + 1;
  }
  const head = headWords(b, m, i, end, 8);
  let w = 0;
  if (head[w] === "pub") {
    w++;
    if (head[w] === "crate" || head[w] === "super" || head[w] === "self") w++;
  }
  let isUse = false;
  let useText = "";
  let decl: Segment["decl"] = null;
  let modName: string | null = null;
  if (head[w] === "use") {
    isUse = true;
    const useAt = findWord(b, m, i, end, "use");
    const stop = b[end - 1] === 0x3b ? end - 1 : end;
    useText = cleanCode(b, m, useAt + 3, stop);
  } else {
    for (let k = w; k < head.length; k++) {
      if (!DECL_KEYWORDS.has(head[k]!)) continue;
      let n = k + 1;
      while (head[n] !== undefined && DECL_SKIP.has(head[n]!)) n++;
      if (head[n] !== undefined) decl = { kind: head[k]!, name: head[n]! };
      break;
    }
    if (head[w] === "mod" && open >= 0 && head[w + 1] !== undefined) modName = head[w + 1]!;
  }
  return { start, end, attrs, innerAttr, open: openOf(b, m, i, end, open), isUse, useText, decl, modName };
}

// A `}` followed by one of these does not end its item: a match arm with a struct pattern, an
// `if` with an `else`, a method call on the value of a block.
function continuesItem(b: Bytes, m: Uint8Array, k: number, to: number): boolean {
  if (k >= to) return false;
  const c = b[k];
  if (c === 0x2c || c === 0x2e || c === 0x3f) return true;
  if (c === 0x3d && b[k + 1] === 0x3e) return true;
  const word = Buffer.from(b.subarray(k, Math.min(to, k + 5))).toString("utf8");
  return word.startsWith("else") && !isIdent(b[k + 4]);
}

// The `{` that opens a segment body: after its `=>` when it is a match arm, else the first one.
function openOf(b: Bytes, m: Uint8Array, start: number, end: number, fallback: number): number {
  let depth = 0;
  let arrowSeen = false;
  for (let k = start; k < end; k++) {
    if (m[k] === 0) continue;
    const c = b[k];
    if (c === 0x28 || c === 0x5b) depth++;
    else if (c === 0x29 || c === 0x5d) depth--;
    else if (c === 0x7b) {
      if (depth === 0 && arrowSeen) return k;
      depth++;
    } else if (c === 0x7d) depth--;
    else if (c === 0x3d && b[k + 1] === 0x3e && depth === 0) arrowSeen = true;
  }
  return fallback;
}

function findWord(b: Bytes, m: Uint8Array, from: number, to: number, word: string): number {
  const pattern = Buffer.from(word);
  for (let k = from; k < to; k++) {
    if (m[k] === 0) continue;
    if (b.subarray(k, k + pattern.length).equals(pattern) && !isIdent(b[k - 1]) && !isIdent(b[k + pattern.length])) {
      return k;
    }
  }
  return from;
}

function cleanCode(b: Bytes, m: Uint8Array, from: number, to: number): string {
  const bytes: number[] = [];
  for (let k = from; k < to; k++) bytes.push(m[k] === 1 ? b[k]! : 0x20);
  return Buffer.from(bytes).toString("utf8");
}

// ---- use trees: the names a `use` binds, and the globs it imports ----

type Binding = { name: string; path: string };
type UseInfo = { bindings: Binding[]; globs: string[] };

function parseUseTree(tree: string, prefix: string[], out: UseInfo): void {
  const text = tree.trim();
  if (text === "") return;
  const brace = text.indexOf("{");
  if (brace >= 0) {
    const head = text.slice(0, brace).replace(/::\s*$/, "").trim();
    const headSegs = head === "" ? [] : head.split("::").map((s) => s.trim());
    let depth = 0;
    let close = text.length - 1;
    for (let k = brace; k < text.length; k++) {
      if (text[k] === "{") depth++;
      if (text[k] === "}") {
        depth--;
        if (depth === 0) {
          close = k;
          break;
        }
      }
    }
    let level = 0;
    let piece = "";
    for (const ch of text.slice(brace + 1, close)) {
      if (ch === "{") level++;
      if (ch === "}") level--;
      if (ch === "," && level === 0) {
        parseUseTree(piece, [...prefix, ...headSegs], out);
        piece = "";
      } else piece += ch;
    }
    parseUseTree(piece, [...prefix, ...headSegs], out);
    return;
  }
  const alias = /^(.*?)\s+as\s+([A-Za-z_]\w*)$/.exec(text);
  const body = alias ? alias[1]!.trim() : text;
  const segs = [...prefix, ...body.split("::").map((s) => s.trim()).filter((s) => s !== "")];
  if (segs[segs.length - 1] === "*") {
    out.globs.push(segs.join("::"));
    return;
  }
  if (segs[segs.length - 1] === "self") segs.pop();
  if (segs.length === 0) return;
  const name = alias ? alias[2]! : segs[segs.length - 1]!;
  out.bindings.push({ name, path: segs.join("::") });
}

function useInfo(seg: Segment): UseInfo {
  const info: UseInfo = { bindings: [], globs: [] };
  parseUseTree(seg.useText, [], info);
  return info;
}

// ---- modules, and the cfg chain of a byte ----

function buildModules(b: Bytes, m: Uint8Array): Module[] {
  const mods: Module[] = [{ id: 0, parent: -1, depth: 0, from: 0, to: b.length, open: -1, segs: [] }];
  for (let q = 0; q < mods.length; q++) {
    const mod = mods[q]!;
    mod.segs = parseSegments(b, m, mod.from, mod.to);
    for (const seg of mod.segs) {
      if (seg.modName === null) continue;
      mods.push({
        id: mods.length,
        parent: q,
        depth: mod.depth + 1,
        from: seg.open + 1,
        to: matchClose(b, m, seg.open),
        open: seg.open,
        segs: [],
      });
    }
  }
  return mods;
}

function innermost(mods: Module[], at: number): Module {
  let best = mods[0]!;
  for (const mod of mods) {
    if (mod.from <= at && at < mod.to && mod.depth > best.depth) best = mod;
  }
  return best;
}

// The `{ .. }` block of a segment that holds `at`, at its own depth: an if, its else, a match or a body.
function blockAt(b: Bytes, m: Uint8Array, seg: Segment, at: number): { open: number; close: number } | null {
  let depth = 0;
  for (let k = seg.start; k < seg.end; k++) {
    if (m[k] === 0) continue;
    const c = b[k];
    if (c === 0x28 || c === 0x5b) depth++;
    else if (c === 0x29 || c === 0x5d) depth--;
    else if (c === 0x7b && depth === 0) {
      const close = matchClose(b, m, k);
      if (k < at && at < close) return { open: k, close };
      k = close;
    }
  }
  return null;
}

// The cfg attributes of every item that holds `at`, inside `mod`, sorted.
function cfgChain(b: Bytes, m: Uint8Array, mod: Module, at: number): string[] {
  const cfgs: string[] = [];
  let segs = mod.segs;
  for (;;) {
    const seg = segs.find((s) => s.start <= at && at < s.end);
    if (!seg) break;
    for (const attr of seg.attrs) if (attr.norm.startsWith("#[cfg(")) cfgs.push(attr.norm);
    const block = blockAt(b, m, seg, at);
    if (block === null) break;
    segs = parseSegments(b, m, block.open + 1, block.close);
  }
  return [...new Set(cfgs)].sort();
}

function segKey(seg: Segment): string {
  return seg.attrs
    .map((a) => a.norm)
    .filter((n) => n.startsWith("#[cfg("))
    .sort()
    .join(KEY_SEP);
}

function lineStart(b: Bytes, idx: number): number {
  let i = idx;
  while (i > 0 && b[i - 1] !== 0x0a) i--;
  return i;
}

// Start of the line that holds `idx`, moved up over the doc comments that sit right above it.
function startWithDocs(b: Bytes, idx: number): number {
  let ls = lineStart(b, idx);
  while (ls > 0) {
    const prev = lineStart(b, ls - 1);
    const text = Buffer.from(b.subarray(prev, ls - 1)).toString("utf8").trim();
    if (!text.startsWith("///") && !text.startsWith("//!")) break;
    ls = prev;
  }
  return ls;
}

function indentOf(b: Bytes, lineBegin: number): string {
  let j = lineBegin;
  while (j < b.length && (b[j] === 0x20 || b[j] === 0x09)) j++;
  return Buffer.from(b.subarray(lineBegin, j)).toString("utf8");
}

// Where the `use` lines of a module go: before its first item that is not a use.
function anchor(b: Bytes, mod: Module, modLine: number): { pos: number; indent: string } {
  const first = mod.segs.find((s) => !s.isUse && !s.innerAttr);
  if (first) {
    const pos = startWithDocs(b, first.start);
    return { pos, indent: indentOf(b, pos) };
  }
  if (mod.open < 0) return { pos: b.length, indent: "" };
  return { pos: lineStart(b, mod.to), indent: `${indentOf(b, lineStart(b, modLine))}    ` };
}

// ---- the rewrite of one file ----

// The message names the bare module name that a `use` would bind, and why it cannot.
// The cfg predicate of one chain: `feature = "a"` for `#[cfg(feature = "a")]`, `all(..)` for more.
function chainPred(key: string): string {
  const preds = key.split(KEY_SEP).map((a) => a.slice("#[cfg(".length, -2));
  return preds.length === 1 ? preds[0]! : `all(${preds.join(", ")})`;
}

// The attributes a use needs to be active whenever any of the given chains holds.
function useAttrsFor(keys: string[]): string[] {
  if (keys.includes("")) return [];
  const distinct = [...new Set(keys)].sort();
  if (distinct.length === 1) return distinct[0]!.split(KEY_SEP);
  return [`#[cfg(any(${distinct.map(chainPred).join(", ")}))]`];
}

// Whether a use with the cfg key `use` is active whenever the chain `key` holds.
function covers(use: string, key: string): boolean {
  if (use === "") return true;
  if (key === "") return false;
  if (use === key) return true;
  const prefix = "#[cfg(any(";
  if (use.startsWith(prefix) && use.endsWith("))]") && !use.includes(KEY_SEP)) {
    return splitTop(use.slice(prefix.length, -3)).includes(chainPred(key));
  }
  return false;
}

function splitTop(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of text) {
    if (ch === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
      continue;
    }
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    cur += ch;
  }
  if (cur.trim() !== "") out.push(cur.trim());
  return out;
}

// The message names the bare module name that a `use` would bind, and why it cannot.
function boundReason(b: Bytes, mods: Module[], mod: Module, bare: string, parent: string, key: string): string | null {
  for (const seg of mod.segs) {
    if (seg.decl !== null && seg.decl.name === bare) {
      return `bare name \`${bare}\` is already declared in this module (line ${lineOf(b, seg.start)})`;
    }
    if (!seg.isUse) continue;
    for (const bind of useInfo(seg).bindings) {
      if (bind.name !== bare) continue;
      if (bind.path !== parent) {
        return `bare name \`${bare}\` is already bound by \`use ${bind.path}\` at line ${lineOf(b, seg.start)}`;
      }
      if (covers(segKey(seg), key)) return null;
      return `bare name \`${bare}\` is already imported as \`${parent}\` under another cfg; hand edit`;
    }
  }
  for (const seg of mod.segs) {
    if (!seg.isUse) continue;
    for (const glob of useInfo(seg).globs) {
      if (glob === "super::*" && mod.parent >= 0) {
        const parentMod = mods[mod.parent]!;
        for (const other of parentMod.segs) {
          if (other.decl !== null && other.decl.name === bare) {
            return `glob import \`${glob}\` in this module may bind \`${bare}\` (declared at line ${lineOf(b, other.start)})`;
          }
        }
        continue;
      }
      return `glob import \`${glob}\` in this module may bind \`${bare}\``;
    }
  }
  return null;
}

// The `use` of `bare` that already binds `parent` in the module, if any.
function existingUse(mod: Module, bare: string, parent: string): Segment | null {
  for (const seg of mod.segs) {
    if (!seg.isUse) continue;
    for (const bind of useInfo(seg).bindings) {
      if (bind.name === bare && bind.path === parent) return seg;
    }
  }
  return null;
}

function findOccurrences(b: Bytes, m: Uint8Array, full: string): number[] {
  const pattern = Buffer.from(full, "utf8");
  const found: number[] = [];
  for (let k = 0; k + pattern.length <= b.length; k++) {
    if (b[k] !== pattern[0]) continue;
    if (!b.subarray(k, k + pattern.length).equals(pattern)) continue;
    if (k > 0 && (isIdent(b[k - 1]) || b[k - 1] === 0x3a)) continue;
    if (isIdent(b[k + pattern.length])) continue;
    let code = true;
    for (let q = k; q < k + pattern.length; q++) if (m[q] === 0) code = false;
    if (code) found.push(k);
  }
  return found;
}

// Whether `at` lies in a `use` item, at any depth: the statement that holds it starts with `use`.
function inUseItem(b: Bytes, m: Uint8Array, at: number): boolean {
  let s = at;
  while (s > 0) {
    const c = b[s - 1]!;
    if (m[s - 1] === 1 && (c === 0x3b || c === 0x7b || c === 0x7d || c === 0x5d)) break;
    s--;
  }
  const start = skipNonCode(b, m, s, at);
  const head = Buffer.from(b.subarray(start, Math.min(b.length, start + 256))).toString("utf8");
  return /^(pub(\([^)]*\))?\s+)?use\s/.test(head);
}

// The leading path of a span: clippy's span may carry generic arguments after it.
const PATH_PREFIX = /^[A-Za-z_]\w*(?:::[A-Za-z_]\w*)+/;

export function rewriteFile(
  source: string,
  hits: Array<Pick<Hit, "start" | "end" | "line" | "expected">>,
  extra: Array<{ start: number; end: number; text: string; expected?: string | undefined }> = [],
): FileResult {
  const b: Bytes = Buffer.from(source, "utf8");
  const m = codeMask(b);
  const mods = buildModules(b, m);
  const refusals: Refusal[] = [];
  const spanText = (h: { start: number; end: number }) => Buffer.from(b.subarray(h.start, h.end)).toString("utf8");

  // Step 1: each hit, checked on its own. The span is cut to its path.
  const plans: Plan[] = [];
  for (const h of hits) {
    if (h.expected !== undefined && spanText(h) !== h.expected) {
      refusals.push({ line: h.line, reason: "stale hit: the file no longer matches clippy's run; run clippy again" });
      continue;
    }
    const prefix = PATH_PREFIX.exec(spanText(h));
    const full = prefix ? prefix[0] : spanText(h);
    const parts = full.split("::");
    if (!prefix || parts.length < 3) {
      refusals.push({ line: h.line, reason: `not a plain path: \`${spanText(h)}\`` });
      continue;
    }
    if (full.includes("time::Instant")) {
      refusals.push({ line: h.line, reason: "time::Instant is refused: clippy.toml forbids Instant::now on wasm32; hand edit" });
      continue;
    }
    const bare = parts[parts.length - 2]!;
    const mod = innermost(mods, h.start);
    const key = cfgChain(b, m, mod, h.start).join(KEY_SEP);
    const parent = parts.slice(0, -1).join("::");
    const reason = boundReason(b, mods, mod, bare, parent, key);
    if (reason !== null) {
      refusals.push({ line: h.line, reason });
      continue;
    }
    const span = { start: h.start, end: h.start + Buffer.byteLength(full), line: h.line };
    plans.push({ hit: span, bare, parent, item: parts[parts.length - 1]!, mod: mod.id, key });
  }

  // Step 2: one bare name with two parents in one file. Every plan that uses it is refused.
  const parentsByBare = new Map<string, Set<string>>();
  for (const p of plans) {
    if (!parentsByBare.has(p.bare)) parentsByBare.set(p.bare, new Set());
    parentsByBare.get(p.bare)!.add(p.parent);
  }
  for (const p of plans) {
    const parents = parentsByBare.get(p.bare)!;
    if (parents.size > 1) {
      refusals.push({
        line: p.hit.line,
        reason: `two parents give \`${p.bare}\` in this file: ${[...parents].sort().join(", ")}`,
      });
    }
  }
  const accepted = plans.filter((p) => parentsByBare.get(p.bare)!.size === 1);

  const edits: Edit[] = [];
  let suggested = 0;
  for (const s of extra) {
    if (s.expected !== undefined && Buffer.from(b.subarray(s.start, s.end)).toString("utf8") !== s.expected) {
      refusals.push({ line: lineOf(b, s.start), reason: "stale suggestion: the file no longer matches the compiler's run; run clippy again" });
      continue;
    }
    edits.push(s);
    suggested++;
  }
  const uses: string[] = [];

  // Step 3: where the `use` of each (module, parent) goes, and the cfg it carries.
  // The use is active whenever one of its hits holds, so its cfg is the union of their chains.
  const groups = new Map<string, { mod: Module; parent: string; bare: string; keys: string[] }>();
  for (const p of accepted) {
    const mod = mods[p.mod]!;
    if (existingUse(mod, p.bare, p.parent) !== null) continue;
    const gid = `${p.mod}\u0000${p.parent}`;
    if (!groups.has(gid)) groups.set(gid, { mod, parent: p.parent, bare: p.bare, keys: [] });
    groups.get(gid)!.keys.push(p.key);
  }
  const useKeyByGroup = new Map<string, string>();
  for (const [gid, g] of groups) {
    const attrs = useAttrsFor(g.keys);
    useKeyByGroup.set(gid, attrs.join(KEY_SEP));
  }
  const byModule = new Map<number, Array<{ parent: string; attrs: string[] }>>();
  for (const [gid, g] of groups) {
    const modId = g.mod.id;
    if (!byModule.has(modId)) byModule.set(modId, []);
    byModule.get(modId)!.push({ parent: g.parent, attrs: useKeyByGroup.get(gid)!.split(KEY_SEP).filter((a) => a !== "") });
  }
  for (const [modId, items] of byModule) {
    const mod = mods[modId]!;
    const modLine = mod.open >= 0 ? mod.open : 0;
    const { pos, indent } = anchor(b, mod, modLine);
    const lines: string[] = [];
    for (const item of items.sort((x, y) => (x.parent < y.parent ? -1 : 1))) {
      for (const attr of item.attrs) lines.push(`${indent}${attr}\n`);
      lines.push(`${indent}use ${item.parent};\n`);
      uses.push(`use ${item.parent};`);
    }
    edits.push({ start: pos, end: pos, text: lines.join("") });
  }

  // Step 4: for each accepted hit, its path in the module; and every other occurrence of that path
  // in the same module whose cfg chain the use covers. Occurrences in comments and literals are skipped.
  const replaced = new Set<number>();
  for (const p of accepted) {
    const mod = mods[p.mod]!;
    const full = `${p.parent}::${p.item}`;
    const gid = `${p.mod}\u0000${p.parent}`;
    const useKey = existingUse(mod, p.bare, p.parent) !== null
      ? segKey(existingUse(mod, p.bare, p.parent)!)
      : useKeyByGroup.get(gid)!;
    const spans = [p.hit.start];
    for (const at of findOccurrences(b, m, full)) {
      if (at === p.hit.start) continue;
      const here = innermost(mods, at);
      if (here.id !== mod.id) continue;
      if (!covers(useKey, cfgChain(b, m, here, at).join(KEY_SEP))) continue;
      if (inUseItem(b, m, at)) continue;
      spans.push(at);
    }
    for (const at of spans) {
      if (replaced.has(at)) continue;
      replaced.add(at);
      edits.push({ start: at, end: at + Buffer.byteLength(full), text: `${p.bare}::${p.item}` });
    }
  }

  // Step 5: apply from the start, and skip a rewrite that overlaps the one before it.
  edits.sort((x, y) => x.start - y.start || x.end - y.end);
  const kept: Edit[] = [];
  let last = -1;
  for (const e of edits) {
    if (e.start < last) {
      refusals.push({ line: lineOf(b, e.start), reason: "overlaps another rewrite; run the script again" });
      continue;
    }
    kept.push(e);
    last = e.end;
  }
  const parts: Buffer[] = [];
  let cursor = 0;
  for (const e of kept) {
    parts.push(b.subarray(cursor, e.start), Buffer.from(e.text, "utf8"));
    cursor = e.end;
  }
  parts.push(b.subarray(cursor));
  refusals.sort((x, y) => x.line - y.line || x.reason.localeCompare(y.reason));
  return {
    text: Buffer.concat(parts).toString("utf8"),
    refusals,
    uses,
    replaced: replaced.size,
    suggested,
  };
}

// ---- command line ----

function main(args: string[]): number {
  let root = process.cwd();
  const jsonFiles: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--root") root = args[++i] ?? root;
    else jsonFiles.push(args[i]!);
  }
  const texts = jsonFiles.map((f) => readFileSync(f, "utf8"));
  const hits = texts.flatMap((t) => collectHits(t));
  const suggestions = [
    ...new Map(
      texts.flatMap((t) => collectSuggestions(t)).map((s) => [`${s.file}:${s.start}:${s.end}:${s.text}`, s]),
    ).values(),
  ];
  const byFile = new Map<string, Hit[]>();
  for (const h of hits) {
    if (!byFile.has(h.file)) byFile.set(h.file, []);
    byFile.get(h.file)!.push(h);
  }
  const suggestionsByFile = new Map<string, Suggestion[]>();
  for (const s of suggestions) {
    if (!suggestionsByFile.has(s.file)) suggestionsByFile.set(s.file, []);
    suggestionsByFile.get(s.file)!.push(s);
  }
  const files = [...new Set([...byFile.keys(), ...suggestionsByFile.keys()])].sort();
  let replaced = 0;
  let suggested = 0;
  let uses = 0;
  let edited = 0;
  const refused: string[] = [];
  for (const file of files) {
    const full = path.join(root, file);
    const source = readFileSync(full, "utf8");
    const result = rewriteFile(source, byFile.get(file) ?? [], suggestionsByFile.get(file) ?? []);
    replaced += result.replaced;
    suggested += result.suggested;
    uses += result.uses.length;
    for (const r of result.refusals) refused.push(`${file}:${r.line}: ${r.reason}`);
    if (result.text !== source) {
      writeFileSync(full, result.text);
      edited++;
    }
  }
  console.log(
    `absolute-paths: hits ${hits.length}, files ${byFile.size}, replaced ${replaced}, suggestions ${suggested}, uses added ${uses}, edited ${edited}, refused ${refused.length}`,
  );
  for (const line of refused) console.log(`refused ${line}`);
  return 0;
}

if (import.meta.main) process.exit(main(process.argv.slice(2)));
