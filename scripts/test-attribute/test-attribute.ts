#!/usr/bin/env bun
// Rewrites each `#[test]` function that uses the habilis_network_test_tracing `test` attribute into
// the guard calls the attribute expands to: `let _guard = init();` for a sync test, and
// `run(init(), async { .. })` (or `run_multi_thread(init(), N, async { .. })`) for an async one.
// A file that has a form this does not handle is reported and left unchanged.

import { readFileSync, writeFileSync } from "node:fs";

const IMPORT = /^[ \t]*use habilis_network_test_tracing::test;\n/gm;
const BRACE_IMPORT = /^([ \t]*)use habilis_network_test_tracing::\{([^}]*)\};\n/gm;
const TEST_FN =
  /^([ \t]*)#\[test(\(([^\n)]*)\))?\]\n((?:[ \t]*#\[[^\n]*\]\n)*)([ \t]*)(pub(?:\([^)]*\))?\s+)?(async\s+)?fn\s+(\w+)\s*\(/gm;

// Where the sync guard goes: after the item declarations that open the body (use, const, fn, ...),
// since an item after a statement is a lint. Returns the body with the guard line inserted.
const ITEM = /^(use|const|static|type|struct|enum|fn|impl|mod|trait)\b|^#\[/;
function guardAfterItems(body: string, bodyIndent: string): string {
  const lines = body.split("\n");
  const guard = `${bodyIndent}let _guard = ::habilis_network_test_tracing::init();`;
  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    if (line.trim() === "") { i++; continue; }
    if (!line.startsWith(bodyIndent) || !ITEM.test(line.slice(bodyIndent.length))) break;
    const end = line.trimEnd().endsWith(";") ? i : lines.findIndex((l, k) => k > i && (l === bodyIndent + "}" || l === bodyIndent + "};"));
    if (end < 0) break;
    i = end + 1;
  }
  return [...lines.slice(0, i), guard, ...lines.slice(i)].join("\n");
}

// The index of the `)` that closes the `(` at `open`, skipping nested parentheses. -1 when unbalanced.
function closingParen(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")" && --depth === 0) return i;
  }
  return -1;
}

// The index of the `}` that closes the `{` at `open`, skipping strings, raw strings, char literals
// and comments. -1 when the braces do not balance.
function closingBrace(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === "/" && text[i + 1] === "/") {
      i = text.indexOf("\n", i);
      if (i < 0) return -1;
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      if (end < 0) return -1;
      i = end + 1;
    } else if (c === "r" && /[#"]/.test(text[i + 1] ?? "") && !/\w/.test(text[i - 1] ?? "")) {
      const hashes = text.slice(i + 1).match(/^#*/)![0].length;
      if (text[i + 1 + hashes] !== '"') continue;
      const close = text.indexOf(`"${"#".repeat(hashes)}`, i + 2 + hashes);
      if (close < 0) return -1;
      i = close + hashes;
    } else if (c === '"') {
      i++;
      while (i < text.length && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
    } else if (c === "'") {
      if (text[i + 1] === "\\") {
        const end = text.indexOf("'", i + 2);
        if (end < 0) return -1;
        i = end;
      } else if (text[i + 2] === "'") {
        i += 2;
      }
    } else if (c === "{") {
      depth++;
    } else if (c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function indentBy(lines: string, extra: string): string {
  return lines
    .split("\n")
    .map((line) => (line.trim() === "" ? line : extra + line))
    .join("\n");
}

// The arguments of `#[test(...)]`: `run`, `run_multi_thread`, or null when this form is not handled.
function runCall(args: string | undefined): { call: string; workers?: string } | null {
  if (args === undefined || args.trim() === "" || args.replace(/\s/g, "") === 'flavor="current_thread"') {
    return { call: "run" };
  }
  const flavor = args.match(/flavor\s*=\s*"multi_thread"/);
  const workers = args.match(/worker_threads\s*=\s*(\d+)/);
  if (flavor && workers && args.replace(/\s/g, "").match(/^(flavor="multi_thread",worker_threads=\d+|worker_threads=\d+,flavor="multi_thread")$/)) {
    return { call: "run_multi_thread", workers: workers[1] };
  }
  return null;
}

export function rewrite(source: string): { text: string; flagged: string[] } {
  const flagged: string[] = [];
  const kept: string[] = [];
  let text = source.replace(IMPORT, "").replace(BRACE_IMPORT, (_line, _indent: string, items: string) => {
    kept.push(...items.split(",").map((item) => item.trim()).filter((item) => item !== "" && item !== "test"));
    return "";
  });
  // A function that was imported by name is called through its module instead: the `fn_import` gate refuses a bare import.
  for (const name of kept) {
    text = text.replace(new RegExp(`(?<![\\w.:])${name}\\(`, "g"), `::habilis_network_test_tracing::${name}(`);
  }
  const testAttrs = (text.match(/#\[test\b/g) ?? []).length;
  const pieces: string[] = [];
  let last = 0;
  let matched = 0;
  for (const m of text.matchAll(TEST_FN)) {
    const start = m.index!;
    const paramsClose = closingParen(text, start + m[0].length - 1);
    const open = text.indexOf("{", paramsClose);
    if (paramsClose < 0 || open < 0) {
      flagged.push(`${m[8]}: unbalanced parameters`);
      continue;
    }
    const params = text.slice(start + m[0].length, paramsClose);
    const ret = text.slice(paramsClose + 1, open);
    const close = closingBrace(text, open);
    if (close < 0) {
      flagged.push(`${m[8]}: unbalanced braces`);
      continue;
    }
    matched++;
    const [, indent, , args, otherAttrs = "", , vis = "", asyncKw, name] = m;
    const body = text.slice(open + 1, close);
    const bodyIndent = body.match(/\n([ \t]*)\S/)?.[1] ?? `${indent}    `;
    let newBody: string;
    if (asyncKw) {
      if (params.trim() !== "") {
        flagged.push(`${name}: async test with parameters`);
        continue;
      }
      const run = runCall(args);
      if (run === null) {
        flagged.push(`${name}: test arguments not handled: ${args}`);
        continue;
      }
      const head = run.call === "run"
        ? `${bodyIndent}::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {`
        : `${bodyIndent}::habilis_network_test_tracing::run_multi_thread(::habilis_network_test_tracing::init(), ${run.workers}, async {`;
      const inner = indentBy(body.replace(/^\n/, "").replace(/\n[ \t]*$/, ""), "    ");
      newBody = `\n${head}\n${inner}\n${bodyIndent}});\n${indent}`;
    } else {
      if (args !== undefined) {
        flagged.push(`${name}: sync test arguments not handled: ${args}`);
        continue;
      }
      newBody = `${guardAfterItems(body, bodyIndent)}${indent}`;
    }
    const header = `${indent}#[test]\n${otherAttrs}${indent}${vis}fn ${name}(${params})${ret}{`;
    pieces.push(text.slice(last, start), `${header}${newBody}}`);
    last = close + 1;
  }
  pieces.push(text.slice(last));
  if (matched !== testAttrs) {
    flagged.push(`${matched} of ${testAttrs} #[test] functions are of a form this does not handle`);
  }
  return { text: pieces.join(""), flagged };
}

if (import.meta.main) {
  let changed = 0;
  for (const file of process.argv.slice(2)) {
    const source = readFileSync(file, "utf8");
    const { text, flagged } = rewrite(source);
    if (flagged.length > 0) {
      console.log(`skipped ${file}: ${flagged.join("; ")}`);
      continue;
    }
    if (text !== source) {
      writeFileSync(file, text);
      changed++;
      console.log(`rewrote ${file}`);
    }
  }
  console.log(`${changed} files rewritten`);
}
