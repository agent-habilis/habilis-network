// Tests of scripts/absolute-paths/absolute-paths.ts. Each case feeds a small Rust fixture and the
// hits that clippy reports on it, then checks the exact output text, or the exact refusal reason.

import { expect, test } from "bun:test";
import { collectHits, collectSuggestions, rewriteFile } from "./absolute-paths.ts";

// Byte offsets of the nth occurrence of `needle`, as clippy reports them (UTF-8 bytes).
function hit(source: string, needle: string, nth = 0) {
  const bytes = Buffer.from(source, "utf8");
  const pattern = Buffer.from(needle, "utf8");
  let from = 0;
  let start = -1;
  for (let i = 0; i <= nth; i++) {
    start = bytes.indexOf(pattern, from);
    from = start + 1;
  }
  const line = bytes.subarray(0, start).toString("utf8").split("\n").length;
  return { start, end: start + pattern.length, line };
}

test("imports the parent module and rewrites the path", () => {
  const src = "static IP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);\n";
  const out = rewriteFile(src, [hit(src, "std::sync::atomic::AtomicBool")]);
  expect(out.text).toBe(
    "use std::sync::atomic;\nstatic IP: atomic::AtomicBool = atomic::AtomicBool::new(false);\n",
  );
  expect(out.refusals).toEqual([]);
});

test("slices by bytes after a multibyte character", () => {
  const src = [
    "use std::fmt;",
    "// café 🦀",
    "fn kind() -> crate::transport::probe::PathKind {",
    "    crate::transport::probe::PathKind::Direct",
    "}",
    "",
  ].join("\n");
  const hits = [hit(src, "crate::transport::probe::PathKind", 0), hit(src, "crate::transport::probe::PathKind", 1)];
  const out = rewriteFile(src, hits);
  expect(out.text).toBe(
    [
      "use std::fmt;",
      "// café 🦀",
      "use crate::transport::probe;",
      "fn kind() -> probe::PathKind {",
      "    probe::PathKind::Direct",
      "}",
      "",
    ].join("\n"),
  );
});

test("puts the use inside mod tests and copies the cfg of the hit", () => {
  const src = [
    "fn outer() {}",
    "#[cfg(test)]",
    "mod tests {",
    "    use super::*;",
    "",
    '    #[cfg(feature = "wasm-simd")]',
    "    fn lanes() -> std::arch::wasm32::v128 { todo!() }",
    "",
    "    #[test]",
    "    fn size() {",
    "        assert_eq!(std::mem::size_of::<std::sync::atomic::AtomicBool>(), 1);",
    "    }",
    "}",
    "",
  ].join("\n");
  const hits = [hit(src, "std::arch::wasm32::v128"), hit(src, "std::sync::atomic::AtomicBool")];
  const out = rewriteFile(src, hits);
  expect(out.text).toBe(
    [
      "fn outer() {}",
      "#[cfg(test)]",
      "mod tests {",
      "    use super::*;",
      "",
      '    #[cfg(feature = "wasm-simd")]',
      "    use std::arch::wasm32;",
      "    use std::sync::atomic;",
      '    #[cfg(feature = "wasm-simd")]',
      "    fn lanes() -> wasm32::v128 { todo!() }",
      "",
      "    #[test]",
      "    fn size() {",
      "        assert_eq!(std::mem::size_of::<atomic::AtomicBool>(), 1);",
      "    }",
      "}",
      "",
    ].join("\n"),
  );
  expect(out.refusals).toEqual([]);
});

test("refuses a bare name that the module already declares", () => {
  const src = [
    "mod atomic {",
    "    pub struct Flag;",
    "}",
    "fn f() -> std::sync::atomic::AtomicBool { todo!() }",
    "",
  ].join("\n");
  const out = rewriteFile(src, [hit(src, "std::sync::atomic::AtomicBool")]);
  expect(out.text).toBe(src);
  expect(out.refusals).toEqual([
    { line: 4, reason: "bare name `atomic` is already declared in this module (line 1)" },
  ]);
});

test("refuses a bare name that a glob import in the module may bind", () => {
  const src = [
    "use std::sync::*;",
    "fn f() -> std::sync::atomic::AtomicBool { todo!() }",
    "",
  ].join("\n");
  const out = rewriteFile(src, [hit(src, "std::sync::atomic::AtomicBool")]);
  expect(out.text).toBe(src);
  expect(out.refusals).toEqual([
    { line: 2, reason: "glob import `std::sync::*` in this module may bind `atomic`" },
  ]);
});

test("refuses two parents that give one bare name in one file", () => {
  const src = [
    "mod one { pub mod fs { pub struct File; } }",
    "mod two { pub mod fs { pub struct File; } }",
    "fn a() -> crate::one::fs::File { todo!() }",
    "fn b() -> crate::two::fs::File { todo!() }",
    "",
  ].join("\n");
  const hits = [hit(src, "crate::one::fs::File"), hit(src, "crate::two::fs::File")];
  const out = rewriteFile(src, hits);
  expect(out.text).toBe(src);
  expect(out.refusals).toEqual([
    { line: 3, reason: "two parents give `fs` in this file: crate::one::fs, crate::two::fs" },
    { line: 4, reason: "two parents give `fs` in this file: crate::one::fs, crate::two::fs" },
  ]);
});

test("refuses a time::Instant path, which the wasm32 clock lint forbids", () => {
  const src = "fn f() { let t = crate::clock::time::Instant::now(); let _ = t; }\n";
  const out = rewriteFile(src, [hit(src, "crate::clock::time::Instant")]);
  expect(out.text).toBe(src);
  expect(out.refusals).toEqual([
    { line: 1, reason: "time::Instant is refused: clippy.toml forbids Instant::now on wasm32; hand edit" },
  ]);
});

test("rewrites an occurrence that clippy did not report, but not in comments or strings", () => {
  const src = [
    "use std::fmt;",
    "fn a() -> std::sync::atomic::AtomicBool { todo!() }",
    "// std::sync::atomic::AtomicBool in a comment",
    'const S: &str = "std::sync::atomic::AtomicBool";',
    "fn b() -> std::sync::atomic::AtomicBool { todo!() }",
    "",
  ].join("\n");
  const out = rewriteFile(src, [hit(src, "std::sync::atomic::AtomicBool", 0)]);
  expect(out.text).toBe(
    [
      "use std::fmt;",
      "use std::sync::atomic;",
      "fn a() -> atomic::AtomicBool { todo!() }",
      "// std::sync::atomic::AtomicBool in a comment",
      'const S: &str = "std::sync::atomic::AtomicBool";',
      "fn b() -> atomic::AtomicBool { todo!() }",
      "",
    ].join("\n"),
  );
});

test("a second run changes nothing", () => {
  const src = "static IP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);\n";
  const once = rewriteFile(src, [hit(src, "std::sync::atomic::AtomicBool")]).text;
  const twice = rewriteFile(once, []).text;
  expect(twice).toBe(once);
});

test("collects the primary span of each absolute_paths message, once per span", () => {
  const diagnostic = {
    reason: "compiler-message",
    message: {
      level: "warning",
      message: "consider bringing this path into scope with the `use` keyword",
      code: { code: "clippy::absolute_paths" },
      spans: [
        {
          file_name: "crates/x/src/lib.rs",
          byte_start: 4,
          byte_end: 33,
          line_start: 1,
          is_primary: true,
        },
      ],
    },
  };
  const line = JSON.stringify(diagnostic);
  const other = JSON.stringify({ reason: "compiler-message", message: { code: { code: "clippy::other" }, spans: [] } });
  const hits = collectHits([line, line, other].join("\n"));
  expect(hits).toEqual([{ file: "crates/x/src/lib.rs", start: 4, end: 33, line: 1 }]);
});

test("keeps the generic arguments of a span and rewrites only the path", () => {
  const src = "fn f() -> tokio::sync::mpsc::UnboundedSender<u8> { todo!() }\n";
  const out = rewriteFile(src, [hit(src, "tokio::sync::mpsc::UnboundedSender<u8>")]);
  expect(out.text).toBe("use tokio::sync::mpsc;\nfn f() -> mpsc::UnboundedSender<u8> { todo!() }\n");
  expect(out.refusals).toEqual([]);
});

test("an unconditional hit makes the use unconditional", () => {
  const src = [
    "fn plain() -> std::sync::atomic::AtomicBool { todo!() }",
    "#[cfg(test)]",
    "fn under_test() -> std::sync::atomic::AtomicBool { todo!() }",
    "",
  ].join("\n");
  const hits = [hit(src, "std::sync::atomic::AtomicBool", 0), hit(src, "std::sync::atomic::AtomicBool", 1)];
  const out = rewriteFile(src, hits);
  expect(out.text).toBe(
    [
      "use std::sync::atomic;",
      "fn plain() -> atomic::AtomicBool { todo!() }",
      "#[cfg(test)]",
      "fn under_test() -> atomic::AtomicBool { todo!() }",
      "",
    ].join("\n"),
  );
});

test("hits that all sit under cfg share one use with an any() cfg", () => {
  const src = [
    '#[cfg(feature = "a")]',
    "fn a() -> std::sync::atomic::AtomicBool { todo!() }",
    '#[cfg(feature = "b")]',
    "fn b() -> std::sync::atomic::AtomicBool { todo!() }",
    "",
  ].join("\n");
  const hits = [hit(src, "std::sync::atomic::AtomicBool", 0), hit(src, "std::sync::atomic::AtomicBool", 1)];
  const out = rewriteFile(src, hits);
  expect(out.text).toBe(
    [
      '#[cfg(any(feature = "a", feature = "b"))]',
      "use std::sync::atomic;",
      '#[cfg(feature = "a")]',
      "fn a() -> atomic::AtomicBool { todo!() }",
      '#[cfg(feature = "b")]',
      "fn b() -> atomic::AtomicBool { todo!() }",
      "",
    ].join("\n"),
  );
  expect(out.refusals).toEqual([]);
});

test("refuses a hit that a use under another cfg would have to cover", () => {
  const src = [
    "#[cfg(test)]",
    "use std::sync::atomic;",
    "fn f() -> std::sync::atomic::AtomicBool { todo!() }",
    "",
  ].join("\n");
  const out = rewriteFile(src, [hit(src, "std::sync::atomic::AtomicBool")]);
  expect(out.text).toBe(src);
  expect(out.refusals).toEqual([
    {
      line: 3,
      reason: "bare name `atomic` is already imported as `std::sync::atomic` under another cfg; hand edit",
    },
  ]);
});

test("refuses a hit whose text no longer matches what clippy reported", () => {
  const src = "fn f() -> std::sync::atomic::AtomicBool { todo!() }\n";
  const stale = { ...hit(src, "std::sync::atomic::AtomicBool"), expected: "std::sync::atomic::AtomicBoo" };
  const out = rewriteFile(src, [stale]);
  expect(out.text).toBe(src);
  expect(out.refusals).toEqual([
    { line: 1, reason: "stale hit: the file no longer matches clippy's run; run clippy again" },
  ]);
});

test("a hit inside a match arm with a struct pattern takes the arm's cfg", () => {
  const src = [
    "fn f(x: Msg) {",
    "    match x {",
    '        #[cfg(feature = "multihop")]',
    "        Msg::Tick { reply } => {",
    "            crate::transport::underlay_webrtc::tick_now(reply);",
    "        }",
    "        Msg::Other => {}",
    "    }",
    "}",
    "",
  ].join("\n");
  const out = rewriteFile(src, [hit(src, "crate::transport::underlay_webrtc::tick_now")]);
  expect(out.text).toBe(
    [
      '#[cfg(feature = "multihop")]',
      "use crate::transport::underlay_webrtc;",
      "fn f(x: Msg) {",
      "    match x {",
      '        #[cfg(feature = "multihop")]',
      "        Msg::Tick { reply } => {",
      "            underlay_webrtc::tick_now(reply);",
      "        }",
      "        Msg::Other => {}",
      "    }",
      "}",
      "",
    ].join("\n"),
  );
});

test("a hit in the else block of an if takes the cfg of its statement", () => {
  const src = [
    "fn f(x: bool) {",
    "    if x {",
    "        g();",
    "    } else {",
    '        #[cfg(feature = "multihop")]',
    "        crate::transport::underlay_webrtc::tick_now(1);",
    "    }",
    "}",
    "",
  ].join("\n");
  const out = rewriteFile(src, [hit(src, "crate::transport::underlay_webrtc::tick_now")]);
  expect(out.text).toBe(
    [
      '#[cfg(feature = "multihop")]',
      "use crate::transport::underlay_webrtc;",
      "fn f(x: bool) {",
      "    if x {",
      "        g();",
      "    } else {",
      '        #[cfg(feature = "multihop")]',
      "        underlay_webrtc::tick_now(1);",
      "    }",
      "}",
      "",
    ].join("\n"),
  );
});

test("applies the compiler's machine-applicable deletions in the same pass", () => {
  const src = "fn f() -> habilis::util::X { todo!() }\n";
  const deletion = { start: 10, end: 25, text: "" };
  const out = rewriteFile(src, [], [deletion]);
  expect(out.text).toBe("fn f() -> X { todo!() }\n");
  expect(out.suggested).toBe(1);
});

test("collects the machine-applicable suggestions of unused_qualifications and unused_imports", () => {
  const line = (code: string, applicability: string) =>
    JSON.stringify({
      reason: "compiler-message",
      message: {
        code: { code },
        spans: [],
        children: [
          {
            spans: [
              {
                file_name: "crates/x/src/lib.rs",
                byte_start: 10,
                byte_end: 25,
                suggested_replacement: "",
                suggestion_applicability: applicability,
              },
            ],
          },
        ],
      },
    });
  const json = [line("unused_qualifications", "MachineApplicable"), line("unused_imports", "MaybeIncorrect")].join("\n");
  expect(collectSuggestions(json)).toEqual([{ file: "crates/x/src/lib.rs", start: 10, end: 25, text: "" }]);
});

test("refuses a compiler suggestion whose text no longer matches the run", () => {
  const src = "fn f() -> habilis::util::X { todo!() }\n";
  const stale = { start: 10, end: 25, text: "", expected: "habilis::util::Y" };
  const out = rewriteFile(src, [], [stale]);
  expect(out.text).toBe(src);
  expect(out.suggested).toBe(0);
  expect(out.refusals).toEqual([
    { line: 1, reason: "stale suggestion: the file no longer matches the compiler's run; run clippy again" },
  ]);
});

test("leaves a use item inside a fn body exactly as it is", () => {
  const src = [
    "fn f() {",
    "    use crate::a::b::C;",
    "    let _ = C;",
    "}",
    "fn g() -> crate::a::b::C { todo!() }",
    "",
  ].join("\n");
  const out = rewriteFile(src, [hit(src, "crate::a::b::C", 1)]);
  expect(out.text).toBe(
    [
      "use crate::a::b;",
      "fn f() {",
      "    use crate::a::b::C;",
      "    let _ = C;",
      "}",
      "fn g() -> b::C { todo!() }",
      "",
    ].join("\n"),
  );
});
