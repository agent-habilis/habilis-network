import { describe, expect, test } from "bun:test";
import { renameInFile } from "./abbrev-names";

describe("renameInFile", () => {
  test("renames a code identifier and keeps its line", () => {
    const { text, hits } = renameInFile("a.rs", "let ctx = 1;\n");
    expect(text).toBe("let context = 1;\n");
    expect(hits).toEqual([{ file: "a.rs", line: 1, from: "ctx", to: "context" }]);
  });

  test("keeps a string, a char, a line comment and a doc comment", () => {
    const src = 'let s = "ctx"; let c = \'m\'; // ctx\n/// the msg\nlet msg = 2;\n';
    const { text } = renameInFile("a.rs", src);
    expect(text).toBe('let s = "ctx"; let c = \'m\'; // ctx\n/// the msg\nlet message = 2;\n');
  });

  test("keeps a raw string and a block comment", () => {
    const { text } = renameInFile("a.rs", 'let r = r#"opts"#; /* buf */ let x = buf;');
    expect(text).toBe('let r = r#"opts"#; /* buf */ let x = buffer;');
  });

  test("does not touch a longer identifier", () => {
    const { text } = renameInFile("a.rs", "let ctxs = previous + msgs;");
    expect(text).toBe("let ctxs = previous + msgs;");
  });
});

describe("attributes and macros", () => {
  test("keeps the words of a cfg attribute", () => {
    const src = '#[cfg(target_os = "macos")]\nfn ctx() -> u8 { ctx_value() }\n';
    const { text } = renameInFile("a.rs", src);
    expect(text).toBe('#[cfg(target_os = "macos")]\nfn context() -> u8 { ctx_value() }\n');
  });

  test("keeps an inner attribute and a nested bracket", () => {
    const { text } = renameInFile("a.rs", "#![allow(clippy::x)]\n#[doc = concat!(\"a\", \"b\")]\nlet buf = [1, 2];");
    expect(text).toBe("#![allow(clippy::x)]\n#[doc = concat!(\"a\", \"b\")]\nlet buffer = [1, 2];");
  });
});

describe("macros", () => {
  test("keeps the name of a macro call", () => {
    const { text } = renameInFile("a.rs", "if cfg!(unix) { let cfg = 1; }");
    expect(text).toBe("if cfg!(unix) { let config = 1; }");
  });
});

describe("macro syntax and module names", () => {
  test("keeps a macro variable and its fragment specifier", () => {
    const { text } = renameInFile("a.rs", "($ctx:expr, $ident:ident) => { let ctx = 1; };");
    expect(text).toBe("($ctx:expr, $ident:ident) => { let context = 1; };");
  });

  test("keeps a module name, which names a file", () => {
    const { text } = renameInFile("a.rs", "mod ident;\nlet ident = 2;");
    expect(text).toBe("mod ident;\nlet ident = 2;");
  });
});
