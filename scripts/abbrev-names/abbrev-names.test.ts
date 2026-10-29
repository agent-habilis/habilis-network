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
