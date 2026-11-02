import { describe, expect, test } from "bun:test";
import { lowercaseStarts, paragraphs, scan } from "./doc-sentence.ts";

describe("doc sentence case", () => {
  test("a paragraph start in lowercase is a hit", () => {
    expect(lowercaseStarts("encodes the frame. Then it sends.")).toEqual(["encodes"]);
  });

  test("a capital, a digit, a code span and an abbreviation are not hits", () => {
    expect(lowercaseStarts("Encodes the frame. `send` it. 3 frames. Use e.g. the default.")).toEqual([]);
  });

  test("code spans and link text are blanked before the check", () => {
    expect(lowercaseStarts("Call [`encode_frame`] first. [`Frame`] is next.")).toEqual([]);
  });

  test("a fenced block is not prose, and a blank doc line breaks a paragraph", () => {
    const src = ["/// Sends one frame.", "///", "/// ```", "/// send(frame)", "/// ```", "/// ok"].join("\n");
    expect(paragraphs(src).map(([, text]) => text)).toEqual(["Sends one frame.", "ok"]);
    expect(scan(src)).toEqual([[6, "ok"]]);
  });

  test("a line that continues a sentence is not a sentence start", () => {
    const src = ["//! The frame is sent", "//! over the wire."].join("\n");
    expect(scan(src)).toEqual([]);
  });
});
