// Tests of scripts/style-check/lower-rows.ts: it lowers and removes rows, and never raises one.
import { expect, test } from "bun:test";
import { lowerRows } from "./lower-rows.ts";

const allow = "# header\nlong_chain|crates/a/src/lib.rs|5|kept: reason\nlong_chain|crates/b/src/lib.rs|2|kept: other";

test("lower-rows: a lowered count is written", () => {
  const out = "style-check: [long_chain] crates/a/src/lib.rs: 3 matching line(s), 5 allowed. Lower the count.";
  expect(lowerRows(allow, out).text).toContain("long_chain|crates/a/src/lib.rs|3|kept: reason");
});
test("lower-rows: a row at zero is removed", () => {
  const out = "style-check: [long_chain] crates/b/src/lib.rs: 0 matching line(s), 2 allowed. Lower the count.";
  expect(lowerRows(allow, out).text).not.toContain("crates/b/src/lib.rs");
});
test("lower-rows: a raised count is reported and not written", () => {
  const out = "style-check: [long_chain] crates/a/src/lib.rs: 9 matching line(s), 5 allowed. Raise.";
  const result = lowerRows(allow, out);
  expect(result.raised).toEqual(["long_chain crates/a/src/lib.rs"]);
  expect(result.text).toContain("long_chain|crates/a/src/lib.rs|5|kept: reason");
});
