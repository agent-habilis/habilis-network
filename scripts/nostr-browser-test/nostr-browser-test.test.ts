import { expect, test } from "bun:test";

import { isListening, skippedIn } from "./nostr-browser-test.ts";

test("a run that printed skipped: counts as skipped", () => {
  expect(skippedIn("running 1 test\nskipped: NOSTR_TEST_RELAY_URL was not set\n")).toBe(true);
});

test("a run that printed no skipped: line does not count as skipped", () => {
  expect(skippedIn("running 1 test\ntest result: ok. 1 passed\n")).toBe(false);
});

test("the relay is listening after its listening line", () => {
  expect(isListening("listening ws://127.0.0.1:7447/\n")).toBe(true);
});

test("the relay is not listening while its log is empty or has other text", () => {
  expect(isListening("")).toBe(false);
  expect(isListening("cannot listen on 127.0.0.1:7447: in use\n")).toBe(false);
});
