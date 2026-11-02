import { expect, test } from "bun:test";
import { abGate, phaseGate, startGate } from "./gate.ts";

test("the start gate needs load1 at most 1.5 now and at most 2.0 in the 3 min before", () => {
  expect(startGate([1.2, 1.4, 1.3]).ok).toBe(true);
  expect(startGate([1.2, 1.4, 1.6]).ok).toBe(false); // the last sample is above 1.5
  expect(startGate([1.2, 2.1, 1.3]).ok).toBe(false); // the max is above 2.0
  expect(startGate([]).ok).toBe(false); // no sample is no proof
});

test("the phase gate needs a median at most 4.0 and a max at most 6.0", () => {
  // Sorted: 1, 2, 3, 5. The median of an even count is the upper middle value: 3.
  expect(phaseGate([3, 1, 5, 2]).ok).toBe(true);
  expect(phaseGate([3, 1, 5, 2]).median).toBe(3);
  expect(phaseGate([4.5, 4.5, 4.5]).ok).toBe(false); // median above 4.0
  expect(phaseGate([1, 1, 6.5]).ok).toBe(false); // max above 6.0
});

test("the A/B gate needs two phase medians within 25 percent", () => {
  expect(abGate(2.0, 2.5).ok).toBe(true); // 2.5 / 2.0 = 1.25
  expect(abGate(2.0, 2.6).ok).toBe(false); // 1.30
  expect(abGate(2.6, 2.0).ok).toBe(false); // the order does not matter
});
