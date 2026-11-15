import { expect, test } from "bun:test";
import { fairGate, phaseGate, startGate, waitForStart, waitForStartWindow } from "./gate.ts";

test("the start gate needs load1 at most 2.0 now and at most 2.5 in the 3 min before", () => {
  expect(startGate([1.2, 1.4, 1.3]).ok).toBe(true);
  expect(startGate([1.7, 2.4, 1.9]).ok).toBe(true); // an idle host of 1.5 to 1.76 starts
  expect(startGate([1.2, 1.4, 2.1]).ok).toBe(false); // the last sample is above 2.0
  expect(startGate([1.2, 2.6, 1.3]).ok).toBe(false); // the max is above 2.5
  expect(startGate([]).ok).toBe(false); // no sample is no proof
});

test("the phase gate needs a median at most 4.0 and a max at most 6.0", () => {
  // Sorted: 1, 2, 3, 5. The median of an even count is the upper middle value: 3.
  expect(phaseGate([3, 1, 5, 2]).ok).toBe(true);
  expect(phaseGate([3, 1, 5, 2]).median).toBe(3);
  expect(phaseGate([4.5, 4.5, 4.5]).ok).toBe(false); // median above 4.0
  expect(phaseGate([1, 1, 6.5]).ok).toBe(false); // max above 6.0
});

const QUIET = [1.4, 1.5, 1.4, 1.5, 1.4, 1.5];

test("the fairness gate lets a pair pass when both arms start from the same host load, whatever load the arms make", () => {
  // The idle load of the arms is no input: an arm that costs less load is the result, not a fault of the pair.
  expect(fairGate(QUIET, [1.5, 1.4, 1.5, 1.4, 1.5, 1.4])).toEqual({ ok: true, ratio: 1 });
  expect(fairGate([1.4, 1.5, 1.4], [1.8, 1.9, 1.8]).ok).toBe(true); // 1.8 / 1.4 = 1.29, within 35 percent
});

test("the fairness gate fails a pair whose arms start from different host load", () => {
  expect(fairGate([1.2, 1.2, 1.2], [1.9, 1.9, 1.9]).ok).toBe(false); // 1.58 is above 1.35
  expect(fairGate([1.9, 1.9, 1.9], [1.2, 1.2, 1.2]).ok).toBe(false); // the order does not matter
});

test("the fairness gate fails a pair when either start window fails the start gate", () => {
  expect(fairGate([1.2, 2.6, 1.3], [1.2, 2.6, 1.3]).ok).toBe(false); // equal, but the max is above 2.5
  expect(fairGate([], QUIET).ok).toBe(false); // no sample is no proof
});

test("the start window of a wait is the last 18 samples, oldest first", async () => {
  let next = 0;
  const read = () => 1 + (next++ % 2 ? 0.1 : 0);
  const waited = await waitForStartWindow({ read, stepMs: 0, maxSteps: 40 });
  expect(waited.ok).toBe(true);
  expect(waited.window).toHaveLength(18);
  expect(waited.window.at(-1)).toBe(waited.last);
});

test("waiting for the start gate returns when 18 samples are quiet, and gives the last load1 when the host never settles", async () => {
  expect(await waitForStart({ read: () => 1.2, stepMs: 0, maxSteps: 40 })).toEqual({ ok: true, last: 1.2 });
  expect(await waitForStart({ read: () => 5, stepMs: 0, maxSteps: 40 })).toEqual({ ok: false, last: 5 });
  // 17 quiet samples are not a window: the gate needs 18.
  expect(await waitForStart({ read: () => 1.2, stepMs: 0, maxSteps: 17 })).toEqual({ ok: false, last: 1.2 });
});
