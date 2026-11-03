import { expect, test } from "bun:test";
import { chooseNodes, projectedSumMib } from "./choose-n.ts";

test("the projected sum follows the line through the two measured means", () => {
  // Mean per daemon: 29.0 MiB at 8 daemons and 53.6 MiB at 16. The slope is 24.6 / 8 = 3.075 MiB per daemon,
  // so the mean is 29.0 + 3.075 x (N - 8). At N = 20 it is 65.9 MiB, and the sum is 1318 MiB.
  expect(projectedSumMib(20)).toBeCloseTo(1318, 0);
  expect(projectedSumMib(8)).toBeCloseTo(232, 0);
});

test("the node count is the largest N whose projected sum is under 60% of the available memory", () => {
  // 2662 MiB x 0.6 = 1597 MiB. N = 22 projects 1585 MiB (under), N = 23 projects 1688 MiB (over).
  expect(chooseNodes(2662 * 1024 ** 2).nodes).toBe(22);
});

test("the node count stops at 64, and at 2 for a host with almost no memory", () => {
  expect(chooseNodes(1000 * 1024 ** 3).nodes).toBe(64);
  expect(chooseNodes(1).nodes).toBe(2);
});

test("the answer says why", () => {
  expect(chooseNodes(2662 * 1024 ** 2).why).toContain("1585");
});
