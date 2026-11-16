// The expected values come from Python 3 (statistics.median, str.format, repr), run once.

import { expect, test } from "bun:test";
import { fixed, mean, median, show } from "./pyformat";

test("median of ints keeps the int type when the count is odd", () => {
  expect(show(median([1, 2, 3], false))).toBe("2");
});

test("median of an even count is a float, as Python gives", () => {
  expect(show(median([1, 2], false))).toBe("1.5");
  expect(show(median([1.0, 2.0], true))).toBe("1.5");
});

test("median of floats keeps the float type, and a whole float prints with .0", () => {
  expect(show(median([1.5, 2.0, 3.0], true))).toBe("2.0");
});

test("median of two floats matches Python's binary result", () => {
  expect(show(median([0.1, 0.2], true))).toBe("0.15000000000000002");
});

test("fixed rounds an exact tie to the even digit, as Python does", () => {
  expect(fixed(0.25, 1)).toBe("0.2");
  expect(fixed(2.5, 1)).toBe("2.5");
  expect(fixed(1.5, 1)).toBe("1.5");
});

test("fixed rounds a binary value below the tie down, as Python does", () => {
  expect(fixed(2.675, 2)).toBe("2.67");
  expect(fixed(0.35, 1)).toBe("0.3");
});

test("mean then fixed", () => {
  expect(fixed(mean([1, 2, 4]), 1)).toBe("2.3");
});

test("a float from 1e16 up prints in exponent form, as Python's repr does", () => {
  expect(show({ value: 1e16, float: true })).toBe("1e+16");
});

test("a small float prints in exponent form with two exponent digits", () => {
  expect(show({ value: 0.00001, float: true })).toBe("1e-05");
});

test("an int prints as it is", () => {
  expect(show({ value: 3, float: false })).toBe("3");
});
