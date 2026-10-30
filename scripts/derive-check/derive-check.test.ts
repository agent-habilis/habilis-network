import { describe, expect, test } from "bun:test";
import { findViolations } from "./derive-check";

const file = (text: string) => ({ path: "crates/x/src/lib.rs", text });

describe("R12: a pub struct with all-pub fields implements Debug", () => {
  test("flags a struct with all-pub fields and no Debug", () => {
    const v = findViolations([file("#[derive(Clone)]\npub struct Open {\n    pub a: u8,\n    pub b: String,\n}\n")]);
    expect(v.map((x) => [x.name, x.rule])).toEqual([["Open", "R12"]]);
  });
  test("passes when the derive is on a multi-line attribute", () => {
    const v = findViolations([file("#[derive(\n    Clone, Debug,\n)]\npub struct Open {\n    pub a: u8,\n}\n")]);
    expect(v).toEqual([]);
  });
  test("passes when Debug is written by hand", () => {
    const v = findViolations([file("pub struct Open {\n    pub a: u8,\n}\nimpl std::fmt::Debug for Open {}\n")]);
    expect(v).toEqual([]);
  });
  test("ignores a struct with a private field", () => {
    const v = findViolations([file("pub struct Guarded {\n    pub a: u8,\n    secret: u8,\n}\n")]);
    expect(v).toEqual([]);
  });
});

describe("R13: an error type with Copy-able fields implements Copy", () => {
  test("flags an error enum of plain values with no Copy", () => {
    const v = findViolations([file("#[derive(Debug)]\npub enum LinkError {\n    Down(u32),\n    Gone,\n}\n")]);
    expect(v.map((x) => [x.name, x.rule])).toEqual([["LinkError", "R13"]]);
  });
  test("passes when the error holds a String", () => {
    const v = findViolations([file("#[derive(Debug)]\npub enum LinkError {\n    Down(String),\n}\n")]);
    expect(v).toEqual([]);
  });
  test("passes when Copy is derived", () => {
    const v = findViolations([file("#[derive(Debug, Clone, Copy)]\npub enum LinkError {\n    Down(u32),\n}\n")]);
    expect(v).toEqual([]);
  });
});
