import { afterEach, beforeEach } from "bun:test";

// A throw inside the call to console.warn or console.error can be swallowed by
// the code under test, so the call is recorded and the hook fails the test.
const methods = ["warn", "error"] as const;
let seen: string[] = [];

for (const method of methods) {
  const original = console[method].bind(console);
  console[method] = (...args: unknown[]) => {
    seen.push(`console.${method}: ${args.map(String).join(" ")}`);
    original(...args);
  };
}

beforeEach(() => {
  seen = [];
});

afterEach(() => {
  if (seen.length > 0) {
    const calls = seen;
    seen = [];
    throw new Error(`test logged to console.warn or console.error:\n${calls.join("\n")}`);
  }
});
