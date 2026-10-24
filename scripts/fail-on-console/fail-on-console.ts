import { afterAll, afterEach } from "bun:test";

// A throw inside the call to console.warn or console.error can be swallowed by
// the code under test, so the call is recorded and the hooks fail the run.
const methods = ["warn", "error"] as const;
let seen: string[] = [];

for (const method of methods) {
  const original = console[method].bind(console);
  console[method] = (...args: unknown[]) => {
    seen.push(`console.${method}: ${args.map(String).join(" ")}`);
    original(...args);
  };
}

// Nothing resets `seen` before a test starts: a call from module load or from
// beforeAll fails the first test, and a call that a concurrent test made is
// reported by whichever test ends next, never lost.
function failOnPendingCalls(subject: string) {
  if (seen.length > 0) {
    const calls = seen;
    seen = [];
    throw new Error(`${subject} logged to console.warn or console.error:\n${calls.join("\n")}`);
  }
}

afterEach(() => failOnPendingCalls("test"));

afterAll(() => failOnPendingCalls("suite"));
