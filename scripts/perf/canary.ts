// Logs every wall-clock gap over 0.5 s in a loop that sleeps 0.1 s: a host or scheduler freeze shows up here.
// usage: bun scripts/perf/canary.ts <out file>

import { openSync, writeSync } from "node:fs";
import { fixed } from "./pyformat";

const clock = () => {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
};

const out = openSync(process.argv[2], "w");
let last = performance.now() / 1000;
while (true) {
  await Bun.sleep(100);
  const now = performance.now() / 1000;
  if (now - last > 0.5) {
    writeSync(out, `${clock()} gap_s=${fixed(now - last, 2)}\n`);
  }
  last = now;
}
