#!/usr/bin/env bun
// A series of runs, one after the other, each after the host has calmed down.
//
// usage: bun scripts/perf/series.ts <binary> <outroot> <steady secs> <N:k> [<N:k> ...]
//
// `N:k` is a run of N nodes, numbered k. The outdir of a run is <outroot>/N<N>-<k>.
// Before each run it waits (at most 15 min) until the 1 min load is below
// `LOAD_BELOW` (default 5), and logs the uptime of every start and end in
// <outroot>/drive.log. Pass the driver settings as environment variables.

import { spawnSync } from "node:child_process";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const [bin, root, steadyArg, ...specs] = process.argv.slice(2);
const STEADY = steadyArg;
const HERE = path.dirname(fileURLToPath(import.meta.url));
const LOAD_BELOW = Number(process.env.LOAD_BELOW || "5");

// The same text `$(...)` gives in the shell: the output with its trailing newlines removed.
function capture(cmd: string): string {
  const proc = spawnSync("sh", ["-c", cmd], { encoding: "utf8" });
  return (proc.stdout ?? "").replace(/\n+$/, "");
}

const uptime = () => capture("uptime").replace(/.*averages*: /, "");

mkdirSync(root, { recursive: true });
const drive = path.join(root, "drive.log");

for (const spec of specs) {
  const [N, k] = spec.split(":");
  let waited = 0;
  while (true) {
    const load = Number(capture("sysctl -n vm.loadavg | awk '{print $2}'"));
    if (load < LOAD_BELOW) break;
    if (waited >= 900) break;
    await Bun.sleep(20_000);
    waited += 20;
  }
  appendFileSync(drive, `${capture("date +%T")} N${N}-${k} start uptime=${uptime()} waited=${waited}s\n`);
  spawnSync(process.execPath, [path.join(HERE, "run.ts"), bin, N, STEADY, path.join(root, `N${N}-${k}`)], {
    stdio: "ignore",
  });
  appendFileSync(drive, `${capture("date +%T")} N${N}-${k} end uptime=${uptime()}\n`);
  await Bun.sleep(30_000);
}
writeFileSync(path.join(root, "finished"), "finished\n");
