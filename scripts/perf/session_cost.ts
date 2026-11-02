#!/usr/bin/env bun
// The memory of one WebRTC session, as a slope over K sessions, read in one process.
//
// usage: bun scripts/perf/session_cost.ts <session_cost binary> <out file>
//
// Build the binary in release mode first:
//   cargo build --release -p habilis-network-iroh-webrtc-transport --features native --example session_cost
//
// Three rounds. Each round runs K = 0, 1, 8, 32 in turn, for both roles, so a drift of the host
// during the run is spread over all K: 24 runs. A run takes about 70 s (a throw-away session and
// its readings 12 s, the readings after the open 10 s, the hold 35 s, the readings after the close
// 10 s, and the negotiation of K sessions), so the 24 runs take about 28 min, plus the waits for
// the load. Before each run the script waits for load1 below 4 (at most 10 min).
//
// One JSON line per run goes to the out file. A run that fails leaves '# failed k=.. role=..'.
// The fit prints the slope per session, with its standard error and the noise floor of the
// K = 0 runs.

import { spawnSync } from "node:child_process";
import { accessSync, appendFileSync, constants, existsSync, readFileSync, writeFileSync } from "node:fs";

const [bin, out] = process.argv.slice(2);

if (!bin || !out || !existsSync(bin) || !isExecutable(bin)) {
  console.log("usage: session_cost.ts <session_cost binary> <out file>");
  process.exit(1);
}
writeFileSync(out, "");

function isExecutable(file: string): boolean {
  try {
    accessSync(file, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function capture(cmd: string): string {
  const proc = spawnSync("sh", ["-c", cmd], { encoding: "utf8" });
  return (proc.stdout ?? "").replace(/\n+$/, "");
}

const load1 = (): string => {
  const mac = capture("sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}' || true");
  return mac || capture("awk '{print $1}' /proc/loadavg");
};

async function waitLoad(): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt++) {
    const load = Number(load1());
    if (load < 4) return;
    await Bun.sleep(10_000);
  }
}

for (const round of [1, 2, 3]) {
  for (const k of [0, 1, 8, 32]) {
    for (const role of ["offerer", "answerer"]) {
      await waitLoad();
      const uptime = capture("uptime").replace(/.*averages*: /, "");
      process.stderr.write(`round ${round} k=${k} ${role} ${capture("date +%T")} load: ${uptime}\n`);
      const run = spawnSync(bin, ["measure", "--role", role, "--k", String(k), "--hold", "30"], {
        encoding: "utf8",
      });
      // The shell appended whatever the run printed, even when it failed. Then it marked the failure.
      appendFileSync(out, run.stdout ?? "");
      if (run.status !== 0) appendFileSync(out, `# failed k=${k} role=${role}\n`);
    }
  }
}

// `fit` reads the out file on its standard input. Its exit code is the script's exit code.
const fit = spawnSync(bin, ["fit"], { input: readFileSync(out), stdio: ["pipe", "inherit", "inherit"] });
process.exit(fit.status ?? 1);
