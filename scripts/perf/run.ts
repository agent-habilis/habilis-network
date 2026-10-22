#!/usr/bin/env bun
// One run of the mesh load driver: N nodes, one process each, on one host.
//
// usage: bun scripts/perf/run.ts <mesh_peer_load binary> <N> <steady secs> <outdir>
//
// The driver reads its settings from the environment (see the header of
// crates/habilis-network/examples/mesh_peer_load.rs): MESH_TRANSPORT,
// MESH_TRANSPORTS, MESH_TRAFFIC, MESH_MAX_PEERS, MESH_MAX_DIRECT,
// MESH_BLOCK_UDP_AFTER_SECS, MESH_UNDERLAY_LEG. `STAGGER` is the gap between two
// node starts, in seconds (default 0.3).
//
// The outdir gets n<i>.out and n<i>.err per node, summary.txt (the last census line
// of each node), host.log (one line per 10 s: load, process states, free memory),
// canary.log (every pause of the host over 0.5 s), probe.log, and `done` at the end.

import { spawnSync } from "node:child_process";
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const sleep = (seconds: number) => Bun.sleep(seconds * 1000);

// Run a shell command and return its stdout, without the trailing newline, as `$(...)` gives it.
function capture(cmd: string): string {
  const proc = spawnSync("sh", ["-c", cmd], { encoding: "utf8" });
  return (proc.stdout ?? "").replace(/\n+$/, "");
}

const [bin = "", nArg = "0", steadyArg = "0", outArg = ""] = process.argv.slice(2);
const N = Number(nArg);
const STEADY = Number(steadyArg);
const OUT = outArg;
mkdirSync(OUT, { recursive: true });
process.env.MESH_TRAFFIC = process.env.MESH_TRAFFIC || "on";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const STAGGER = Number(process.env.STAGGER || "0.3");

const canary = Bun.spawn([process.execPath, path.join(HERE, "canary.ts"), `${OUT}/canary.log`], {
  stdout: "ignore",
  stderr: "ignore",
});

const PIDFILE = `${OUT}/pids`;
writeFileSync(PIDFILE, "");
const pidsOf = (): [number, number][] =>
  readFileSync(PIDFILE, "utf8")
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => {
      const [i, pid] = line.trim().split(/\s+/);
      return [Number(i), Number(pid)] as [number, number];
    });
const appendPid = (i: number, pid: number) => appendFileSync(PIDFILE, `${i} ${pid}\n`);

// A node's output and error files. The child owns the descriptors, so we close ours at once.
function start(i: number, args: string[]): number {
  const out = openSync(`${OUT}/n${i}.out`, "w");
  const err = openSync(`${OUT}/n${i}.err`, "w");
  const child = Bun.spawn([bin, ...args], {
    env: { ...process.env, MESH_NODE_INDEX: String(i) },
    stdout: out,
    stderr: err,
  });
  closeSync(out);
  closeSync(err);
  return child.pid;
}

// The creator prints `mesh <id>` on its first lines. Wait for it.
let ID = "";
const creatorPid = start(1, []);
appendPid(1, creatorPid);
for (let attempt = 0; attempt < 60; attempt++) {
  const found = readFileSync(`${OUT}/n1.out`, "utf8")
    .split("\n")
    .find((line) => line.startsWith("mesh"));
  if (found !== undefined) {
    ID = found.replace(/^mesh */, "");
    if (ID) break;
  }
  await sleep(0.5);
}
if (!ID) {
  console.log("creator gave no id");
  canary.kill();
  process.exit(1);
}

// Host sampler: one line per 10 s in host.log, and a probe line for each node that went quiet.
let sampling = true;
let sampled = 0;
const hostLine = (): string => {
  const pids = pidsOf().map(([, pid]) => pid).join(",");
  const stamp = capture("date +%T");
  const load = capture("sysctl -n vm.loadavg | tr -d '{}'");
  const states = capture(
    `ps -o stat=,pcpu= -p ${pids} 2>/dev/null | awk '{s[substr($1,1,1)]++; c+=$2} END{for(k in s) printf "%s=%d ", k, s[k]; printf "pcpu_sum=%.0f", c}'`,
  );
  const builds = capture("pgrep -x rustc | wc -l | tr -d ' '");
  const vm = capture(
    `vm_stat | awk '/Pages free/{f=$3} /occupied by compressor/{c=$5} /Pageins/{pi=$2} /Pageouts/{po=$2} END{printf "free_pg=%s compressor_pg=%s pageins=%s pageouts=%s", f, c, pi, po}'`,
  );
  const swap = capture("sysctl -n vm.swapusage | awk '{print $6}'");
  return `${stamp} load=${load} ${states} builds=${builds} ${vm} swap=${swap}`;
};

const sampler = (async () => {
  while (sampling) {
    appendFileSync(`${OUT}/host.log`, hostLine() + "\n");
    const now = Date.now() / 1000;
    for (const [i, pid] of pidsOf()) {
      const errFile = `${OUT}/n${i}.err`;
      if (!existsSync(errFile)) continue;
      const age = Math.floor(now - statSync(errFile).mtimeMs / 1000);
      let alive = true;
      try {
        process.kill(pid, 0);
      } catch {
        alive = false;
      }
      if (age > 25 && alive) {
        const info = capture(`ps -o stat=,pcpu=,time=,rss= -p ${pid}`);
        appendFileSync(`${OUT}/probe.log`, `${capture("date +%T")} n${i} pid=${pid} silent ${age}s: ${info}\n`);
        const sampleFile = `${OUT}/sample-n${i}.txt`;
        if (sampled < 4 && !existsSync(sampleFile)) {
          capture(`sample ${pid} 3 -file ${sampleFile} > /dev/null 2>&1`);
          sampled++;
        }
      }
    }
    await sleep(10);
  }
})();

for (let i = 2; i <= N; i++) {
  appendPid(i, start(i, [ID]));
  await sleep(STAGGER);
}
await sleep(STEADY);

for (let i = 1; i <= N; i++) {
  const last = capture(`tail -n1 "${OUT}/n${i}.out" | tr -d '\\n'`);
  const census = capture(
    `grep 'mesh census' "${OUT}/n${i}.err" | tail -n1 | sed 's/\\x1b\\[[0-9;]*m//g' | grep -o 'roster_len=[0-9]*\\|link_len=[0-9]*\\|links_direct=[0-9]*\\|links_pending=[0-9]*\\|peak_resident_memory_mb=[0-9]*' | tr '\\n' ' '`,
  );
  appendFileSync(`${OUT}/summary.txt`, `n${i} ${last} | ${census}\n`);
}

// Stop the sampler and the canary, then each node by its own pid, then the stragglers by the same pids.
sampling = false;
await sampler;
canary.kill();
const killIt = (pid: number, signal: NodeJS.Signals) => {
  try {
    process.kill(pid, signal);
  } catch {
    // The process already exited.
  }
};
for (const [, pid] of pidsOf()) killIt(pid, "SIGTERM");
await sleep(2);
for (const [, pid] of pidsOf()) killIt(pid, "SIGKILL");
writeFileSync(`${OUT}/done`, "done\n");
