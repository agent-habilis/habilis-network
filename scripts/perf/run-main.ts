#!/usr/bin/env bun
// The main benchmark run, one step after the other, with the clock time of every step written to
// <out>/schedule.log: the pairs of HEAD against B-prime, then the CPU curve of HEAD, then the curve of B-prime (the
// last step is the one to drop when the time is short).
// It stops at the first step that fails (a stopped b4.ts says why in its own b4.log).
//
// usage: bun run-main.ts --head <binary> --bprime <binary> --out <folder> [--pairs 2] [--reps 3]
// Run it after `ulimit -n 10240`, under `caffeinate -dimsu`, on the quiet host.

import { appendFileSync, mkdirSync } from "node:fs";
import path from "node:path";

const flags = new Map<string, string>();
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 2) flags.set((argv[i] ?? "").replace(/^--/, ""), argv[i + 1] ?? "");
const need = (name: string) => flags.get(name) ?? (console.error(`missing --${name}`), process.exit(2));
const HEAD = need("head");
const BPRIME = need("bprime");
const OUT = need("out");
const PAIRS = flags.get("pairs") ?? "2";
const REPS = flags.get("reps") ?? "3";
const HERE = import.meta.dir;
mkdirSync(OUT, { recursive: true });

const log = (text: string) => {
  const line = `${new Date().toISOString()} ${text}`;
  console.log(line);
  appendFileSync(path.join(OUT, "schedule.log"), line + "\n");
};

const steps: { name: string; args: string[] }[] = [
  {
    name: "pairs",
    args: ["--plain", BPRIME, "--plain-loaded", "300", "--counters", HEAD, "--pairs", PAIRS, "--nodes", "16", "--out-root", path.join(OUT, "pairs")],
  },
  {
    name: "curve-head",
    args: ["--plain", HEAD, "--counters", HEAD, "--curve", "8,12,16,20", "--reps", REPS, "--out-root", path.join(OUT, "curve-head")],
  },
  {
    name: "curve-bprime",
    args: ["--plain", BPRIME, "--counters", BPRIME, "--curve", "8,12,16,20", "--reps", REPS, "--out-root", path.join(OUT, "curve-bprime")],
  },
];

log(`T0: main run starts (pairs ${PAIRS}, curve reps ${REPS})`);
for (const step of steps) {
  log(`step ${step.name} starts`);
  const proc = Bun.spawnSync([process.execPath, path.join(HERE, "b4.ts"), ...step.args], { stdout: "inherit", stderr: "inherit" });
  if (proc.exitCode !== 0) {
    log(`STOP: step ${step.name} failed (exit ${proc.exitCode}); see ${path.join(OUT, step.name)}/b4.log`);
    process.exit(1);
  }
  log(`step ${step.name} ended`);
}
log("main run done");
