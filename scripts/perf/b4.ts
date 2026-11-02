#!/usr/bin/env bun
// The interleaved pairs of the baseline benchmark: arm a (plain baseline, for CPU) and arm b (baseline with
// counters, for bytes and the ratio), each pair run in turn, the order swapped in every second pair.
//
// usage: bun scripts/perf/b4.ts --plain <binary> --counters <binary> [--plain-record <json>]
//          [--counters-record <json>] [--pairs 3] [--nodes 16] [--out-root ~/bench-results/b4]
//
// Every run waits for the start gate, then runs bench.ts with the same warm-up (the settle phase). A run whose
// phase breaks the phase gate is void and runs again, twice at most. After a pair, the A/B gate compares the
// load of the two idle1 phases; a pair that fails it runs once more. See README.md, "Load gates".
// Run it after `ulimit -n 10240`. The result goes to <out-root>/b4.json.

import { appendFileSync, readFileSync, renameSync, writeFileSync, mkdirSync } from "node:fs";
import { homedir, loadavg } from "node:os";
import path from "node:path";
import { AB_RATIO_MAX, PHASE_MAX, PHASE_MEDIAN_MAX, START_NOW_MAX, START_WINDOW_MAX, abGate, phaseGate, startGate } from "./gate.ts";

const flags = new Map<string, string>();
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 2) flags.set((argv[i] ?? "").replace(/^--/, ""), argv[i + 1] ?? "");
const need = (name: string) => flags.get(name) ?? (console.error(`missing --${name}`), process.exit(2));
const ARMS = {
  plain: { binary: need("plain"), record: flags.get("plain-record"), loaded: 0 },
  counters: { binary: need("counters"), record: flags.get("counters-record"), loaded: 300 },
};
const PAIRS = Number(flags.get("pairs") ?? 3);
const NODES = Number(flags.get("nodes") ?? 16);
const ROOT = flags.get("out-root") ?? path.join(homedir(), "bench-results", "b4");
mkdirSync(ROOT, { recursive: true });
const HERE = import.meta.dir;
const log = (text: string) => {
  const line = `${new Date().toISOString()} ${text}`;
  console.log(line);
  appendFileSync(`${ROOT}/b4.log`, line + "\n");
};

// The gate reads load1 every 10 s for 3 min. It waits up to 20 min for a quiet host.
async function waitForStart(): Promise<void> {
  const window: number[] = [];
  for (let waited = 0; waited < 20 * 60; waited += 10) {
    window.push(loadavg()[0] ?? 0);
    if (window.length > 18) window.shift();
    if (window.length === 18 && startGate(window).ok) return;
    await Bun.sleep(10_000);
  }
  log(`start gate: the host did not settle in 20 min, last load1 ${window.at(-1)}`);
  process.exit(1);
}

type Run = { arm: string; pair: number; folder: string; phases: Record<string, { median: number; max: number; ok: boolean }>; void: boolean };

async function runOnce(arm: "plain" | "counters", pair: number, attempt: number): Promise<Run> {
  await waitForStart();
  const spec = ARMS[arm];
  const label = `b4-${arm}-p${pair}${attempt ? `-r${attempt}` : ""}`;
  const args = [
    process.execPath, `${HERE}/bench.ts`, spec.binary, label, "--nodes", String(NODES), "--stagger", "0.5", "--settle", "300",
    "--idle", "240", "--loaded", String(spec.loaded), "--min-avail-gib", "1", "--out-root", ROOT,
    ...(spec.record ? ["--record", spec.record] : []),
  ];
  log(`run ${label}: ${args.slice(2).join(" ")}`);
  const proc = Bun.spawn(args, { stdout: "pipe", stderr: "pipe" });
  const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  const code = await proc.exited;
  const folder = out.match(/run folder: (\S+)/)?.[1] ?? "";
  if (code !== 0 || !folder) {
    log(`run ${label} failed (exit ${code}): ${err.trim().slice(-300)}`);
    process.exit(1);
  }
  const result = JSON.parse(readFileSync(`${folder}/result.json`, "utf8"));
  const host = readFileSync(`${folder}/host.jsonl`, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const phases: Run["phases"] = {};
  for (const phase of result.phases as { name: string; start_ms: number; end_ms: number }[]) {
    const load1s = host.filter((s) => s.ts >= phase.start_ms && s.ts <= phase.end_ms).map((s) => s.load1 as number);
    if (load1s.length === 0) continue;
    phases[phase.name] = phaseGate(load1s);
  }
  const summary = Bun.spawnSync([process.execPath, `${HERE}/summarize.ts`, folder]);
  writeFileSync(`${folder}/summary.txt`, summary.stdout.toString() + summary.stderr.toString());
  const bad = Object.entries(phases).filter(([, gate]) => !gate.ok).map(([name]) => name);
  log(`run ${label} done: ${Object.entries(phases).map(([n, g]) => `${n} median ${g.median.toFixed(2)} max ${g.max.toFixed(2)}`).join("; ")}${bad.length ? `; VOID (${bad.join(",")})` : ""}`);
  if (bad.length > 0) return { arm, pair, folder: markVoid(folder), phases, void: true };
  return { arm, pair, folder, phases, void: false };
}

// A void run stays on disk under a name that says so.
function markVoid(folder: string): string {
  const named = path.join(path.dirname(folder), `void-${path.basename(folder)}`);
  renameSync(folder, named);
  return named;
}

async function runValid(arm: "plain" | "counters", pair: number): Promise<Run> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const run = await runOnce(arm, pair, attempt);
    if (!run.void) return run;
  }
  log(`pair ${pair} ${arm}: 3 void runs, the host is too loaded; stop`);
  process.exit(1);
}

// The first start gate (load1 1.5) never opened: the host idles at 1.5 to 1.76 with none of our daemons.
const gates = {
  start_now_max: START_NOW_MAX,
  start_window_max: START_WINDOW_MAX,
  phase_median_max: PHASE_MEDIAN_MAX,
  phase_max: PHASE_MAX,
  ab_ratio_max: AB_RATIO_MAX,
  reason: "widened by the leader on 2026-11-02 after the first start gate (1.5) failed on an idle host",
};
const kept: Run[] = [];
const pairs: { pair: number; ab: ReturnType<typeof abGate>; runs: string[] }[] = [];
for (let pair = 1; pair <= PAIRS; pair++) {
  const order: ("plain" | "counters")[] = pair % 2 === 1 ? ["plain", "counters"] : ["counters", "plain"];
  for (let round = 0; round < 2; round++) {
    const done: Run[] = [];
    for (const arm of order) done.push(await runValid(arm, pair));
    const ab = abGate(done[0]!.phases.idle1!.median, done[1]!.phases.idle1!.median);
    log(`pair ${pair} A/B idle1 load1 ratio ${ab.ratio.toFixed(2)} ${ab.ok ? "ok" : "FAILED"}`);
    if (ab.ok || round === 1) {
      kept.push(...done);
      pairs.push({ pair, ab, runs: done.map((run) => run.folder) });
      break;
    }
    for (const run of done) run.folder = markVoid(run.folder);
  }
  writeFileSync(`${ROOT}/b4.json`, JSON.stringify({ nodes: NODES, gates, pairs, kept }, null, 2));
}
log("all pairs done");
