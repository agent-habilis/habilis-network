// The marginal memory of the underlay WebRTC sessions, from run folders of run.ts.
//
// usage: bun scripts/perf/underlay_report.ts <run dir> [<run dir> ...]
//
// Run the driver with MESH_BLOCK_UDP_AFTER_SECS=60 (phase 2 starts when a node takes IP
// away from every connection of its process), the transport list with relay, and traffic
// on. Two cells: the underlay leg on, and MESH_UNDERLAY_LEG=off as the control. Per node
// the report reads two lines of n<i>.out:
//
// - phase 1 end: the last line before the block.
// - phase 2: the first line at least SECS_INTO_PHASE_2 (180) seconds after the block.
//
// Per run: the median and the maximum, over nodes, of the delta of the current resident
// memory (MB) between the two readings, and the mean number of underlay sessions per
// node at the second reading. The marginal memory of one session is
// (delta with the leg on - delta with the leg off) / mean underlay sessions: compare
// the lines of the two cells by hand, three runs each.

import { readdirSync, readFileSync } from "node:fs";
import { fixed, mean, median, show } from "./pyformat/pyformat";

const SECS_INTO_PHASE_2 = 180;
const LINE = /^t (\d+) phase (\d) peers (\d+) links (\d+) sessions (\d+) underlay (\d+) rss_mb (\d+)/;

type Reading = { t: number; phase: number; underlay: number; rss: number };

function readings(file: string): Reading[] {
  const rows: Reading[] = [];
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const found = LINE.exec(line);
    if (found) {
      const [t = 0, phase = 0, , , , underlay = 0, rss = 0] = found.slice(1).map(Number);
      rows.push({ t, phase, underlay, rss });
    }
  }
  return rows;
}

function report(run: string): string {
  const deltas: number[] = [];
  const underlays: number[] = [];
  const files = readdirSync(run)
    .filter((f) => /^n.*\.out$/.test(f))
    .sort()
    .map((f) => `${run}/${f}`);
  for (const file of files) {
    const rows = readings(file);
    const phase1 = rows.filter((row) => row.phase === 1);
    const phase2 = rows.filter((row) => row.phase === 2);
    if (phase1.length === 0 || phase2.length === 0) continue;
    const switchAt = phase2[0]?.t ?? 0;
    const late = phase2.filter((row) => row.t >= switchAt + SECS_INTO_PHASE_2);
    const first = late[0];
    const last = phase1[phase1.length - 1];
    if (!first || !last) continue;
    deltas.push(first.rss - last.rss);
    underlays.push(first.underlay);
  }
  if (deltas.length === 0) return `${run}: no node has both readings`;
  const name = run.replace(/\/+$/, "").split("/").pop() ?? run;
  return (
    `${name.padEnd(12)} nodes=${deltas.length} ` +
    `delta_rss_mb median=${show(median(deltas, false))} max=${Math.max(...deltas)} ` +
    `| underlay_sessions mean=${fixed(mean(underlays), 1)}`
  );
}

for (const run of process.argv.slice(2).map((r) => r.replace(/\/+$/, ""))) {
  console.log(report(run));
}
