// One line of metrics per run folder of run.ts.
//
// usage: bun scripts/perf/summarize.ts <run dir> [<run dir> ...]
//
// Reads summary.txt (the last census line of each node), the n<i>.err logs, host.log
// and canary.log. The fields:
//
// - full / isolated / roster_med / min: how many nodes hold the whole roster, how many
//   hold none, and the median and the least roster, out of N nodes.
// - stalls / longest_s: `maintenance timer stalled` warnings, and the longest gap.
// - up / down: `gossip neighbor up` and `gossip neighbor down` lines of all nodes, the
//   link churn of the run.
// - drop_nodes / worst_drop: nodes that logged a dropped data message (the send queue of
//   a connection was full), and the worst count a node logged (a lower bound: the log
//   line appears at each power of two).
// - disc_nodes / worst_disc: the same for `send_overflow_disconnects`.
// - resent / resend_dropped: the sum of the `idle_resent` and `idle_resend_dropped`
//   deltas of every census line, which is the total over the run.
// - mem_med / mem_max: peak resident memory of the nodes, in MB.
// - load1 median and max, from host.log; canary pauses of the host over 0.5 s.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { median, show } from "./pyformat";

const clean = (text: string) => text.replace(/\x1b\[[0-9;]*m/g, "");

const numbers = (text: string, pattern: RegExp): number[] =>
  [...text.matchAll(new RegExp(pattern.source, "g"))].map((m) => Number(m[1]));

// Python's str.split("\n") in a line loop: a final newline does not make an extra line.
const lines = (text: string): string[] => {
  const parts = text.split("\n");
  if (parts.length > 0 && parts[parts.length - 1] === "") parts.pop();
  return parts;
};

function summarize(run: string): string {
  const rows = lines(readFileSync(`${run}/summary.txt`, "utf8")).map(
    (line) => Object.fromEntries([...line.matchAll(/(\w+)=(\d+)/g)].map((m) => [m[1], m[2]])),
  );
  const census = rows.filter((row) => "roster_len" in row);
  const roster = census.map((row) => Number(row.roster_len));
  const mem = census
    .filter((row) => "peak_resident_memory_mb" in row)
    .map((row) => Number(row.peak_resident_memory_mb));
  const n = rows.length;

  const stalls: number[] = [];
  const drops = new Map<string, number>();
  const discs = new Map<string, number>();
  let up = 0;
  let down = 0;
  let resent = 0;
  let resendDropped = 0;
  for (const file of readdirSync(run).filter((f) => /^n.*\.err$/.test(f))) {
    const text = clean(readFileSync(`${run}/${file}`, "utf8"));
    stalls.push(...numbers(text, /timer stalled[^\n]*?mono_gap_ms=(\d+)/));
    const found = numbers(text, /dropped a data message[^\n]*?dropped=(\d+)/);
    if (found.length > 0) drops.set(file, Math.max(...found));
    const refused = numbers(text, /send queue of the peer refused[^\n]*?disconnects=(\d+)/);
    if (refused.length > 0) discs.set(file, Math.max(...refused));
    up += text.split("gossip neighbor up").length - 1;
    down += text.split("gossip neighbor down").length - 1;
    resent += numbers(text, /idle_resent=(\d+)/).reduce((a, b) => a + b, 0);
    resendDropped += numbers(text, /idle_resend_dropped=(\d+)/).reduce((a, b) => a + b, 0);
  }

  const loads: number[] = [];
  if (existsSync(`${run}/host.log`)) {
    for (const line of lines(readFileSync(`${run}/host.log`, "utf8"))) {
      const found = line.match(/load=\s*([0-9.]+)/);
      if (found) loads.push(Number(found[1]));
    }
  }
  let gaps: string[] = [];
  if (existsSync(`${run}/canary.log`)) {
    gaps = [...readFileSync(`${run}/canary.log`, "utf8").matchAll(/gap_s=([0-9.]+)/g)].map((m) => m[1]);
  }

  const rosterMed = roster.length ? show(median(roster, false)) : "-";
  const rosterMin = roster.length ? String(Math.min(...roster)) : "-";
  const memMed = mem.length ? show(median(mem, false)) : "-";
  const memMax = mem.length ? String(Math.max(...mem)) : "-";
  const loadMed = loads.length ? show(median(loads, true)) : "-";
  const loadMax = loads.length ? show({ value: Math.max(...loads), float: true }) : "-";
  const maxOf = (values: number[]) => (values.length ? Math.max(...values) : 0);

  return (
    `${path.basename(run).padEnd(12)} full=${roster.filter((x) => x >= n - 1).length}/${n} ` +
    `isolated=${roster.filter((x) => x <= 1).length} roster_med=${rosterMed} ` +
    `min=${rosterMin} | stalls=${stalls.length} longest_s=${stalls.length ? Math.floor(maxOf(stalls) / 1000) : 0} ` +
    `| up=${up} down=${down} | drop_nodes=${drops.size} worst_drop=${maxOf([...drops.values()])} ` +
    `| disc_nodes=${discs.size} worst_disc=${maxOf([...discs.values()])} ` +
    `| resent=${resent} resend_dropped=${resendDropped} ` +
    `| mem_med=${memMed} mem_max=${memMax} ` +
    `| load1 median=${loadMed} max=${loadMax} ` +
    `| canary_pauses=${gaps.length}`
  );
}

for (const run of process.argv.slice(2).map((r) => r.replace(/\/+$/, ""))) {
  console.log(summarize(run));
}
