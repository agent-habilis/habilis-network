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
// - census_lines: the census lines of all nodes. Divide a total below by it for a mean per node
//   and interval (10 s).
// - cpu_user_ms / cpu_sys_ms / wakeups / dup / fresh / fr_asks / fr_retries / answers /
//   frames_uni / frames_bc / rejected: the sums of the `cpu_user_ms`, `cpu_sys_ms`, `idle_wakeups`,
//   `idle_duplicates`, `idle_fresh`, `idle_fr_asks`, `idle_fr_retries`, `idle_state_answers`,
//   `idle_state_frames_unicast`, `idle_state_frames_broadcast` and `idle_state_rejected` deltas of
//   every census line.
// - ext_<arm>: the sums of the `idle_ext_<arm>` deltas, the wakes of each arm that is not a timer.
//   Only the arms that woke.
// - ahead_max: the largest `idle_ahead_peers` gauge of any census line.
// - node_load_max: the largest `load_1m` that a node logged.
// - mem_med / mem_max: peak resident memory of the nodes, in MB.
// - load1 median and max, from host.log; canary pauses of the host over 0.5 s.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { median, show } from "./pyformat/pyformat";

const clean = (text: string) => text.replace(/\x1b\[[0-9;]*m/g, "");

const numbers = (text: string, pattern: RegExp): number[] =>
  [...text.matchAll(new RegExp(pattern.source, "g"))].map((m) => Number(m[1]));

const sum = (values: number[]): number => values.reduce((a, b) => a + b, 0);

// The census fields that are per-interval deltas, summed over a run: the summary name, then the
// census field.
const TOTALS: [string, string][] = [
  ["cpu_user_ms", "cpu_user_ms"],
  ["cpu_sys_ms", "cpu_sys_ms"],
  ["wakeups", "idle_wakeups"],
  ["dup", "idle_duplicates"],
  ["fresh", "idle_fresh"],
  ["fr_asks", "idle_fr_asks"],
  ["fr_retries", "idle_fr_retries"],
  ["answers", "idle_state_answers"],
  ["frames_uni", "idle_state_frames_unicast"],
  ["frames_bc", "idle_state_frames_broadcast"],
  ["rejected", "idle_state_rejected"],
];

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
  let censusLines = 0;
  const totals = new Map<string, number>(TOTALS.map(([name]) => [name, 0]));
  const ext = new Map<string, number>();
  const ahead: number[] = [];
  const nodeLoads: number[] = [];
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
    censusLines += numbers(text, /idle_wakeups=(\d+)/).length;
    for (const [name, field] of TOTALS) {
      totals.set(name, (totals.get(name) ?? 0) + sum(numbers(text, new RegExp(`\\b${field}=(\\d+)`))));
    }
    for (const arm of text.matchAll(/\bidle_ext_(\w+?)=(\d+)/g)) {
      ext.set(arm[1] ?? "", (ext.get(arm[1] ?? "") ?? 0) + Number(arm[2]));
    }
    ahead.push(...numbers(text, /\bidle_ahead_peers=(\d+)/));
    nodeLoads.push(...numbers(text, /\bload_1m=([0-9.]+)/));
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
    gaps = [...readFileSync(`${run}/canary.log`, "utf8").matchAll(/gap_s=([0-9.]+)/g)].map((m) => m[1] ?? "");
  }

  const rosterMed = roster.length ? show(median(roster, false)) : "-";
  const rosterMin = roster.length ? String(Math.min(...roster)) : "-";
  const memMed = mem.length ? show(median(mem, false)) : "-";
  const memMax = mem.length ? String(Math.max(...mem)) : "-";
  const loadMed = loads.length ? show(median(loads, true)) : "-";
  const loadMax = loads.length ? show({ value: Math.max(...loads), float: true }) : "-";
  const maxOf = (values: number[]) => (values.length ? Math.max(...values) : 0);
  const totalsText = [...totals].map(([name, value]) => `${name}=${value}`).join(" ");
  const extText = [...ext]
    .filter(([, value]) => value > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, value]) => `ext_${name}=${value}`)
    .join(" ");

  return (
    `${path.basename(run).padEnd(12)} full=${roster.filter((x) => x >= n - 1).length}/${n} ` +
    `isolated=${roster.filter((x) => x <= 1).length} roster_med=${rosterMed} ` +
    `min=${rosterMin} | stalls=${stalls.length} longest_s=${stalls.length ? Math.floor(maxOf(stalls) / 1000) : 0} ` +
    `| up=${up} down=${down} | drop_nodes=${drops.size} worst_drop=${maxOf([...drops.values()])} ` +
    `| disc_nodes=${discs.size} worst_disc=${maxOf([...discs.values()])} ` +
    `| resent=${resent} resend_dropped=${resendDropped} ` +
    `| census_lines=${censusLines} ${totalsText} ahead_max=${maxOf(ahead)} ` +
    `node_load_max=${show({ value: maxOf(nodeLoads), float: true })} | ${extText} ` +
    `| mem_med=${memMed} mem_max=${memMax} ` +
    `| load1 median=${loadMed} max=${loadMax} ` +
    `| canary_pauses=${gaps.length}`
  );
}

for (const run of process.argv.slice(2).map((r) => r.replace(/\/+$/, ""))) {
  console.log(summarize(run));
}
