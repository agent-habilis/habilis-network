// Re-dials of a run of mesh_peer_load: bun scripts/perf/redial_report.ts <run folder> [<run folder> ...]
//
// Reads the last per-second line of every node (n<i>.out). `qclose`, `pclose` and `sclose` count the
// closes of every QUIC connection (the gossip links too), of the pooled unicast connections that a
// send used, and of WebRTC sessions; `qredial`, `predial` and `sredial` the closes that were
// followed by a connection to the same peer within 300 s. Prints, for each kind, the closes and
// re-dials per node per hour and the share of closes that were followed by a re-dial.

import { readdirSync, readFileSync } from "node:fs";
import { fixed, median } from "./pyformat";

const LINE =
  /^t (\d+) .* qclose (\d+) qredial (\d+) sclose (\d+) sredial (\d+)(?: pclose (\d+) predial (\d+))?/;

type Row = number[];

function lastLine(file: string): Row | undefined {
  let found: Row | undefined;
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const match = LINE.exec(line);
    if (match) {
      found = Array.from({ length: 7 }, (_, i) => Number(match[i + 1] ?? 0));
    }
  }
  return found;
}

function report(folder: string): void {
  const files = readdirSync(folder)
    .filter((f) => /^n.*\.out$/.test(f))
    .sort()
    .map((f) => `${folder}/${f}`);
  const rows = files.map(lastLine).filter((row): row is Row => row !== undefined);
  if (rows.length === 0) {
    console.log(folder, "no lines");
    return;
  }
  const hours = Math.max(...rows.map((row) => row[0])) / 3600;
  const nodes = rows.length;
  const name = folder.replace(/\/+$/, "").split("/").pop() ?? folder;
  for (const [kind, closes, redials] of [
    ["quic", 1, 2],
    ["pool", 5, 6],
    ["session", 3, 4],
  ] as const) {
    const totalCloses = rows.reduce((sum, row) => sum + row[closes], 0);
    const totalRedials = rows.reduce((sum, row) => sum + row[redials], 0);
    const share = totalCloses ? totalRedials / totalCloses : 0.0;
    const perNode = rows.map((row) => row[redials] / hours);
    console.log(
      `${name.padEnd(12)} ${kind.padEnd(8)} nodes=${nodes} ` +
        `closes/node/h=${fixed(totalCloses / nodes / hours, 1)} ` +
        `redials/node/h=${fixed(totalRedials / nodes / hours, 1)} ` +
        `(median ${fixed(median(perNode, true).value, 1)}, max ${fixed(Math.max(...perNode), 1)}) ` +
        `share of closes followed by a redial=${fixed(share, 2)}`,
    );
  }
}

for (const folder of process.argv.slice(2)) {
  report(folder);
}
