// A run of 2 nodes with known bytes. Each expected value is a hand calculation, written
// beside the fixture it comes from.

import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const SUMMARIZE = path.join(import.meta.dir, "summarize.ts");
const T0 = Date.parse("2026-01-01T00:00:00Z");

const censusLine = (offsetSecs: number, fields: Record<string, number>): string =>
  `${new Date(T0 + offsetSecs * 1000).toISOString()}  INFO habilis_network::lifecycle: mesh census roster_len=2 ` +
  Object.entries(fields)
    .map(([key, value]) => `${key}=${value}`)
    .join(" ");

// Phases of 60 s: idle1 0-60, loaded 60-120, idle2 120-180.
function fixture(wireInLoaded: [number, number]): string {
  const dir = mkdtempSync(path.join(tmpdir(), "summarize-"));
  const nodeLog = (idle1: number, loaded: number, netLoaded: number, idle2: number) =>
    [
      censusLine(30, { idle_wire_in: idle1, idle_net_recv_ip: idle1 }),
      censusLine(90, { idle_wire_in: loaded, idle_net_recv_ip: netLoaded }),
      censusLine(150, { idle_wire_in: idle2, idle_net_recv_ip: idle2 }),
    ].join("\n") + "\n";
  writeFileSync(`${dir}/n1.err`, nodeLog(3000, wireInLoaded[0], 1600, 6000));
  writeFileSync(`${dir}/n2.err`, nodeLog(3000, wireInLoaded[1], 1000, 6000));
  writeFileSync(
    `${dir}/result.json`,
    JSON.stringify({
      phases: [
        { name: "idle1", start_ms: T0, end_ms: T0 + 60_000 },
        { name: "loaded", start_ms: T0 + 60_000, end_ms: T0 + 120_000 },
        { name: "idle2", start_ms: T0 + 120_000, end_ms: T0 + 180_000 },
      ],
    }),
  );
  // One broadcast and one msg of 200 bytes each. In a mesh of 2 each has 1 receiver.
  writeFileSync(
    `${dir}/oracle.jsonl`,
    [
      { sender: "a", kind: "broadcast", receivers: 1, bytes: 200, seq: 0, ts: T0 + 70_000 },
      { sender: "b", kind: "msg", receivers: 1, bytes: 200, seq: 1, ts: T0 + 80_000 },
    ]
      .map((line) => JSON.stringify(line))
      .join("\n") + "\n",
  );
  return dir;
}

const run = (dir: string) => Bun.spawnSync([process.execPath, SUMMARIZE, dir], { stderr: "pipe" });

test("the idle phase gives the metadata bytes per second per daemon", () => {
  const out = run(fixture([1200, 800])).stdout.toString();
  // idle1: (3000 + 3000) bytes / (60 s x 2 daemons) = 50.0. idle2: 12000 / 120 = 100.0.
  expect(out).toContain("idle1_meta_bps_per_daemon=50.0");
  expect(out).toContain("idle2_meta_bps_per_daemon=100.0");
});

test("the loaded phase gives the metadata bytes per delivered data byte", () => {
  const out = run(fixture([1200, 800])).stdout.toString();
  // Delivered data: 200 x 1 + 200 x 1 = 400. Frame layer: wire 1200 + 800 = 2000, so metadata is
  // 1600 and the ratio is 4.00. UDP layer: 1600 + 1000 = 2600, so metadata is 2200 and the ratio is 5.50.
  expect(out).toContain("delivered_data_bytes=400");
  expect(out).toContain("frame_meta_per_data=4.00");
  expect(out).toContain("udp_meta_per_data=5.50");
});

test("a wire total below the delivered data bytes fails the frame layer", () => {
  // wire 200 + 100 = 300 is below the 400 delivered data bytes: the census or the oracle is wrong.
  const proc = run(fixture([200, 100]));
  expect(proc.exitCode).not.toBe(0);
  expect(proc.stderr.toString()).toContain("frame layer");
});

test("the wire fields are read from a separate wire census line", () => {
  const dir = fixture([1200, 800]);
  // The engine writes the wire counters on a `wire census` line beside the `mesh census` line.
  // Move them there: the node logs keep their phases and their totals.
  for (const node of ["n1", "n2"]) {
    const file = `${dir}/${node}.err`;
    const moved = readFileSync(file, "utf8")
      .split("\n")
      .filter((line) => line)
      .flatMap((line) => [
        line.replace(/ idle_wire_in=\d+ idle_net_recv_ip=\d+/, ""),
        line.replace("mesh census roster_len=2", "wire census"),
      ]);
    writeFileSync(file, moved.join("\n") + "\n");
  }
  const out = run(dir).stdout.toString();
  expect(out).toContain("frame_meta_per_data=4.00");
  expect(out).toContain("idle1_meta_bps_per_daemon=50.0");
});

test("the host samples give the resident memory per daemon at the peak, with the daemon count", () => {
  const dir = fixture([1200, 800]);
  const sample = (daemons: number, sum: number, max: number) =>
    JSON.stringify({ ts: T0, load1: 1, avail_bytes: 0, open_files: 0, daemons, rss_kb_sum: sum, rss_kb_max: max });
  writeFileSync(`${dir}/host.jsonl`, [sample(1, 20000, 20000), sample(2, 50000, 30000), sample(2, 40000, 25000)].join("\n") + "\n");
  const out = run(dir).stdout.toString();
  // The peak sum is 50000 kB with 2 daemons: mean 25000 kB = 24.4 MB. The peak max is 30000 kB = 29.3 MB.
  // The peak sum is 50000 / 1024 = 48.8 MB.
  expect(out).toContain("rss_n=2 rss_mean_mb_per_daemon=24.4 rss_max_mb=29.3 rss_sum_mb=48.8");
});

test("the cputime of the daemon processes gives the CPU per daemon in each phase", () => {
  const dir = fixture([1200, 800]);
  const sample = (at: number, cpu: number) =>
    JSON.stringify({ ts: T0 + at * 1000, load1: 1, avail_bytes: 0, open_files: 0, daemons: 2, rss_kb_sum: 1, rss_kb_max: 1, cpu_s_sum: cpu });
  // idle1 spans 0-60 s: the sums are 10 s at 0 s and 70 s at 60 s. The two daemons used 60 s of CPU in 60 s.
  // idle2 spans 120-180 s: 100 s at 120 s and 112 s at 180 s. They used 12 s in 60 s.
  writeFileSync(
    `${dir}/host.jsonl`,
    [sample(0, 10), sample(30, 40), sample(60, 70), sample(120, 100), sample(180, 112)].join("\n") + "\n",
  );
  const out = run(dir).stdout.toString();
  // idle1: 60 s / (60 s x 2 daemons) = 50.0 percent of a core. idle2: 12 / 120 = 10.0 percent.
  expect(out).toContain("idle1_cpu_pct_per_daemon=50.0");
  expect(out).toContain("idle2_cpu_pct_per_daemon=10.0");
});

test("a summary of a summary does not count its aggregate line as a node", () => {
  const dir = fixture([1200, 800]);
  writeFileSync(`${dir}/summary.txt`, run(dir).stdout.toString());
  // The aggregate line of the first pass is no node: the 2 node logs give the count.
  expect(run(dir).stdout.toString()).toMatch(/full=\d+\/2 /);
});

test("the CPU total reads both census forms: user plus system, and the one field", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "summarize-"));
  writeFileSync(`${dir}/n1.err`, censusLine(30, { idle_wakeups: 1, cpu_user_ms: 6, cpu_sys_ms: 3 }) + "\n");
  writeFileSync(`${dir}/n2.err`, censusLine(30, { idle_wakeups: 1, cpu_ms: 10 }) + "\n");
  // 6 + 3 from the node with the two fields, and 10 from the node with one.
  expect(run(dir).stdout.toString()).toContain("cpu_ms=19 ");
});

test("a run whose census has no wire counters gets no ratio and no failure", () => {
  const dir = fixture([1200, 800]);
  for (const node of ["n1.err", "n2.err"]) {
    const text = readFileSync(`${dir}/${node}`, "utf8");
    writeFileSync(`${dir}/${node}`, text.replaceAll(/ idle_wire_in=\d+/g, "").replaceAll(/ idle_net_recv_ip=\d+/g, ""));
  }
  const result = run(dir);
  expect(result.exitCode).toBe(0);
  expect(result.stdout.toString()).not.toContain("frame_meta_per_data");
});

