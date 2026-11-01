// A run of 2 nodes with known bytes. Each expected value is a hand calculation, written
// beside the fixture it comes from.

import { expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
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
