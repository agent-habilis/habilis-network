// The ratio goal: at N = 16 the engine sends at most half of the metadata bytes per delivered data byte that
// the baseline sends. The two host tests run bench.ts on the binary in RATIO_BIN (a build with the wire
// counters) for about 20 min. They need the host to be quiet: see README.md, "Load gates".
//
// RATIO_BIN=<binary> bun test scripts/perf/ratio.test.ts
// RATIO_ALLOW_SKIP=1 lets a host with too little memory skip the two host tests instead of failing.

import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { availableBytes } from "./avail.ts";
import { chooseNodes } from "./choose-n.ts";
import { phaseGate, waitForStart } from "./gate.ts";
import { budgetLimit, goalLimit, parseFrameRatio } from "./ratio.ts";

const NODES = 16;
const baseline = JSON.parse(readFileSync(path.join(import.meta.dir, "baseline-ratio.json"), "utf8"));

test("the goal is half of the baseline and the budget is the head value plus 10 percent", () => {
  expect(goalLimit(78.9)).toBeCloseTo(39.45, 10);
  expect(budgetLimit(40)).toBeCloseTo(44, 10);
});

test("the ratio is read from the frame_meta_per_data field of the summary", () => {
  expect(parseFrameRatio("a=1 frame_meta_per_data=78.58 udp_meta_per_data=132.57")).toBe(78.58);
  expect(() => parseFrameRatio("no ratio here")).toThrow("frame_meta_per_data");
});

// One run serves both host tests.
let measured: Promise<number> | undefined;
function measure(): Promise<number> {
  measured ??= (async () => {
    const binary = process.env.RATIO_BIN;
    if (!binary) throw new Error("RATIO_BIN names no binary: set it to a build with the wire counters");
    // The start gate of b4.ts: the host must be quiet before the run, not only during it.
    const start = await waitForStart();
    if (!start.ok) throw new Error(`start gate: the host did not settle in 20 min, last load1 ${start.last}`);
    const out = mkdtempSync(path.join(tmpdir(), "ratio-"));
    const bench = Bun.spawn(
      [
        process.execPath, path.join(import.meta.dir, "bench.ts"), binary, "ratio-test", "--nodes", String(NODES),
        "--stagger", "0.5", "--settle", "300", "--idle", "240", "--loaded", "300", "--min-avail-gib", "1", "--out-root", out,
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    const [text, err] = await Promise.all([new Response(bench.stdout).text(), new Response(bench.stderr).text()]);
    const folder = text.match(/run folder: (\S+)/)?.[1];
    if (!folder) throw new Error(`bench.ts gave no run folder (exit ${await bench.exited}): ${err.slice(-300)}`);
    // The load gates of b4.ts: a ratio from a loaded host is no measurement.
    const host = readFileSync(`${folder}/host.jsonl`, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    const result = JSON.parse(readFileSync(`${folder}/result.json`, "utf8"));
    for (const phase of result.phases as { name: string; start_ms: number; end_ms: number }[]) {
      const load1s = host.filter((s) => s.ts >= phase.start_ms && s.ts <= phase.end_ms).map((s) => s.load1 as number);
      const gate = phaseGate(load1s);
      if (!gate.ok) throw new Error(`phase ${phase.name}: load1 median ${gate.median}, max ${gate.max}: the host was too loaded, run again`);
    }
    const summary = Bun.spawnSync([process.execPath, path.join(import.meta.dir, "summarize.ts"), folder]);
    return parseFrameRatio(summary.stdout.toString());
  })();
  return measured;
}

// A skip never passes by itself: without RATIO_ALLOW_SKIP the test fails.
function lacksMemory(): boolean {
  const { nodes, why } = chooseNodes(availableBytes());
  if (nodes >= NODES) return false;
  const message = `SKIPPED: this host fits ${nodes} daemons, the test needs ${NODES} (${why})`;
  console.log(message);
  if (process.env.RATIO_ALLOW_SKIP !== "1") throw new Error(`${message}. Set RATIO_ALLOW_SKIP=1 to allow it.`);
  return true;
}

const HOST_TEST_MS = 40 * 60 * 1000;

// A bare `bun test` of the repository must not start a benchmark of 20 minutes: the two host tests run
// only when RATIO_BIN names a binary. (`bun run test` also path-ignores this file, see package.json.)
const hostTest = process.env.RATIO_BIN ? test : test.skip;

hostTest(
  `goal: at N=${NODES} the metadata bytes per data byte are at most half of the baseline`,
  async () => {
    if (lacksMemory()) return;
    const ratio = await measure();
    expect(ratio).toBeLessThanOrEqual(goalLimit(baseline.value));
  },
  HOST_TEST_MS,
);

hostTest(
  `budget: at N=${NODES} the metadata bytes per data byte stay within 10 percent of the head value`,
  async () => {
    if (lacksMemory()) return;
    if (typeof baseline.head_value !== "number") throw new Error("baseline-ratio.json has no head_value: measure the head binary and commit it");
    const ratio = await measure();
    expect(ratio).toBeLessThanOrEqual(budgetLimit(baseline.head_value));
  },
  HOST_TEST_MS,
);
