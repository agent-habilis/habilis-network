import { loadavg } from "node:os";

// The load gates of the benchmark, accepted by the leader: see README.md, "Load gates". The phase numbers come
// from the idle meshes on nyc-macmini1 (8 cores). The start numbers were widened on 2026-11-02: the host
// idles at load1 1.5 to 1.76 with none of our daemons, so the first start gate (1.5) never opened. The pair gate
// was changed on 2026-11-07, after it voided two pairs of arms that differ in load: see README.md, "Load gates".

export const START_NOW_MAX = 2.0;
export const START_WINDOW_MAX = 2.5;
export const PHASE_MEDIAN_MAX = 4.0;
export const PHASE_MAX = 6.0;
export const START_RATIO_MAX = 1.35;

// `samples` are the load1 values of the 3 min before the start, oldest first.
export function startGate(samples: number[]): { ok: boolean; now: number; max: number } {
  const now = samples[samples.length - 1] ?? Infinity;
  const max = samples.length ? Math.max(...samples) : Infinity;
  return { ok: now <= START_NOW_MAX && max <= START_WINDOW_MAX, now, max };
}

// `samples` are the load1 values inside one phase.
export function phaseGate(samples: number[]): { ok: boolean; median: number; max: number } {
  const sorted = [...samples].sort((a, b) => a - b);
  const median = sorted[sorted.length >> 1] ?? Infinity;
  const max = sorted[sorted.length - 1] ?? Infinity;
  return { ok: median <= PHASE_MEDIAN_MAX && max <= PHASE_MAX, median, max };
}

// The fairness gate of a pair: the two arms must start from the same host state. `startA` and `startB` are the
// load1 windows of the 3 min before each arm started. Both windows pass the start gate, and their medians are
// within START_RATIO_MAX of each other. The load that an arm makes is no input: an arm that costs less load is
// the result that the pair measures.
export function fairGate(startA: number[], startB: number[]): { ok: boolean; ratio: number } {
  const median = (samples: number[]) => [...samples].sort((a, b) => a - b)[samples.length >> 1] ?? Infinity;
  const [medianA, medianB] = [median(startA), median(startB)];
  const ratio = medianA === 0 && medianB === 0 ? 1 : Math.max(medianA, medianB) / Math.min(medianA, medianB);
  return { ok: startGate(startA).ok && startGate(startB).ok && ratio <= START_RATIO_MAX, ratio };
}

// The start gate waits for a quiet host: it reads load1 every `stepMs` (10 s), keeps the last 18 values (3 min)
// and returns when they pass `startGate`. After `maxSteps` reads (120, 20 min) it gives up with the last load1.
export async function waitForStartWindow(
  options: { read?: () => number; stepMs?: number; maxSteps?: number } = {},
): Promise<{ ok: boolean; last: number; window: number[] }> {
  const { read = () => loadavg()[0] ?? 0, stepMs = 10_000, maxSteps = 120 } = options;
  const window: number[] = [];
  for (let step = 0; step < maxSteps; step++) {
    window.push(read());
    if (window.length > 18) window.shift();
    if (window.length === 18 && startGate(window).ok) return { ok: true, last: window[17] ?? 0, window };
    await Bun.sleep(stepMs);
  }
  return { ok: false, last: window.at(-1) ?? 0, window };
}

export async function waitForStart(
  options: { read?: () => number; stepMs?: number; maxSteps?: number } = {},
): Promise<{ ok: boolean; last: number }> {
  const { ok, last } = await waitForStartWindow(options);
  return { ok, last };
}
