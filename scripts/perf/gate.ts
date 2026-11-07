import { loadavg } from "node:os";

// The load gates of the benchmark, accepted by the leader: see README.md, "Load gates". The phase numbers come
// from the idle meshes on nyc-macmini1 (8 cores). The start and A/B numbers were widened on 2026-11-02: the host
// idles at load1 1.5 to 1.76 with none of our daemons, so the first start gate (1.5) never opened.

export const START_NOW_MAX = 2.0;
export const START_WINDOW_MAX = 2.5;
export const PHASE_MEDIAN_MAX = 4.0;
export const PHASE_MAX = 6.0;
export const AB_RATIO_MAX = 1.35;

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

export function abGate(medianA: number, medianB: number): { ok: boolean; ratio: number } {
  const ratio = medianA === 0 && medianB === 0 ? 1 : Math.max(medianA, medianB) / Math.min(medianA, medianB);
  return { ok: ratio <= AB_RATIO_MAX, ratio };
}

// The start gate waits for a quiet host: it reads load1 every `stepMs` (10 s), keeps the last 18 values (3 min)
// and returns when they pass `startGate`. After `maxSteps` reads (120, 20 min) it gives up with the last load1.
export async function waitForStart(
  options: { read?: () => number; stepMs?: number; maxSteps?: number } = {},
): Promise<{ ok: boolean; last: number }> {
  const { read = () => loadavg()[0] ?? 0, stepMs = 10_000, maxSteps = 120 } = options;
  const window: number[] = [];
  for (let step = 0; step < maxSteps; step++) {
    window.push(read());
    if (window.length > 18) window.shift();
    if (window.length === 18 && startGate(window).ok) return { ok: true, last: window[17] ?? 0 };
    await Bun.sleep(stepMs);
  }
  return { ok: false, last: window.at(-1) ?? 0 };
}
