// The default number of daemons of a run, from the memory that the host has.
//
// The mean RSS per daemon grows with N: the runs on ma-imac (plain baseline, loopback) gave 29.0 MiB at
// 8 daemons and 53.6 MiB at 16. The line through these two points is the projection. Replace the two
// points when a run gives a better pair.
const POINTS = [
  { nodes: 8, meanMib: 29.0 },
  { nodes: 16, meanMib: 53.6 },
] as const;
const SHARE = 0.6;
const MIN_NODES = 2;
const MAX_NODES = 64;

const slope = (POINTS[1].meanMib - POINTS[0].meanMib) / (POINTS[1].nodes - POINTS[0].nodes);
const meanMib = (nodes: number) => POINTS[0].meanMib + slope * (nodes - POINTS[0].nodes);

export const projectedSumMib = (nodes: number): number => nodes * meanMib(nodes);

export function chooseNodes(availableBytes: number): { nodes: number; why: string } {
  const budgetMib = (availableBytes / 1024 ** 2) * SHARE;
  let nodes = MIN_NODES;
  while (nodes < MAX_NODES && projectedSumMib(nodes + 1) < budgetMib) nodes++;
  const why =
    `N=${nodes}: projected RSS sum ${projectedSumMib(nodes).toFixed(0)} MiB, ` +
    `budget ${budgetMib.toFixed(0)} MiB (${SHARE * 100}% of ${(availableBytes / 1024 ** 2).toFixed(0)} MiB available)`;
  return { nodes, why };
}
