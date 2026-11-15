// The ratio goal and the regression budget, for ratio.test.ts.
export const GOAL_SHARE = 0.5;
export const BUDGET_MARGIN = 1.1;

export const goalLimit = (baseline: number): number => GOAL_SHARE * baseline;
export const budgetLimit = (head: number): number => BUDGET_MARGIN * head;

export function parseFrameRatio(summary: string): number {
  const found = summary.match(/frame_meta_per_data=([0-9.]+)/)?.[1];
  if (found === undefined) throw new Error("the summary has no frame_meta_per_data field");
  return Number(found);
}
