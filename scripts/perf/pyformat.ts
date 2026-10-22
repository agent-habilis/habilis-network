// Python's number behaviour for the perf reports: statistics.median keeps the type of its input
// (an even count gives a float), a float prints with ".0" when it is whole, and `:.Nf` rounds an
// exact tie to the even digit.

export type Num = { value: number; float: boolean };

export function median(values: number[], float: boolean): Num {
  const sorted = [...values].sort((a, b) => a - b);
  const n = sorted.length;
  if (n % 2 === 1) return { value: sorted[(n - 1) / 2], float };
  return { value: (sorted[n / 2 - 1] + sorted[n / 2]) / 2, float: true };
}

export function show(n: Num): string {
  if (n.float && Number.isInteger(n.value)) return `${n.value}.0`;
  return String(n.value);
}

export function fixed(x: number, digits: number): string {
  const scale = 10 ** digits;
  const scaled = x * scale;
  // An exact tie: the binary value sits halfway between two steps.
  if (Number.isInteger(scaled * 2) && !Number.isInteger(scaled)) {
    const floor = Math.floor(scaled);
    const even = floor % 2 === 0 ? floor : floor + 1;
    return (even / scale).toFixed(digits);
  }
  return x.toFixed(digits);
}

export function mean(values: number[]): number {
  return values.reduce((sum, v) => sum + v, 0) / values.length;
}
