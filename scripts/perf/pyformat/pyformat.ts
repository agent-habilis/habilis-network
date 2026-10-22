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

// Python prints a float in exponent form from 1e16 up and below 1e-4, and a whole float with ".0".
export function show(n: Num): string {
  const v = n.value;
  if (n.float && v !== 0 && Number.isFinite(v) && (Math.abs(v) >= 1e16 || Math.abs(v) < 1e-4)) {
    const [mantissa, exponent] = v.toExponential().split("e");
    const sign = exponent.startsWith("-") ? "-" : "+";
    return `${mantissa}e${sign}${exponent.replace(/^[+-]/, "").padStart(2, "0")}`;
  }
  if (n.float && Number.isInteger(v)) return `${v}.0`;
  return String(v);
}

// `toFixed` rounds an exact tie up. Python rounds it to the even digit. A tie is a value whose
// exact binary expansion stops with a 5 right after the digits we keep; `toFixed(100)` shows
// that expansion exactly, which a scaled float product does not.
export function fixed(x: number, digits: number): string {
  const exact = Math.abs(x).toFixed(100);
  const dot = exact.indexOf(".");
  if (dot < 0) return x.toFixed(digits);
  const tail = exact.slice(dot + 1 + digits);
  if (/^50*$/.test(tail)) {
    const head = exact.slice(0, dot + (digits ? 1 + digits : 0));
    if (Number(head[head.length - 1]) % 2 === 0) return (x < 0 ? "-" : "") + head;
  }
  return x.toFixed(digits);
}

export function mean(values: number[]): number {
  return values.reduce((sum, v) => sum + v, 0) / values.length;
}
