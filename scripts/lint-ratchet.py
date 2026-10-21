#!/usr/bin/env python3
"""Ratchet for the lints that still have old findings.

The lints are missing_docs, clippy::exhaustive_enums, clippy::exhaustive_structs and
clippy::unwrap_used. A count above the baseline fails, because it is a new finding. A
count below the baseline fails too, so the baseline only tightens. Standard library only.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter

LINTS = (
    "missing_docs",
    "clippy::exhaustive_enums",
    "clippy::exhaustive_structs",
    "clippy::unwrap_used",
)

CLIPPY = [
    "cargo",
    "clippy",
    "--workspace",
    "--all-targets",
    "--all-features",
    "--keep-going",
    "--message-format=json",
    "--",
    "--cap-lints",
    "warn",
    "-W",
    "missing_docs",
    "-W",
    "clippy::exhaustive_enums",
    "-W",
    "clippy::exhaustive_structs",
    "-W",
    "clippy::unwrap_used",
]

# Only library source counts. Tests, examples and benches are not in crates/<crate>/src/.
SRC = re.compile(r"^crates/([^/]+)/src/")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BASELINE = os.path.join(ROOT, "scripts", "lint-ratchet.baseline")

HEADER = """# Count of findings per lint and crate, under crates/<crate>/src/.
# Written by `python3 scripts/lint-ratchet.py --update`. Lower a count when a finding
# goes away. A count above this file is a new finding and fails CI.
"""


def findings(lines):
    """Count the findings in clippy JSON lines, one per (lint, file, line, column)."""
    seen = set()
    counts = Counter()
    for line in lines:
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("reason") != "compiler-message":
            continue
        message = obj["message"]
        code = (message.get("code") or {}).get("code")
        if code not in LINTS:
            continue
        primary = [span for span in message.get("spans", []) if span.get("is_primary")]
        if not primary:
            continue
        span = primary[0]
        match = SRC.match(span["file_name"].replace("\\", "/"))
        if not match:
            continue
        # The lib target and the test target both report a source file. Count it once.
        key = (code, span["file_name"], span["line_start"], span["column_start"])
        if key in seen:
            continue
        seen.add(key)
        counts[(code, match.group(1))] += 1
    return counts


def clippy_lines():
    """Run clippy on the workspace and return its JSON lines. Exit if it did not finish."""
    proc = subprocess.run(CLIPPY, cwd=ROOT, capture_output=True, text=True)
    lines = proc.stdout.splitlines()
    finished = [json.loads(line) for line in lines if '"build-finished"' in line]
    if not finished or not finished[-1].get("success"):
        sys.stderr.write(proc.stderr[-4000:])
        print("lint-ratchet: clippy did not finish, so the counts are not known")
        sys.exit(2)
    return lines


def read_baseline(path):
    counts = Counter()
    if not os.path.exists(path):
        return counts
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            lint, crate, count = line.split("|")
            counts[(lint, crate)] = int(count)
    return counts


def write_baseline(path, counts):
    rows = sorted((lint, crate, n) for (lint, crate), n in counts.items() if n > 0)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(HEADER)
        for lint, crate, n in rows:
            handle.write(f"{lint}|{crate}|{n}\n")


def compare(current, baseline):
    problems = []
    for lint, crate in sorted(set(current) | set(baseline)):
        now = current.get((lint, crate), 0)
        then = baseline.get((lint, crate), 0)
        if now > then:
            problems.append(
                f"lint-ratchet: [{lint}] {crate}: {now} finding(s), baseline {then}. "
                "New finding(s): fix them, or write the item so the lint does not fire."
            )
        elif now < then:
            problems.append(
                f"lint-ratchet: [{lint}] {crate}: {now} finding(s), baseline {then}. "
                "Lower the baseline with: python3 scripts/lint-ratchet.py --update"
            )
    return problems


def totals(counts):
    parts = []
    for lint in LINTS:
        parts.append(f"{lint} {sum(n for (name, _), n in counts.items() if name == lint)}")
    return "lint-ratchet: totals: " + ", ".join(parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--update", action="store_true", help="rewrite the baseline")
    parser.add_argument("--from-json", metavar="FILE", help="read a saved clippy run")
    parser.add_argument("--baseline", default=DEFAULT_BASELINE, help="baseline file")
    args = parser.parse_args()

    if args.from_json:
        with open(args.from_json, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    else:
        lines = clippy_lines()

    current = findings(lines)
    print(totals(current))

    if args.update:
        write_baseline(args.baseline, current)
        print(f"lint-ratchet: baseline written to {args.baseline}")
        return 0

    problems = compare(current, read_baseline(args.baseline))
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
