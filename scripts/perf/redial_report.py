#!/usr/bin/env python3
"""Re-dials of a run of mesh_peer_load: python3 redial_report.py <run folder> [<run folder> ...]

Reads the last per-second line of every node (n<i>.out). `qclose` and `sclose` count the closes
of plain QUIC connections and of WebRTC sessions, `qredial` and `sredial` the closes that were
followed by a connection to the same peer within 300 s. Prints, for each kind, the closes and
re-dials per node per hour and the share of closes that were followed by a re-dial.
"""
import glob
import re
import statistics as st
import sys

LINE = re.compile(
    r"^t (\d+) .* qclose (\d+) qredial (\d+) sclose (\d+) sredial (\d+)"
)


def last_line(path):
    found = None
    for line in open(path, errors="ignore"):
        match = LINE.match(line)
        if match:
            found = tuple(int(group) for group in match.groups())
    return found


def report(folder):
    rows = [last_line(path) for path in sorted(glob.glob(folder + "/n*.out"))]
    rows = [row for row in rows if row]
    if not rows:
        print(folder, "no lines")
        return
    hours = max(row[0] for row in rows) / 3600
    nodes = len(rows)
    for name, closes, redials in (("quic", 1, 2), ("session", 3, 4)):
        total_closes = sum(row[closes] for row in rows)
        total_redials = sum(row[redials] for row in rows)
        share = total_redials / total_closes if total_closes else 0.0
        per_node = [row[redials] / hours for row in rows]
        print(
            f"{folder.rstrip('/').split('/')[-1]:<12} {name:<8} nodes={nodes} "
            f"closes/node/h={total_closes / nodes / hours:.1f} "
            f"redials/node/h={total_redials / nodes / hours:.1f} "
            f"(median {st.median(per_node):.1f}, max {max(per_node):.1f}) "
            f"share of closes followed by a redial={share:.2f}"
        )


if __name__ == "__main__":
    for folder in sys.argv[1:]:
        report(folder)
