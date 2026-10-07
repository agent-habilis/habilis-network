"""The marginal memory of the underlay WebRTC sessions, from run folders of run.sh.

usage: python3 underlay_report.py <run dir> [<run dir> ...]

Run the driver with MESH_BLOCK_UDP_AFTER_SECS=60 (phase 2 starts when a node takes IP
away from every connection of its process), the transport list with relay, and traffic
on. Two cells: the underlay leg on, and MESH_UNDERLAY_LEG=off as the control. Per node
the report reads two lines of n<i>.out:

- phase 1 end: the last line before the block.
- phase 2: the first line at least SECS_INTO_PHASE_2 (180) seconds after the block.

Per run: the median and the maximum, over nodes, of the delta of the current resident
memory (MB) between the two readings, and the mean number of underlay sessions per
node at the second reading. The marginal memory of one session is
(delta with the leg on - delta with the leg off) / mean underlay sessions: compare
the lines of the two cells by hand, three runs each.
"""
import glob
import re
import statistics as st
import sys

SECS_INTO_PHASE_2 = 180
LINE = re.compile(
    r"^t (\d+) phase (\d) peers (\d+) links (\d+) sessions (\d+) underlay (\d+) rss_mb (\d+)"
)


def readings(path):
    rows = []
    for line in open(path, errors="replace"):
        found = LINE.match(line)
        if found:
            t, phase, peers, links, sessions, underlay, rss = map(int, found.groups())
            rows.append((t, phase, underlay, rss))
    return rows


def report(run):
    deltas, underlays = [], []
    for path in sorted(glob.glob(run + "/n*.out")):
        rows = readings(path)
        phase_1 = [row for row in rows if row[1] == 1]
        phase_2 = [row for row in rows if row[1] == 2]
        if not phase_1 or not phase_2:
            continue
        switch = phase_2[0][0]
        late = [row for row in phase_2 if row[0] >= switch + SECS_INTO_PHASE_2]
        if not late:
            continue
        deltas.append(late[0][3] - phase_1[-1][3])
        underlays.append(late[0][2])
    if not deltas:
        return f"{run}: no node has both readings"
    return (
        f"{run.rstrip('/').split('/')[-1]:12} nodes={len(deltas)} "
        f"delta_rss_mb median={st.median(deltas)} max={max(deltas)} "
        f"| underlay_sessions mean={st.mean(underlays):.1f}"
    )


if __name__ == "__main__":
    for run in sys.argv[1:]:
        print(report(run.rstrip("/")))
