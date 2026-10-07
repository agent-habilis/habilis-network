"""One line of metrics per run folder of run.sh.

usage: python3 summarize.py <run dir> [<run dir> ...]

Reads summary.txt (the last census line of each node), the n<i>.err logs, host.log
and canary.log. The fields:

- full / isolated / roster_med / min: how many nodes hold the whole roster, how many
  hold none, and the median and the least roster, out of N nodes.
- stalls / longest_s: `maintenance timer stalled` warnings, and the longest gap.
- up / down: `gossip neighbor up` and `gossip neighbor down` lines of all nodes, the
  link churn of the run.
- drop_nodes / worst_drop: nodes that logged a dropped data message (the send queue of
  a connection was full), and the worst count a node logged (a lower bound: the log
  line appears at each power of two).
- disc_nodes / worst_disc: the same for `send_overflow_disconnects`.
- resent / resend_dropped: the sum of the `idle_resent` and `idle_resend_dropped`
  deltas of every census line, which is the total over the run.
- mem_med / mem_max: peak resident memory of the nodes, in MB.
- load1 median and max, from host.log; canary pauses of the host over 0.5 s.
"""
import glob
import os
import re
import statistics as st
import sys


def clean(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def numbers(text, pattern):
    return [int(x) for x in re.findall(pattern, text)]


def summarize(run):
    rows = [dict(re.findall(r"(\w+)=(\d+)", line)) for line in open(run + "/summary.txt")]
    census = [row for row in rows if "roster_len" in row]
    roster = [int(row["roster_len"]) for row in census]
    mem = [int(row["peak_resident_memory_mb"]) for row in census if "peak_resident_memory_mb" in row]
    n = len(rows)
    stalls, drops, discs = [], {}, {}
    up = down = resent = resend_dropped = 0
    for path in glob.glob(run + "/n*.err"):
        text = clean(open(path, errors="replace").read())
        node = os.path.basename(path)
        stalls += numbers(text, r"timer stalled[^\n]*?mono_gap_ms=(\d+)")
        found = numbers(text, r"dropped a data message[^\n]*?dropped=(\d+)")
        if found:
            drops[node] = max(found)
        found = numbers(text, r"send queue of the peer refused[^\n]*?disconnects=(\d+)")
        if found:
            discs[node] = max(found)
        up += text.count("gossip neighbor up")
        down += text.count("gossip neighbor down")
        resent += sum(numbers(text, r"idle_resent=(\d+)"))
        resend_dropped += sum(numbers(text, r"idle_resend_dropped=(\d+)"))
    loads = []
    if os.path.exists(run + "/host.log"):
        for line in open(run + "/host.log"):
            found = re.search(r"load=\s*([0-9.]+)", line)
            if found:
                loads.append(float(found.group(1)))
    gaps = []
    if os.path.exists(run + "/canary.log"):
        gaps = [float(x) for x in re.findall(r"gap_s=([0-9.]+)", open(run + "/canary.log").read())]
    return (
        f"{os.path.basename(run):12} full={sum(x >= n - 1 for x in roster)}/{n} "
        f"isolated={sum(x <= 1 for x in roster)} roster_med={st.median(roster) if roster else '-'} "
        f"min={min(roster) if roster else '-'} | stalls={len(stalls)} longest_s={max(stalls) // 1000 if stalls else 0} "
        f"| up={up} down={down} | drop_nodes={len(drops)} worst_drop={max(drops.values()) if drops else 0} "
        f"| disc_nodes={len(discs)} worst_disc={max(discs.values()) if discs else 0} "
        f"| resent={resent} resend_dropped={resend_dropped} "
        f"| mem_med={st.median(mem) if mem else '-'} mem_max={max(mem) if mem else '-'} "
        f"| load1 median={st.median(loads) if loads else '-'} max={max(loads) if loads else '-'} "
        f"| canary_pauses={len(gaps)}"
    )


if __name__ == "__main__":
    for run in sys.argv[1:]:
        print(summarize(run.rstrip("/")))
