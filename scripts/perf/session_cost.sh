#!/bin/bash
# The memory of one WebRTC session, as a slope over K sessions, read in one process.
#
# usage: session_cost.sh <session_cost binary> <out file>
#
# Build the binary in release mode first:
#   cargo build --release -p habilis-network-iroh-webrtc-transport --features native --example session_cost
#
# Three rounds. Each round runs K = 0, 1, 8, 32 in turn, for both roles, so a drift of the host
# during the run is spread over all K: 24 runs. A run takes about 70 s (a throw-away session and
# its readings 12 s, the readings after the open 10 s, the hold 35 s, the readings after the close
# 10 s, and the negotiation of K sessions), so the 24 runs take about 28 min, plus the waits for
# the load. Before each run the script waits for load1 below 4 (at most 10 min).
#
# One JSON line per run goes to the out file. A run that fails leaves '# failed k=.. role=..'.
# The fit prints the slope per session, with its standard error and the noise floor of the
# K = 0 runs.
BIN=$1 OUT=$2
[ -x "$BIN" ] || { echo "usage: $0 <session_cost binary> <out file>"; exit 1; }
: > "$OUT"
load1() { sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}' || true; }
waitload() {
  for _ in $(seq 1 60); do
    L=$(load1); [ -z "$L" ] && L=$(awk '{print $1}' /proc/loadavg)
    awk -v load="$L" 'BEGIN { exit !(load < 4) }' && return
    sleep 10
  done
}
for round in 1 2 3; do
  for k in 0 1 8 32; do
    for role in offerer answerer; do
      waitload
      echo "round $round k=$k $role $(date +%T) load: $(uptime | sed 's/.*averages*: //')" >&2
      "$BIN" measure --role "$role" --k "$k" --hold 30 >> "$OUT" || echo "# failed k=$k role=$role" >> "$OUT"
    done
  done
done
"$BIN" fit < "$OUT"
