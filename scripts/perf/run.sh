#!/bin/bash
# One run of the mesh load driver: N nodes, one process each, on one host.
#
# usage: run.sh <mesh_peer_load binary> <N> <steady secs> <outdir>
#
# The driver reads its settings from the environment (see the header of
# crates/habilis-network/examples/mesh_peer_load.rs): MESH_TRANSPORT,
# MESH_TRANSPORTS, MESH_TRAFFIC, MESH_MAX_PEERS, MESH_MAX_DIRECT,
# MESH_BLOCK_UDP_AFTER_SECS, MESH_UNDERLAY_LEG. `STAGGER` is the gap between two
# node starts, in seconds (default 0.3).
#
# The outdir gets n<i>.out and n<i>.err per node, summary.txt (the last census line
# of each node), host.log (one line per 10 s: load, process states, free memory),
# canary.log (every pause of the host over 0.5 s), probe.log, and `done` at the end.
BIN=$1 N=$2 STEADY=$3 OUT=$4
mkdir -p "$OUT"
export MESH_TRAFFIC=${MESH_TRAFFIC:-on}
HERE=$(cd "$(dirname "$0")" && pwd)
python3 "$HERE/canary.py" "$OUT/canary.log" & CAN=$!
PIDFILE="$OUT/pids"; : > "$PIDFILE"
"$BIN" > "$OUT/n1.out" 2> "$OUT/n1.err" & echo "1 $!" >> "$PIDFILE"
for _ in $(seq 1 60); do ID=$(sed -n 's/^mesh *//p' "$OUT/n1.out"); [ -n "$ID" ] && break; sleep 0.5; done
[ -z "$ID" ] && { echo "creator gave no id"; kill $CAN; exit 1; }
(
  sampled=0
  while :; do
    P=$(awk '{print $2}' "$PIDFILE" | paste -sd, -)
    echo "$(date +%T) load=$(sysctl -n vm.loadavg | tr -d '{}') $(ps -o stat=,pcpu= -p $P 2>/dev/null | awk '{s[substr($1,1,1)]++; c+=$2} END{for(k in s) printf "%s=%d ", k, s[k]; printf "pcpu_sum=%.0f", c}') builds=$(pgrep -x rustc | wc -l | tr -d ' ') $(vm_stat | awk '/Pages free/{f=$3} /occupied by compressor/{c=$5} /Pageins/{pi=$2} /Pageouts/{po=$2} END{printf "free_pg=%s compressor_pg=%s pageins=%s pageouts=%s", f, c, pi, po}') swap=$(sysctl -n vm.swapusage | awk '{print $6}')" >> "$OUT/host.log"
    now=$(date +%s)
    while read -r i pid; do
      [ -e "$OUT/n$i.err" ] || continue
      age=$(( now - $(stat -f %m "$OUT/n$i.err") ))
      if [ $age -gt 25 ] && kill -0 "$pid" 2>/dev/null; then
        echo "$(date +%T) n$i pid=$pid silent ${age}s: $(ps -o stat=,pcpu=,time=,rss= -p "$pid")" >> "$OUT/probe.log"
        if [ $sampled -lt 4 ] && [ ! -e "$OUT/sample-n$i.txt" ]; then sample "$pid" 3 -file "$OUT/sample-n$i.txt" > /dev/null 2>&1; sampled=$((sampled+1)); fi
      fi
    done < "$PIDFILE"
    sleep 10
  done
) & SAM=$!
for i in $(seq 2 "$N"); do
  "$BIN" "$ID" > "$OUT/n$i.out" 2> "$OUT/n$i.err" & echo "$i $!" >> "$PIDFILE"
  sleep "${STAGGER:-0.3}"
done
sleep "$STEADY"
for i in $(seq 1 "$N"); do
  echo "n$i $(tail -n1 "$OUT/n$i.out" | tr -d '\n') | $(grep 'mesh census' "$OUT/n$i.err" | tail -n1 | sed 's/\x1b\[[0-9;]*m//g' | grep -o 'roster_len=[0-9]*\|link_len=[0-9]*\|links_direct=[0-9]*\|links_pending=[0-9]*\|peak_resident_memory_mb=[0-9]*' | tr '\n' ' ')" >> "$OUT/summary.txt"
done
kill $SAM $CAN 2>/dev/null
# Each node by its own pid, then the stragglers by the same pids: nothing else is touched.
for p in $(awk '{print $2}' "$PIDFILE"); do kill "$p" 2>/dev/null; done; sleep 2
for p in $(awk '{print $2}' "$PIDFILE"); do kill -9 "$p" 2>/dev/null; done
echo done > "$OUT/done"
