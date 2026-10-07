#!/bin/bash
# A series of runs, one after the other, each after the host has calmed down.
#
# usage: series.sh <binary> <outroot> <steady secs> <N:k> [<N:k> ...]
#
# `N:k` is a run of N nodes, numbered k. The outdir of a run is <outroot>/N<N>-<k>.
# Before each run it waits (at most 15 min) until the 1 min load is below
# `LOAD_BELOW` (default 5), and logs the uptime of every start and end in
# <outroot>/drive.log. Pass the driver settings as environment variables.
BIN=$1 ROOT=$2 STEADY=$3; shift 3
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$ROOT"
for spec in "$@"; do
  N=${spec%%:*}; k=${spec##*:}
  waited=0
  while :; do
    L=$(sysctl -n vm.loadavg | awk '{print $2}')
    [ "$(echo "$L < ${LOAD_BELOW:-5}" | bc)" = 1 ] && break
    [ $waited -ge 900 ] && break
    sleep 20; waited=$((waited+20))
  done
  echo "$(date +%T) N$N-$k start uptime=$(uptime | sed 's/.*averages*: //') waited=${waited}s" >> "$ROOT/drive.log"
  bash "$HERE/run.sh" "$BIN" "$N" "$STEADY" "$ROOT/N$N-$k" > /dev/null 2>&1
  echo "$(date +%T) N$N-$k end uptime=$(uptime | sed 's/.*averages*: //')" >> "$ROOT/drive.log"
  sleep 30
done
echo finished > "$ROOT/finished"
