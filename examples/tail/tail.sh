#!/usr/bin/env bash
# Stream a growing file to one reader: its last lines, then every line
# appended, until you stop it. Options after the file go to habilis-network-stream.
#
#   examples/tail/tail.sh app.log --web-url http://127.0.0.1:3020/
#
# HABILIS_NETWORK_STREAM names the binary when it is not on PATH.
set -euo pipefail

file=${1:?usage: tail.sh <file> [habilis-network-stream options]}
shift

# Not a pipeline: `tail -f` never ends by itself, and a pipeline waits for it
# after habilis-network-stream has exited. Through a FIFO, the trap stops it instead.
# The FIFO carries the file's bytes, so only this user may open it: a
# private directory (mktemp -d is 0700) and a 0600 FIFO inside it. The mode
# repeats what the directory already ensures, on purpose: it still holds if
# the FIFO ever moves out.
dir=$(mktemp -d "${TMPDIR:-/tmp}/tail-stream.XXXXXX")
fifo="$dir/input"
mkfifo -m 600 "$fifo"
tail_pid=
stream_pid=
stopping=
# `|| true`: under `set -e` a failed kill (tail already gone) would replace
# the exit code this script is leaving with.
trap 'rm -rf "${dir:?}"; [ -z "$tail_pid" ] || kill "$tail_pid" 2>/dev/null || true' EXIT

# Ctrl-C, SIGTERM or SIGHUP to this script ends the input, so a reader gets
# the end of the stream. habilis-network-stream reads its input only once a reader
# attaches, so with none yet it would wait forever: it gets 10 s, more than
# its own graceful close takes (a 5 s drain, then the node close), and is
# then stopped.
# shellcheck disable=SC2329  # the trap below calls it
stop() {
    [ -z "$stopping" ] || return 0
    stopping=1
    # Nothing to wait for yet: leave now; the EXIT trap cleans up.
    [ -n "$stream_pid" ] || exit 143
    kill "$tail_pid" 2>/dev/null || true
    for _ in $(seq 100); do
        kill -0 "$stream_pid" 2>/dev/null || return 0
        sleep 0.1
    done
    kill -TERM "$stream_pid" 2>/dev/null || true
}
trap stop INT TERM HUP

tail -f "$file" > "$fifo" &
tail_pid=$!
# In the background, then `wait`: bash runs a trap only between commands, so
# a foreground habilis-network-stream would hold off `stop` until it had exited.
"${HABILIS_NETWORK_STREAM:-habilis-network-stream}" "$@" < "$fifo" &
stream_pid=$!
status=0
wait "$stream_pid" || status=$?
# A trap cuts the first `wait` short; the second one gets the real exit code.
if [ -n "$stopping" ]; then
    status=0
    wait "$stream_pid" || status=$?
fi
exit "$status"
