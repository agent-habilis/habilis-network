#!/bin/sh
# Tests of scripts/lint-ratchet.py. Each case runs the ratchet on a saved clippy run (--from-json)
# against a baseline, and checks the exit code. A count that the ratchet misses fails here.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
fixtures="$here/lint-ratchet-fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

# check <name> <expected exit code> <expected text in output, or -> <command...>
check() {
    name=$1
    expected=$2
    text=$3
    shift 3
    status=0
    "$@" >"$work/out" 2>&1 || status=$?
    if [ "$status" != "$expected" ]; then
        printf 'FAIL  %s: exit %s, expected %s\n' "$name" "$status" "$expected"
        sed 's/^/        /' "$work/out"
        failures=$((failures + 1))
    elif [ "$text" != "-" ] && ! grep -q -- "$text" "$work/out"; then
        printf 'FAIL  %s: output lacks %s\n' "$name" "$text"
        sed 's/^/        /' "$work/out"
        failures=$((failures + 1))
    else
        printf 'ok    %s\n' "$name"
    fi
}

ratchet() {
    python3 "$here/lint-ratchet.py" --from-json "$1" --baseline "$2"
}

base="$fixtures/base.json"
extra="$fixtures/extra.json"
: >"$work/empty"

# The baseline of the base run: one finding per lint and crate, as --update writes it.
python3 "$here/lint-ratchet.py" --from-json "$base" --baseline "$work/base.baseline" --update >/dev/null
# A baseline that is one finding short for habilis-network.
printf '%s\n' 'missing_docs|habilis-network|2' 'clippy::exhaustive_enums|habilis-network-protocol|1' \
    >"$work/fewer.baseline"

# Equal counts pass. The duplicate lines in base.json count once, and the test, example,
# task and unknown-lint lines are ignored.
check 'equal counts pass' 0 - ratchet "$base" "$work/base.baseline"

# One more finding fails.
head -n 1 "$extra" >"$work/one-more.json"
cat "$base" "$work/one-more.json" >"$work/base-plus.json"
check 'one more finding fails' 1 'New finding' ratchet "$work/base-plus.json" "$work/base.baseline"

# One fewer finding fails.
check 'one fewer finding fails' 1 'Lower the baseline' ratchet "$base" "$work/fewer.baseline"

# A duplicate message for one span counts once.
grep 'crates/habilis-network/src/a.rs' "$base" | grep -v needless_return >"$work/dup.json"
printf '%s\n' 'missing_docs|habilis-network|1' >"$work/dup.baseline"
check 'duplicate span counts once' 0 - ratchet "$work/dup.json" "$work/dup.baseline"

# Findings in tests/, examples/ and tasks/ are ignored.
grep -E 'tests/|examples/|tasks/' "$base" >"$work/ignored.json"
check 'tests, examples, tasks ignored' 0 - ratchet "$work/ignored.json" "$work/empty"

# An unknown lint is ignored.
grep 'needless_return' "$base" >"$work/unknown.json"
check 'unknown lint ignored' 0 - ratchet "$work/unknown.json" "$work/empty"

# A new crate with findings and no baseline line fails.
grep 'habilis-network-newcrate' "$extra" >"$work/newcrate.json"
cat "$base" "$work/newcrate.json" >"$work/base-newcrate.json"
check 'new crate without baseline fails' 1 'habilis-network-newcrate' ratchet "$work/base-newcrate.json" "$work/base.baseline"

# A baseline written by --update passes on the same run.
python3 "$here/lint-ratchet.py" --from-json "$base" --baseline "$work/rt.baseline" --update >/dev/null
check 'update then compare passes' 0 - ratchet "$base" "$work/rt.baseline"

# Struct fields and variants are left without docs on purpose, so they are not counted.
kinds="$fixtures/kinds.json"
grep 'struct field' "$kinds" >"$work/field.json"
check 'missing_docs for a struct field is ignored' 0 - ratchet "$work/field.json" "$work/empty"
grep 'a variant' "$kinds" >"$work/variant.json"
check 'missing_docs for a variant is ignored' 0 - ratchet "$work/variant.json" "$work/empty"

# Functions and methods still need docs, so they are counted.
grep 'a function' "$kinds" >"$work/function.json"
check 'missing_docs for a function counts' 1 'New finding' ratchet "$work/function.json" "$work/empty"
grep 'a method' "$kinds" >"$work/method.json"
check 'missing_docs for a method counts' 1 'New finding' ratchet "$work/method.json" "$work/empty"

if [ "$failures" -gt 0 ]; then
    printf '%s case(s) failed\n' "$failures"
    exit 1
fi
echo 'all lint-ratchet cases passed'
