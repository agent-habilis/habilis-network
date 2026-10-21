#!/bin/sh
# Tests of scripts/style-check.sh. Each case plants a file in a scratch git repository and runs the
# check there. A rule that the check does not catch, or a clean file that it refuses, fails here.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

# case <name> <expected exit code> <path of the planted file> <content> [allow list content]
case_() {
    name=$1
    expected=$2
    path=$3
    content=$4
    allow=${5:-}
    repo="$work/repo"
    rm -rf "$repo"
    mkdir -p "$repo/scripts" "$repo/$(dirname "$path")"
    cp "$here/style-check.sh" "$repo/scripts/style-check.sh"
    printf '%s\n' "$allow" >"$repo/scripts/style-check.allow"
    printf '%s\n' "$content" >"$repo/$path"
    git -C "$repo" init -q
    status=0
    sh "$repo/scripts/style-check.sh" >"$work/out" 2>&1 || status=$?
    if [ "$status" = "$expected" ]; then
        printf 'ok    %s\n' "$name"
    else
        printf 'FAIL  %s: exit %s, expected %s\n' "$name" "$status" "$expected"
        sed 's/^/        /' "$work/out"
        failures=$((failures + 1))
    fi
}

# Each rule catches its plain form.
case_ 'poison: path form' 1 src/a.rs 'fn f(m: &M) { m.lock().unwrap_or_else(std::sync::PoisonError::into_inner); }'
case_ 'poison: closure form' 1 src/a.rs 'fn f(m: &M) { m.lock().unwrap_or_else(|e| e.into_inner()); }'
case_ 'poison: renamed import' 1 src/a.rs 'use std::sync::PoisonError as Pe;'
case_ 'poison: turbofish' 1 src/a.rs 'fn f() { let _ = PoisonError::<u8>::into_inner; }'
case_ 'feature: plain' 1 src/a.rs '#![feature(never_type)]'
case_ 'feature: behind cfg_attr' 1 src/a.rs '#![cfg_attr(nightly, feature(coroutines))]'
case_ 'catch_unwind' 1 src/a.rs 'fn f() { let _ = std::panic::catch_unwind(|| 1); }'
case_ 'ctor: attribute' 1 src/a.rs '#[ctor]
fn init() {}'
case_ 'ctor: path attribute' 1 src/a.rs '#[ctor::ctor]
fn init() {}'
case_ 'block doc: outer' 1 src/a.rs '/** old style */
fn f() {}'
case_ 'block doc: inner' 1 src/a.rs '/*! crate doc */'

# A clean file passes, and so does a string that only looks like a block doc comment.
case_ 'clean file' 0 src/a.rs 'fn f() {}'
case_ 'string with /**' 0 src/a.rs 'const G: &str = "src/**";'
case_ 'doc comment with ///' 0 src/a.rs '/// A doc comment.
fn f() {}'

# The allow list.
violation='fn f() { let _ = std::panic::catch_unwind(|| 1); }'
case_ 'file name with a space' 1 'c/src/a b.rs' "$violation"
case_ 'allowed, exact count' 0 src/a.rs "$violation" 'catch_unwind|src/a.rs|1|a boundary'
case_ 'allowed, count exceeded' 1 src/a.rs "$violation
$violation" 'catch_unwind|src/a.rs|1|a boundary'
case_ 'allowed, count too high (stale)' 1 src/a.rs "$violation" 'catch_unwind|src/a.rs|2|a boundary'
case_ 'allowed, file has no match (stale)' 1 src/a.rs 'fn f() {}' 'catch_unwind|src/a.rs|1|a boundary'
case_ 'two rows for one file' 1 src/a.rs "$violation" 'catch_unwind|src/a.rs|1|one
catch_unwind|src/a.rs|1|two'
case_ 'comment and blank lines in the list' 0 src/a.rs "$violation" '# a comment

catch_unwind|src/a.rs|1|a boundary'

if [ "$failures" -gt 0 ]; then
    printf '%s case(s) failed\n' "$failures"
    exit 1
fi
