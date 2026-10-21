#!/bin/sh
# Rules of the Google Rust Style Guide (issue #29) that no compiler lint checks.
# Each rule is one pattern. A match fails the check unless `style-check.allow` names the file with
# at least that many matches. A new match in an allowed file raises the count, so it fails too.
# A count that is higher than the matches fails as well: lower it when you remove an exception.
set -eu

cd "$(dirname "$0")/.."
allow="scripts/style-check.allow"
failed=0

# check <rule> <pattern> <file-glob> <why>
check() {
    rule=$1
    pattern=$2
    glob=$3
    why=$4
    counts=$(git ls-files -co --exclude-standard -- "$glob" | xargs grep -cE -- "$pattern" 2>/dev/null |
        grep -v ':0$' || true)

    # A match that no exception covers, or more matches than the exception allows.
    for entry in $counts; do
        file=${entry%:*}
        found=${entry##*:}
        allowed=$(awk -F'|' -v r="$rule" -v f="$file" '$1 == r && $2 == f { print $3 }' "$allow")
        allowed=${allowed:-0}
        if [ "$found" -gt "$allowed" ]; then
            echo "style-check: [$rule] $file: $found match(es), $allowed allowed. $why"
            failed=1
        fi
    done

    # An exception that no longer matches that many lines.
    awk -F'|' -v r="$rule" '$1 == r { print $2 "|" $3 }' "$allow" | while IFS='|' read -r file allowed; do
        found=$(printf '%s\n' "$counts" | awk -F: -v f="$file" '$1 == f { print $2 }')
        found=${found:-0}
        if [ "$found" -lt "$allowed" ]; then
            echo "style-check: [$rule] $file: $found match(es), $allowed allowed. Lower the count in $allow."
            exit 1
        fi
    done || failed=1
}

check poison 'PoisonError::into_inner' '*.rs' \
    'Never reach inside a poisoned mutex. Use .expect("...") and let the panic spread.'
check feature '^\s*#!\[feature\(' '*.rs' \
    'No unstable features. The light-cycles example is the one exception, with its own toolchain.'
check catch_unwind 'catch_unwind' '*/src/*.rs' \
    'Do not call panic::catch_unwind in first-party code. A boundary with C is the exception.'
check ctor '#\[(ctor::)?ctor\]|use ctor\b' '*.rs' \
    'Do not run code before main().'
check block_doc '/\*\*($|[^*/])' '*.rs' \
    'Document with /// and //!, not with /** */.'

exit "$failed"
