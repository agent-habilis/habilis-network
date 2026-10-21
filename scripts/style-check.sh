#!/bin/sh
# Rules of the Google Rust Style Guide (issue #29) that no compiler lint checks.
# Each rule is one pattern. A match fails the check unless `style-check.allow` names the file with
# at least that many matching lines. A new match in an allowed file raises the count, so it fails
# too. A count that is higher than the matches fails as well: lower it when you remove an exception.
# `style-check-test.sh` plants a violation for each rule and for each way the allow list can break.
set -eu

cd "$(dirname "$0")/.."
allow=${STYLE_CHECK_ALLOW:-scripts/style-check.allow}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
: >"$work/found"
: >"$work/why"

# check <rule> <pattern> <file-glob> <why>
# Appends `rule|file|matching lines` to $work/found for every file that matches.
check() {
    rule=$1
    pattern=$2
    glob=$3
    why=$4
    printf '%s|%s\n' "$rule" "$why" >>"$work/why"
    # -z and -0 keep a file name with a space whole. -H names the file even when there is one file.
    git ls-files -z -co --exclude-standard -- "$glob" |
        xargs -0 -r grep -cHE -- "$pattern" >"$work/out" || true
    while IFS= read -r line; do
        count=${line##*:}
        file=${line%:*}
        [ "$count" = 0 ] && continue
        printf '%s|%s|%s\n' "$rule" "$file" "$count" >>"$work/found"
    done <"$work/out"
}

check poison 'PoisonError|unwrap_or_else\([|][^|]*[|][^)]*into_inner' '*.rs' \
    'Never reach inside a poisoned mutex. Use .expect("...") and let the panic spread.'
check feature '^[[:space:]]*#!?\[(cfg_attr\([^]]*, *)?feature\(' '*.rs' \
    'No unstable features. The light-cycles example is the one exception, with its own toolchain.'
check catch_unwind 'catch_unwind' '*.rs' \
    'Do not call panic::catch_unwind in first-party code. A boundary with C is the exception.'
check ctor '#\[(ctor::)?ctor\]|use ctor([^_[:alnum:]]|$)' '*.rs' \
    'Do not run code before main().'
check block_doc '^[[:space:]]*/\*[*!]($|[^*/])' '*.rs' \
    'Document with /// and //!, not with /** */ or /*! */.'

# Compare what was found with what the allow list says.
awk -F'|' -v allowfile="$allow" '
    FILENAME == ARGV[1] {
        if ($0 ~ /^[[:space:]]*(#|$)/) next
        key = $1 "|" $2
        if (key in allowed) {
            printf "style-check: %s has two rows for [%s] %s. Merge them.\n", allowfile, $1, $2
            status = 1
        }
        allowed[key] = $3
        next
    }
    FILENAME == ARGV[2] { found[$1 "|" $2] = $3; next }
    { why[$1] = substr($0, length($1) + 2) }
    END {
        for (key in found) {
            limit = (key in allowed) ? allowed[key] : 0
            if (found[key] > limit) {
                split(key, part, "|")
                printf "style-check: [%s] %s: %d matching line(s), %d allowed. %s\n", \
                    part[1], part[2], found[key], limit, why[part[1]]
                status = 1
            }
        }
        for (key in allowed) {
            have = (key in found) ? found[key] : 0
            if (have < allowed[key]) {
                split(key, part, "|")
                printf "style-check: [%s] %s: %d matching line(s), %d allowed. Lower the count in %s.\n", \
                    part[1], part[2], have, allowed[key], allowfile
                status = 1
            }
        }
        exit status
    }
' "$allow" "$work/found" "$work/why"
