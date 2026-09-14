#!/bin/sh
# Fail-closed regressions for crossrepo-campaign-finalize.sh.
#
# Run: sh deploy/soak/crossrepo-campaign-finalize.test.sh
#
# Builds complete and deliberately incomplete results files and asserts the exact
# exit status, done_iterations, records_reconciled, and campaign_complete outcome.
set -eu

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
finalize=$dir/crossrepo-campaign-finalize.sh
[ -f "$finalize" ] || { printf '%s\n' "finalizer not found: $finalize" >&2; exit 66; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

duration=86400
first=2026-09-12T00:00:00Z
last=2026-09-13T00:00:00Z

failures=0

# Extract the completion value from finalizer output. Require exactly one
# completion line and match it exactly, so a prefix value (for example
# campaign_complete=trueINVALID) or contradictory duplicates are rejected.
completion_value() {
    text=$1
    count=$(printf '%s\n' "$text" | grep -c '^campaign_complete=' || true)
    [ "$count" -eq 1 ] || { printf 'invalid\n'; return 0; }
    line=$(printf '%s\n' "$text" | grep '^campaign_complete=' | head -1 || true)
    case "$line" in
        'campaign_complete=true') printf 'true\n' ;;
        'campaign_complete=false') printf 'false\n' ;;
        'campaign_complete=false '*) printf 'false\n' ;;
        *) printf 'invalid\n' ;;
    esac
}

probe() {
    name=$1 expected=$2 text=$3
    got=$(completion_value "$text")
    if [ "$got" = "$expected" ]; then
        printf 'PASS %s\n' "$name"
    else
        printf 'FAIL %s (expected %s got %s)\n' "$name" "$expected" "$got"
        failures=$((failures + 1))
    fi
}

check() {
    name=$1 want_complete=$2 want_reconciled=$3 want_done=$4 file=$5
    status=0
    if out=$("$finalize" --results "$file" --duration-seconds "$duration" 2>&1); then
        status=0
    else
        status=$?
    fi
    ok=yes
    [ "$status" -eq 0 ] || ok=no
    case "$out" in *"done_iterations=$want_done "*) : ;; *) ok=no ;; esac
    case "$out" in *"records_reconciled=$want_reconciled "*) : ;; *) ok=no ;; esac
    [ "$(completion_value "$out")" = "$want_complete" ] || ok=no
    if [ "$ok" = yes ]; then
        printf 'PASS %s\n' "$name"
    else
        printf 'FAIL %s (expected exit=0 complete=%s reconciled=%s done=%s)\n%s\n' \
            "$name" "$want_complete" "$want_reconciled" "$want_done" "$out"
        failures=$((failures + 1))
    fi
}

cat > "$work/a.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$first","fault":"downstream_restart","result":"recovered"}
{"ts":"$last","iteration":2,"result":"pass"}
{"ts":"$last","done":true,"iterations":2}
EOF
check complete true true 2 "$work/a.jsonl"

cat > "$work/b.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$last","iteration":2,"result":"pass"}
{"ts":"$last","done":true,"iterations":3}
EOF
check lost-records false false 3 "$work/b.jsonl"

cat > "$work/c.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$last","iteration":2,"result":"pass"}
EOF
check missing-done false false missing "$work/c.jsonl"

cat > "$work/d.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$last","iteration":2,"result":"fail"}
{"ts":"$last","done":true,"iterations":2}
EOF
check failed-iteration false true 2 "$work/d.jsonl"

cat > "$work/e.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$first","fault":"downstream_restart","result":"failed"}
{"ts":"$last","iteration":2,"result":"pass"}
{"ts":"$last","done":true,"iterations":2}
EOF
check unrecovered-fault false true 2 "$work/e.jsonl"

printf '%s\n' "{\"ts\":\"$first\",\"iteration\":1,\"result\":\"pass\"}" > "$work/f.jsonl"
printf '%s\n' "{\"ts\":\"$last\",\"iteration\":2" >> "$work/f.jsonl"
printf '%s\n' "{\"ts\":\"$last\",\"done\":true,\"iterations\":2}" >> "$work/f.jsonl"
check truncated-record false false 2 "$work/f.jsonl"

printf '%s\n' "{\"ts\":\"$first\",\"iteration\":1,\"result\":\"pass\"}" > "$work/g.jsonl"
printf '%s\n' "{\"ts\":\"$last\",\"done\":true,\"iterations\":1" >> "$work/g.jsonl"
check torn-done false false missing "$work/g.jsonl"

cat > "$work/h.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$last","done":true,"iterations":1}
{"ts":"$last","iteration":2,"result":"pass"}
EOF
check nonterminal-done false false missing "$work/h.jsonl"

# Matcher self-tests: exact values accepted; prefix, duplicate, and missing
# completion evidence rejected.
probe completion-exact-true true 'campaign_complete=true'
probe completion-exact-false false 'campaign_complete=false required_seconds=86400'
probe completion-prefix-rejected invalid 'campaign_complete=trueINVALID'
probe completion-duplicate-rejected invalid 'campaign_complete=true
campaign_complete=false required_seconds=1'
probe completion-missing-rejected invalid 'samples=2 iterations=2'

if [ "$failures" -ne 0 ]; then
    printf 'FAILED %s regression(s)\n' "$failures" >&2
    exit 1
fi
printf '%s\n' 'all crossrepo-campaign-finalize regressions passed'