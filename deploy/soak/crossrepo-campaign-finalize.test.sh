#!/bin/sh
# Fail-closed regressions for crossrepo-campaign-finalize.sh.
#
# Run: sh deploy/soak/crossrepo-campaign-finalize.test.sh
#
# Builds complete and deliberately incomplete results files and asserts that only
# a reconciled terminal record authorizes campaign_complete=true.
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
check() {
    name=$1 expected_complete=$2 expected_reconciled=$3 file=$4
    out=$("$finalize" --results "$file" --duration-seconds "$duration" 2>&1 || true)
    got_complete=no
    got_reconciled=no
    case "$out" in *'campaign_complete=true'*) got_complete=yes ;; esac
    case "$out" in *'records_reconciled=true'*) got_reconciled=yes ;; esac
    if [ "$got_complete" = "$expected_complete" ] && [ "$got_reconciled" = "$expected_reconciled" ]; then
        printf 'PASS %s\n' "$name"
    else
        printf 'FAIL %s (expected complete=%s reconciled=%s)\n%s\n' "$name" "$expected_complete" "$expected_reconciled" "$out"
        failures=$((failures + 1))
    fi
}

cat > "$work/a.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$first","fault":"downstream_restart","result":"recovered"}
{"ts":"$last","iteration":2,"result":"pass"}
{"ts":"$last","done":true,"iterations":2}
EOF
check complete yes yes "$work/a.jsonl"

cat > "$work/b.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$last","iteration":2,"result":"pass"}
{"ts":"$last","done":true,"iterations":3}
EOF
check lost-records no no "$work/b.jsonl"

cat > "$work/c.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$last","iteration":2,"result":"pass"}
EOF
check missing-done no no "$work/c.jsonl"

cat > "$work/d.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$last","iteration":2,"result":"fail"}
{"ts":"$last","done":true,"iterations":2}
EOF
check failed-iteration no yes "$work/d.jsonl"

cat > "$work/e.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$first","fault":"downstream_restart","result":"failed"}
{"ts":"$last","iteration":2,"result":"pass"}
{"ts":"$last","done":true,"iterations":2}
EOF
check unrecovered-fault no yes "$work/e.jsonl"

printf '%s\n' "{\"ts\":\"$first\",\"iteration\":1,\"result\":\"pass\"}" > "$work/f.jsonl"
printf '%s\n' "{\"ts\":\"$last\",\"iteration\":2" >> "$work/f.jsonl"
printf '%s\n' "{\"ts\":\"$last\",\"done\":true,\"iterations\":2}" >> "$work/f.jsonl"
check truncated-record no no "$work/f.jsonl"

printf '%s\n' "{\"ts\":\"$first\",\"iteration\":1,\"result\":\"pass\"}" > "$work/g.jsonl"
printf '%s\n' "{\"ts\":\"$last\",\"done\":true,\"iterations\":1" >> "$work/g.jsonl"
check torn-done no no "$work/g.jsonl"

cat > "$work/h.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$last","done":true,"iterations":1}
{"ts":"$last","iteration":2,"result":"pass"}
EOF
check nonterminal-done no no "$work/h.jsonl"

if [ "$failures" -ne 0 ]; then
    printf 'FAILED %s regression(s)\n' "$failures" >&2
    exit 1
fi
printf '%s\n' 'all crossrepo-campaign-finalize regressions passed'