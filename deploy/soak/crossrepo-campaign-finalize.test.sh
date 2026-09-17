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
# completion line and match it exactly: `campaign_complete=true`, bare
# `campaign_complete=false`, or `campaign_complete=false required_seconds=<digits>`.
# A prefix value (for example campaign_complete=trueINVALID), a malformed suffix,
# or contradictory duplicates are rejected.
completion_value() {
    text=$1
    count=$(printf '%s\n' "$text" | grep -c '^campaign_complete=' || true)
    [ "$count" -eq 1 ] || { printf 'invalid\n'; return 0; }
    line=$(printf '%s\n' "$text" | grep '^campaign_complete=' | head -1 || true)
    case "$line" in
        'campaign_complete=true') printf 'true\n' ;;
        'campaign_complete=false') printf 'false\n' ;;
        *)
            if printf '%s\n' "$line" | grep -Eq '^campaign_complete=false required_seconds=[0-9]+$'; then
                printf 'false\n'
            else
                printf 'invalid\n'
            fi
            ;;
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
    shift 5
    status=0
    if out=$("$finalize" --results "$file" --duration-seconds "$duration" "$@" 2>&1); then
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

# Single-deployment campaigns: one gateway for the window, every iteration on a
# strictly higher lease epoch, and every required fault kind injected and
# recovered. A regressed epoch, a missing mode record, an unrecovered fault of
# any kind, and an unknown fault kind must each keep the campaign incomplete.
single_faults() {
    cat <<EOF2
{"ts":"$first","fault":"restart","result":"recovered"}
{"ts":"$first","fault":"archive","result":"recovered","detail":"archive/000001"}
{"ts":"$first","fault":"budget","result":"recovered","detail":"restarts=3"}
{"ts":"$first","fault":"telemetry_outage","result":"recovered","detail":"iteration=2"}
EOF2
}

cat > "$work/s-ok.jsonl" <<EOF
{"ts":"$first","mode":"single-deployment","gateway_addr":"127.0.0.1:21000","episode_profile":"repeated-episode-lease-v1"}
{"ts":"$first","iteration":1,"result":"pass","lease_epoch":1}
{"ts":"$first","iteration":2,"result":"pass","lease_epoch":2}
$(single_faults)
{"ts":"$last","iteration":3,"result":"pass","lease_epoch":3}
{"ts":"$last","done":true,"iterations":3}
EOF
check single-deployment-complete true true 3 "$work/s-ok.jsonl" --single-deployment

cat > "$work/s-regress.jsonl" <<EOF
{"ts":"$first","mode":"single-deployment","gateway_addr":"127.0.0.1:21000","episode_profile":"repeated-episode-lease-v1"}
{"ts":"$first","iteration":1,"result":"pass","lease_epoch":1}
{"ts":"$first","iteration":2,"result":"pass","lease_epoch":2}
$(single_faults)
{"ts":"$last","iteration":3,"result":"pass","lease_epoch":2}
{"ts":"$last","done":true,"iterations":3}
EOF
check single_deployment_mode_requires_monotonic_lease_epochs false true 3 "$work/s-regress.jsonl" --single-deployment

cat > "$work/s-no-epoch.jsonl" <<EOF
{"ts":"$first","mode":"single-deployment","gateway_addr":"127.0.0.1:21000","episode_profile":"repeated-episode-lease-v1"}
{"ts":"$first","iteration":1,"result":"pass","lease_epoch":1}
{"ts":"$first","iteration":2,"result":"pass"}
$(single_faults)
{"ts":"$last","iteration":3,"result":"pass","lease_epoch":3}
{"ts":"$last","done":true,"iterations":3}
EOF
check single_deployment_mode_requires_monotonic_lease_epochs-missing-epoch false true 3 "$work/s-no-epoch.jsonl" --single-deployment

# A fresh-gateway results file (no mode record) cannot be finalized as
# single-deployment evidence, and a mode record is honoured without the flag.
check single-deployment-flag-requires-mode-record false true 2 "$work/a.jsonl" --single-deployment
check single-deployment-mode-record-without-flag false true 3 "$work/s-regress.jsonl"

cat > "$work/s-fault-failed.jsonl" <<EOF
{"ts":"$first","mode":"single-deployment","gateway_addr":"127.0.0.1:21000","episode_profile":"repeated-episode-lease-v1"}
{"ts":"$first","iteration":1,"result":"pass","lease_epoch":1}
{"ts":"$first","fault":"restart","result":"recovered"}
{"ts":"$first","fault":"archive","result":"recovered"}
{"ts":"$first","fault":"budget","result":"failed","detail":"restarts=2"}
{"ts":"$first","fault":"telemetry_outage","result":"recovered"}
{"ts":"$last","iteration":2,"result":"pass","lease_epoch":2}
{"ts":"$last","done":true,"iterations":2}
EOF
check every_fault_kind_must_record_recovery false true 2 "$work/s-fault-failed.jsonl" --single-deployment

cat > "$work/s-fault-missing.jsonl" <<EOF
{"ts":"$first","mode":"single-deployment","gateway_addr":"127.0.0.1:21000","episode_profile":"repeated-episode-lease-v1"}
{"ts":"$first","iteration":1,"result":"pass","lease_epoch":1}
{"ts":"$first","fault":"restart","result":"recovered"}
{"ts":"$first","fault":"archive","result":"recovered"}
{"ts":"$first","fault":"telemetry_outage","result":"recovered"}
{"ts":"$last","iteration":2,"result":"pass","lease_epoch":2}
{"ts":"$last","done":true,"iterations":2}
EOF
check every_fault_kind_must_record_recovery-missing-kind false true 2 "$work/s-fault-missing.jsonl" --single-deployment

cat > "$work/s-fault-unknown.jsonl" <<EOF
{"ts":"$first","mode":"single-deployment","gateway_addr":"127.0.0.1:21000","episode_profile":"repeated-episode-lease-v1"}
{"ts":"$first","iteration":1,"result":"pass","lease_epoch":1}
$(single_faults)
{"ts":"$first","fault":"power_loss","result":"recovered"}
{"ts":"$last","iteration":2,"result":"pass","lease_epoch":2}
{"ts":"$last","done":true,"iterations":2}
EOF
check unknown_fault_kind_fails_closed false true 2 "$work/s-fault-unknown.jsonl" --single-deployment

cat > "$work/i.jsonl" <<EOF
{"ts":"$first","iteration":1,"result":"pass"}
{"ts":"$first","fault":"power_loss","result":"recovered"}
{"ts":"$last","iteration":2,"result":"pass"}
{"ts":"$last","done":true,"iterations":2}
EOF
check unknown_fault_kind_fails_closed-fresh-gateway false true 2 "$work/i.jsonl"

# Matcher self-tests: exact values accepted; prefix, duplicate, missing, and
# malformed-suffix completion evidence rejected.
probe completion-exact-true true 'campaign_complete=true'
probe completion-bare-false false 'campaign_complete=false'
probe completion-exact-false false 'campaign_complete=false required_seconds=86400'
probe completion-prefix-rejected invalid 'campaign_complete=trueINVALID'
probe completion-false-suffix-rejected invalid 'campaign_complete=false INVALID'
probe completion-false-nonnumeric-rejected invalid 'campaign_complete=false required_seconds=abc'
probe completion-duplicate-rejected invalid 'campaign_complete=true
campaign_complete=false required_seconds=1'
probe completion-missing-rejected invalid 'samples=2 iterations=2'

if [ "$failures" -ne 0 ]; then
    printf 'FAILED %s regression(s)\n' "$failures" >&2
    exit 1
fi
printf '%s\n' 'all crossrepo-campaign-finalize regressions passed'