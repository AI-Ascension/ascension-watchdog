#!/bin/sh
# Summarize a cross-repo campaign results file and refuse to call a run complete
# before the requested wall-clock duration (or with any failed iteration, any
# unrecovered or unknown injected fault, or — for a single-deployment campaign —
# a missing mode record, a missing required fault kind, or lease epochs that are
# not strictly increasing across the recorded iterations).
#
# Usage: crossrepo-campaign-finalize.sh --results PATH --duration-seconds N [--single-deployment]
set -eu

usage() {
    printf '%s\n' 'usage: crossrepo-campaign-finalize.sh --results PATH --duration-seconds N [--single-deployment]' >&2
    exit 64
}

results=
duration=
require_single=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --results) [ "$#" -ge 2 ] || usage; results=$2; shift 2 ;;
        --duration-seconds) [ "$#" -ge 2 ] || usage; duration=$2; shift 2 ;;
        --single-deployment) require_single=1; shift ;;
        *) usage ;;
    esac
done
[ -n "$results" ] && [ -n "$duration" ] || usage
[ -f "$results" ] || { printf '%s\n' "results file is missing: $results" >&2; exit 66; }

first=$(sed -n 's/.*"ts":"\([^"]*\)".*/\1/p' "$results" 2>/dev/null | head -1)
last=$(sed -n 's/.*"ts":"\([^"]*\)".*/\1/p' "$results" 2>/dev/null | tail -1)
[ -n "$first" ] && [ -n "$last" ] || { printf '%s\n' 'results file has no timestamped samples' >&2; exit 65; }

# The runner's terminal record has exactly this shape on the final non-empty
# line: {"ts":"<iso8601>","done":true,"iterations":N}. Require a complete,
# delimited record in terminal position: a torn or interleaved record, or a
# completion marker that is not the last line, must not authorize completion.
last_line=$(sed -n '/[^[:space:]]/p' "$results" | tail -1)
terminal=$(printf '%s\n' "$last_line" | grep -E '^\{"ts":"[^"]*","done":true,"iterations":[0-9]+\}$' || true)
done_iterations=$(printf '%s\n' "$terminal" | sed -n 's/.*"iterations":\([0-9][0-9]*\)}$/\1/p')
[ -n "$done_iterations" ] || done_iterations=missing

iterations=$(grep -c '"iteration"' "$results" || true)
passed=$(grep -c '"result":"pass"' "$results" || true)
failed=$(grep -c '"result":"fail"' "$results" || true)
recorded_results=$((passed + failed))
elapsed=$(( $(date -u -d "$last" +%s) - $(date -u -d "$first" +%s) ))

# Injected faults form a closed matrix. Every fault record must name a known
# kind and record recovery; an unknown kind is counted and fails the campaign
# rather than being ignored as "not a downstream restart".
known_kinds='downstream_restart restart archive budget telemetry_outage'
faults=$(grep -c '"fault":"' "$results" || true)
recovered=0
unknown_faults=$faults
fault_summary=
for kind in $known_kinds; do
    kind_total=$(grep -c "\"fault\":\"$kind\"" "$results" || true)
    kind_recovered=$(grep -c "\"fault\":\"$kind\",\"result\":\"recovered\"" "$results" || true)
    recovered=$((recovered + kind_recovered))
    unknown_faults=$((unknown_faults - kind_total))
    [ "$kind_total" -eq 0 ] || fault_summary="$fault_summary $kind=$kind_recovered/$kind_total"
done
if [ "$unknown_faults" -eq 0 ] && [ "$faults" -eq "$recovered" ]; then
    faults_reconciled=true
else
    faults_reconciled=false
fi

# Single-deployment campaigns are recognized by the runner's mode record. The
# flag requires that record, so a fresh-gateway-per-iteration run cannot be
# finalized as single-deployment evidence; a mode record without the flag still
# enforces the single-deployment rules, because the file says what it is.
mode_records=$(grep -c '"mode":"single-deployment"' "$results" || true)
if [ "$require_single" -eq 1 ] || [ "$mode_records" -gt 0 ]; then
    mode=single-deployment
else
    mode=fresh-gateway
fi
epochs_monotonic=n/a
required_kinds_present=n/a
if [ "$mode" = single-deployment ]; then
    # Every iteration record must carry a lease epoch and the epochs must be
    # strictly increasing in file order: a reused or regressed epoch means an
    # episode did not land on a fresh lease of the same deployment.
    epoch_lines=$(grep '"iteration"' "$results" | grep -c '"lease_epoch":[0-9][0-9]*' || true)
    if [ "$mode_records" -eq 1 ] && [ "$epoch_lines" -eq "$iterations" ] && [ "$iterations" -gt 0 ] \
        && grep '"iteration"' "$results" \
            | sed -n 's/.*"lease_epoch":\([0-9][0-9]*\).*/\1/p' \
            | awk 'BEGIN { previous = 0; ok = 1 } { if ($1 + 0 <= previous) { ok = 0 } previous = $1 + 0 } END { exit ok ? 0 : 1 }'; then
        epochs_monotonic=true
    else
        epochs_monotonic=false
    fi
    required_kinds_present=true
    for kind in restart archive budget telemetry_outage; do
        grep -q "\"fault\":\"$kind\",\"result\":\"recovered\"" "$results" || required_kinds_present=false
    done
fi

# Fail closed on a truncated, interrupted, or otherwise incomplete results file:
# the terminal `done` marker must be present, its authoritative iteration count
# must equal the recorded iteration records, and every record must carry one
# pass/fail result. Otherwise the campaign cannot be reported complete.
if [ "$done_iterations" = "$iterations" ] && [ "$recorded_results" -eq "$iterations" ] && [ "$iterations" -gt 0 ]; then
    reconciled=true
else
    reconciled=false
fi

printf 'samples=%s iterations=%s pass=%s fail=%s downstream_faults=%s downstream_recovered=%s unknown_fault_kinds=%s faults_reconciled=%s fault_kinds=%s mode=%s lease_epochs_monotonic=%s required_fault_kinds_present=%s done_iterations=%s records_reconciled=%s first=%s last=%s elapsed_seconds=%s\n' \
    "$(wc -l < "$results")" "$iterations" "$passed" "$failed" "$faults" "$recovered" "$unknown_faults" "$faults_reconciled" "${fault_summary# }" "$mode" "$epochs_monotonic" "$required_kinds_present" "$done_iterations" "$reconciled" "$first" "$last" "$elapsed"

single_ok=true
if [ "$mode" = single-deployment ]; then
    [ "$epochs_monotonic" = true ] && [ "$required_kinds_present" = true ] || single_ok=false
fi
if [ "$elapsed" -ge "$duration" ] && [ "$failed" -eq 0 ] && [ "$faults_reconciled" = true ] && [ "$reconciled" = true ] && [ "$single_ok" = true ]; then
    printf '%s\n' 'campaign_complete=true'
else
    printf 'campaign_complete=false required_seconds=%s\n' "$duration"
fi
