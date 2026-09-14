#!/bin/sh
# Summarize a cross-repo campaign results file and refuse to call a run complete
# before the requested wall-clock duration (or with any failed iteration or
# unrecovered downstream fault).
#
# Usage: crossrepo-campaign-finalize.sh --results PATH --duration-seconds N
set -eu

usage() {
    printf '%s\n' 'usage: crossrepo-campaign-finalize.sh --results PATH --duration-seconds N' >&2
    exit 64
}

results=
duration=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --results) [ "$#" -ge 2 ] || usage; results=$2; shift 2 ;;
        --duration-seconds) [ "$#" -ge 2 ] || usage; duration=$2; shift 2 ;;
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
faults=$(grep -c '"fault":"downstream_restart"' "$results" || true)
recovered=$(grep -c '"fault":"downstream_restart","result":"recovered"' "$results" || true)
recorded_results=$((passed + failed))
elapsed=$(( $(date -u -d "$last" +%s) - $(date -u -d "$first" +%s) ))

# Fail closed on a truncated, interrupted, or otherwise incomplete results file:
# the terminal `done` marker must be present, its authoritative iteration count
# must equal the recorded iteration records, and every record must carry one
# pass/fail result. Otherwise the campaign cannot be reported complete.
if [ "$done_iterations" = "$iterations" ] && [ "$recorded_results" -eq "$iterations" ] && [ "$iterations" -gt 0 ]; then
    reconciled=true
else
    reconciled=false
fi

printf 'samples=%s iterations=%s pass=%s fail=%s downstream_faults=%s downstream_recovered=%s done_iterations=%s records_reconciled=%s first=%s last=%s elapsed_seconds=%s\n' \
    "$(wc -l < "$results")" "$iterations" "$passed" "$failed" "$faults" "$recovered" "$done_iterations" "$reconciled" "$first" "$last" "$elapsed"

if [ "$elapsed" -ge "$duration" ] && [ "$failed" -eq 0 ] && [ "$faults" -eq "$recovered" ] && [ "$reconciled" = true ]; then
    printf '%s\n' 'campaign_complete=true'
else
    printf 'campaign_complete=false required_seconds=%s\n' "$duration"
fi
