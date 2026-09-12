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

first=$(sed -n 's/.*"ts":"\([^"]*\)".*/\1/p' "$results" | head -1)
last=$(sed -n 's/.*"ts":"\([^"]*\)".*/\1/p' "$results" | tail -1)
[ -n "$first" ] && [ -n "$last" ] || { printf '%s\n' 'results file has no timestamped samples' >&2; exit 65; }

iterations=$(grep -c '"iteration"' "$results" || true)
passed=$(grep -c '"result":"pass"' "$results" || true)
failed=$(grep -c '"result":"fail"' "$results" || true)
faults=$(grep -c '"fault":"downstream_restart"' "$results" || true)
recovered=$(grep -c '"fault":"downstream_restart","result":"recovered"' "$results" || true)
elapsed=$(( $(date -u -d "$last" +%s) - $(date -u -d "$first" +%s) ))

printf 'samples=%s iterations=%s pass=%s fail=%s downstream_faults=%s downstream_recovered=%s first=%s last=%s elapsed_seconds=%s\n' \
    "$(wc -l < "$results")" "$iterations" "$passed" "$failed" "$faults" "$recovered" "$first" "$last" "$elapsed"

if [ "$elapsed" -ge "$duration" ] && [ "$failed" -eq 0 ] && [ "$faults" -eq "$recovered" ]; then
    printf '%s\n' 'campaign_complete=true'
else
    printf 'campaign_complete=false required_seconds=%s\n' "$duration"
fi
