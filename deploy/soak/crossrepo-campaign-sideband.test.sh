#!/bin/sh
# Fail-closed regressions for the crossrepo campaign's downstream host sideband.
#
# Run: sh deploy/soak/crossrepo-campaign-sideband.test.sh
#
# Drives the real crossrepo-campaign.sh with a zero-second window against stub
# binaries, and asserts two things: that the synthetic downstream's host
# sideband is composed from --env-file (the stub echoes what it inherited), and
# that a readiness line disagreeing with that configuration fails the campaign
# before any episode runs, so a durable-recovery campaign cannot start against a
# downstream that would refuse every host-lease-control frame.
set -eu

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
campaign=$dir/crossrepo-campaign.sh
[ -f "$campaign" ] || { printf '%s\n' "campaign not found: $campaign" >&2; exit 66; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

bins=$work/bin
mkdir -p "$bins"
key=00112233445566778899aabbccddeeff
principal=11111111-2222-4333-8444-555555555555

# The stub downstream reports the readiness tail its case asks for and echoes
# the sideband it actually inherited, so a case proves the campaign forwarded
# the names instead of relying on whatever the caller had exported.
cat > "$bins/synthetic_mod_server" <<'STUB'
#!/bin/sh
# `@silent` mimics the pinned binary refusing its configuration: it exits
# before printing any readiness line.
[ "${STUB_READINESS:-}" = '@silent' ] && exit 0
printf 'synthetic_mod_listening=127.0.0.1:1 mode=Success%s\n' "${STUB_READINESS:-}"
printf 'stub_host_lease_key=%s\n' "${STS2_SYNTHETIC_HOST_LEASE_KEY:-unset}"
printf 'stub_host_principal=%s\n' "${STS2_SYNTHETIC_HOST_PRINCIPAL_ID:-unset}"
sleep 5
STUB
chmod +x "$bins/synthetic_mod_server"
for name in sts2-gateway-runtime sts2-harness-runtime sts2-mcp-server bridge.sh; do
    printf '#!/bin/sh\nexit 0\n' > "$bins/$name"
    chmod +x "$bins/$name"
done

failures=0
case_seq=0

record() {
    name=$1 ok=$2 detail=$3
    if [ "$ok" = 1 ]; then
        printf 'PASS %s\n' "$name"
    else
        printf 'FAIL %s (%s)\n' "$name" "$detail"
        failures=$((failures + 1))
    fi
}

# run_case NAME READINESS EXPECTED_STATUS [ENV_LINE...]
#
# Runs the campaign for a zero-second window with the stub reporting READINESS
# and, when env lines are supplied, an --env-file carrying exactly those lines.
# Leaves the run's status in `status`, its combined output in `out_file`, and
# the downstream log in `mod_log`.
run_case() {
    case_name=$1 readiness=$2 expected_status=$3
    shift 3
    case_seq=$((case_seq + 1))
    case_dir=$work/case-$case_seq
    mkdir -p "$case_dir"
    out_file=$case_dir/output
    results_dir=$case_dir/results
    mod_log=$results_dir/synthetic-mod.log
    export STUB_READINESS=$readiness
    status=0
    if [ "$#" -gt 0 ]; then
        env_file=$case_dir/campaign.env
        : > "$env_file"
        for line in "$@"; do printf '%s\n' "$line" >> "$env_file"; done
        sh "$campaign" --bin-dir "$bins" --results "$results_dir" \
            --duration-seconds 0 --env-file "$env_file" > "$out_file" 2>&1 || status=$?
    else
        sh "$campaign" --bin-dir "$bins" --results "$results_dir" \
            --duration-seconds 0 > "$out_file" 2>&1 || status=$?
    fi
    if [ "$status" -eq "$expected_status" ]; then
        record "$case_name status" 1 ""
    else
        record "$case_name status" 0 "expected $expected_status got $status: $(tail -n 1 "$out_file")"
    fi
}

# assert_inherited STUB_FIELD EXPECTED_VALUE
assert_inherited() {
    field=$1 want=$2
    got=$(grep -m1 "^$field=" "$mod_log" 2>/dev/null | sed 's/^[^=]*=//' || true)
    if [ "$got" = "$want" ]; then
        record "inherited $field" 1 ""
    else
        record "inherited $field" 0 "expected $want got ${got:-<missing>}"
    fi
}

# assert_disagreement_refused NAME
#
# The failure must name the sideband state the campaign wanted, so an operator
# reads the cause instead of a bare "failed to start".
assert_disagreement_refused() {
    if grep -q 'readiness disagrees with the campaign environment' "$out_file"; then
        record "$1 names the disagreement" 1 ""
    else
        record "$1 names the disagreement" 0 "no disagreement message in campaign output"
    fi
}

# A downstream without a configured sideband must report closed, and one built
# before the sideband existed (no host_lease field at all) is still accepted
# because the campaign does not need a sideband. Neither run invents a key, so
# the downstream sees both names unset.
run_case closed_without_sideband ' host_lease=closed' 0
assert_inherited stub_host_lease_key unset
assert_inherited stub_host_principal unset
run_case legacy_without_sideband '' 0
assert_inherited stub_host_lease_key unset

# The sideband reaches the downstream through --env-file, and the downstream
# confirms it by echoing the inherited names.
run_case enabled_with_sideband ' host_lease=enabled' 0 \
    "STS2_SYNTHETIC_HOST_LEASE_KEY=$key" "STS2_SYNTHETIC_HOST_PRINCIPAL_ID=$principal"
assert_inherited stub_host_lease_key "$key"
assert_inherited stub_host_principal "$principal"

# A sideband that was configured but not reported, and a downstream that refuses
# signed frames while the campaign expects them, both fail before any episode.
run_case closed_with_sideband_refused ' host_lease=closed' 69 \
    "STS2_SYNTHETIC_HOST_LEASE_KEY=$key"
assert_inherited stub_host_lease_key "$key"
assert_disagreement_refused closed_with_sideband_refused
run_case enabled_without_sideband_refused ' host_lease=enabled' 69
assert_disagreement_refused enabled_without_sideband_refused
run_case sideband_not_reported_refused '' 69 "STS2_SYNTHETIC_HOST_LEASE_KEY=$key"
assert_disagreement_refused sideband_not_reported_refused

# A principal without a key does not compose a sideband, so the downstream is
# expected to report closed and the name still reaches it.
run_case principal_without_key ' host_lease=closed' 0 \
    "STS2_SYNTHETIC_HOST_PRINCIPAL_ID=$principal"
assert_inherited stub_host_principal "$principal"

# A configured sideband whose key the pinned terminal refuses never reaches
# readiness. The campaign has to name the encoding rather than only timing out,
# so an operator is not left reading a bare "failed to start".
run_case sideband_key_refused '@silent' 69 "STS2_SYNTHETIC_HOST_LEASE_KEY=$key"
if grep -q 'must be 64 hex characters' "$out_file"; then
    record 'sideband_key_refused names the encoding' 1 ""
else
    record 'sideband_key_refused names the encoding' 0 'no encoding message in campaign output'
fi

# The env file stays closed to non-STS2 names.
run_case env_file_rejects_non_sts2 '' 64 'CAMPAIGN_MODE=host-lease'

# The cross-process probe needs both pinned binaries, so it cannot run here, but
# its contract can be guarded: it must stay a parseable script, must document
# every mode it accepts, and must reject an unknown mode and a missing binary
# instead of silently running something else.
probe=$dir/host-sideband-gateway-probe.sh
if [ -s "$probe" ] && sh -n "$probe" 2>/dev/null; then
    record 'probe parses' 1 ""
else
    record 'probe parses' 0 "missing or unparseable: $probe"
fi

probe_help=$(sh "$probe" --help 2>&1 || true)
for mode in configured wrong-key closed; do
    if printf '%s' "$probe_help" | grep -q "$mode"; then
        record "probe documents $mode" 1 ""
    else
        record "probe documents $mode" 0 "usage does not name $mode"
    fi
done

probe_status=0
sh "$probe" --gateway-bin /bin/true --mod-bin /bin/true --mode bogus >/dev/null 2>&1 || probe_status=$?
if [ "$probe_status" -eq 2 ]; then
    record 'probe rejects an unknown mode' 1 ""
else
    record 'probe rejects an unknown mode' 0 "expected 2 got $probe_status"
fi

probe_status=0
sh "$probe" --gateway-bin "$work/absent-gateway" --mod-bin /bin/true --mode closed >/dev/null 2>&1 || probe_status=$?
if [ "$probe_status" -eq 2 ]; then
    record 'probe rejects a missing binary' 1 ""
else
    record 'probe rejects a missing binary' 0 "expected 2 got $probe_status"
fi

# The start-time check is fail-closed, but the restart path re-runs it through
# restart_mod, and that is the case a durable-recovery window actually depends
# on: the sideband has to survive the downstream restart that --single-deployment
# injects, and a downstream that comes back *without* it is a permanent loss of
# the durable path for the rest of the window rather than a recovered restart.
sb_bins=$work/sideband-bin
mkdir -p "$sb_bins"
cat > "$sb_bins/synthetic_mod_server" <<'STUB'
#!/bin/sh
# The sideband the downstream reports depends on which launch this is, so a
# restart can change it. The counter lives outside the log the campaign reads.
launches=$(cat "$STUB_LAUNCH_COUNTER" 2>/dev/null || printf 0)
launches=$((launches + 1))
printf '%s' "$launches" > "$STUB_LAUNCH_COUNTER"
suffix=${STUB_READINESS:-}
# `-` rather than `:-`: the lost-sideband case passes an *empty* restart
# readiness on purpose, and `:-` would silently substitute the first launch's
# value and hide the very regression this case exists to catch.
if [ "$launches" -ge 2 ]; then suffix=${STUB_RESTART_READINESS-$suffix}; fi
printf 'synthetic_mod_listening=127.0.0.1:1 mode=Success%s\n' "$suffix"
sleep 5
STUB
chmod +x "$sb_bins/synthetic_mod_server"
# A single-deployment campaign never restarts the gateway, so its stub has to
# outlive the window instead of exiting like the per-episode stub does.
printf '#!/bin/sh\nsleep 60\n' > "$sb_bins/sts2-gateway-runtime"
chmod +x "$sb_bins/sts2-gateway-runtime"
for name in sts2-harness-runtime sts2-mcp-server bridge.sh; do
    printf '#!/bin/sh\nexit 0\n' > "$sb_bins/$name"
    chmod +x "$sb_bins/$name"
done

# run_restart_case NAME RESTART_READINESS
#
# Runs a ten-second single-deployment window whose only fault is `restart`, and
# leaves the results file in `sb_results`, the combined output in `sb_output`,
# and the downstream log in `sb_mod_log`.
#
# The window has to span more than one loop pass: the loop sleeps four seconds
# after every episode, so a window shorter than that exits before the fault
# check is ever reached and the case would pass vacuously with no fault record.
# Ten seconds leaves room for the first pass (no fault) plus two faulted passes.
run_restart_case() {
    sb_name=$1 restart_readiness=$2
    sb_case=$work/restart-$sb_name
    mkdir -p "$sb_case/results"
    sb_env=$sb_case/campaign.env
    printf 'STS2_SYNTHETIC_HOST_LEASE_KEY=%s\n' "$key" > "$sb_env"
    sb_counter=$sb_case/launches
    : > "$sb_counter"
    sb_results=$sb_case/results/iterations.jsonl
    sb_output=$sb_case/output
    sb_mod_log=$sb_case/results/synthetic-mod.log
    STUB_LAUNCH_COUNTER=$sb_counter STUB_READINESS=' host_lease=enabled' \
        STUB_RESTART_READINESS=$restart_readiness \
        sh "$campaign" --bin-dir "$sb_bins" --results "$sb_case/results" \
        --duration-seconds 10 --fault-interval-seconds 1 --single-deployment \
        --fault-kinds restart --env-file "$sb_env" \
        --mod-addr 127.0.0.1:20011 --gateway-port-base 21200 > "$sb_output" 2>&1 || true
}

# assert_fault NAME KIND RESULT
assert_fault() {
    if grep -q "\"fault\":\"$2\",\"result\":\"$3\"" "$sb_results" 2>/dev/null; then
        record "$1 records $2=$3" 1 ""
    else
        record "$1 records $2=$3" 0 "no such fault record in $(basename "$sb_results")"
    fi
}

run_restart_case kept ' host_lease=enabled'
assert_fault restart_kept_sideband restart recovered
# The restart really happened, so the case is not vacuous: the downstream was
# launched at least twice and every launch reported the sideband.
sb_launches=$(cat "$work/restart-kept/launches" 2>/dev/null || printf 0)
if [ "${sb_launches:-0}" -ge 2 ]; then
    record 'restart_kept_sideband restarted the downstream' 1 ""
else
    record 'restart_kept_sideband restarted the downstream' 0 "launches=$sb_launches"
fi
sb_enabled=$(grep -c 'host_lease=enabled' "$sb_mod_log" 2>/dev/null || true)
if [ "${sb_enabled:-0}" -ge 2 ]; then
    record 'restart_kept_sideband kept the sideband across the restart' 1 ""
else
    record 'restart_kept_sideband kept the sideband across the restart' 0 "enabled_readiness_lines=$sb_enabled"
fi

run_restart_case lost ''
assert_fault restart_lost_sideband restart failed
# The drop has to be real, otherwise the failing case would be failing for some
# other reason and the assertion above would be vacuous.
sb_dropped=$(tail -n +2 "$sb_mod_log" 2>/dev/null | grep -c 'host_lease=' || true)
if [ "${sb_dropped:-0}" -eq 0 ]; then
    record 'restart_lost_sideband really dropped the sideband' 1 ""
else
    record 'restart_lost_sideband really dropped the sideband' 0 "still reported: $sb_dropped"
fi
if grep -q 'readiness disagrees with the campaign environment' "$sb_output"; then
    record 'restart_lost_sideband names the disagreement' 1 ""
else
    record 'restart_lost_sideband names the disagreement' 0 "no disagreement message in campaign output"
fi

if [ "$failures" -ne 0 ]; then
    printf 'FAILED %s regression(s)\n' "$failures" >&2
    exit 1
fi
printf '%s\n' 'all crossrepo-campaign-sideband regressions passed'
