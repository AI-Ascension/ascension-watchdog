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

if [ "$failures" -ne 0 ]; then
    printf 'FAILED %s regression(s)\n' "$failures" >&2
    exit 1
fi
printf '%s\n' 'all crossrepo-campaign-sideband regressions passed'
