#!/bin/sh
# Fail-closed regressions for the crossrepo campaign's component lifecycle:
# gateway readiness before an episode or a durable bring-up, and the campaign
# owning the components it launched on every exit path.
#
# Run: sh deploy/soak/crossrepo-campaign-lifecycle.test.sh
#
# Drives the real crossrepo-campaign.sh against stub binaries whose gateway
# reports that it is listening only after a configurable delay. The campaign
# must wait for that report before it launches an episode or posts its durable
# bring-up: the launched process is not a listening process, and a fixed sleep
# cannot express that ordering at any delay. Every case also asserts that no
# component the campaign launched is still running after it exits, because a
# survivor keeps the address the next run needs.
set -eu

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
campaign=$dir/crossrepo-campaign.sh
[ -f "$campaign" ] || { printf '%s\n' "campaign not found: $campaign" >&2; exit 66; }

work=$(mktemp -d)
cleanup() {
    find "$work" -depth -mindepth 1 -delete 2>/dev/null || true
    rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

bins=$work/bin
mkdir -p "$bins"

# The stub downstream reports readiness the way the pinned operator binary does
# and then stays up for the window. It records its own pid so the case can prove
# the campaign reaped it: a component that outlives the campaign keeps the
# address the next run needs.
cat > "$bins/synthetic_mod_server" <<'STUB'
#!/bin/sh
printf '%s' "$$" > "${STUB_MOD_PID_FILE:-/dev/null}"
printf 'synthetic_mod_listening=127.0.0.1:1 mode=Success\n'
sleep 30
STUB
chmod +x "$bins/synthetic_mod_server"

# The stub gateway prints its listening line only after STUB_GATEWAY_DELAY
# seconds, and prints a line before it so a campaign that waits on the log file
# existing rather than on the listening report is visible. `STUB_GATEWAY_READY=0`
# keeps the process alive without ever reporting; `die` exits immediately. It
# records its pid as well, for the same reason as the downstream stub.
cat > "$bins/sts2-gateway-runtime" <<'STUB'
#!/bin/sh
printf 'stub gateway starting\n'
case "${STUB_GATEWAY_READY:-1}" in
    die) exit 1 ;;
esac
printf '%s' "$$" > "${STUB_GATEWAY_PID_FILE:-/dev/null}"
sleep "${STUB_GATEWAY_DELAY:-0}"
if [ "${STUB_GATEWAY_READY:-1}" = 1 ]; then
    printf 'sts2-gateway runtime listening on %s for instance stub\n' "${STS2_GATEWAY_ADDR:-unset}"
fi
sleep 30
STUB
chmod +x "$bins/sts2-gateway-runtime"

# The stub harness passes only when the gateway for that iteration had already
# reported that it was listening before the episode started. Under a fixed sleep
# the episode starts first and records a failed iteration.
cat > "$bins/sts2-harness-runtime" <<'STUB'
#!/bin/sh
ready=0
for log in "${STUB_RESULTS:-.}"/.gateway-*.log "${STUB_RESULTS:-.}"/gateway.log; do
    [ -f "$log" ] || continue
    if grep -qF "listening on ${STS2_GATEWAY_ADDR:-unset}" "$log" 2>/dev/null; then
        ready=1
    fi
done
[ "$ready" = 1 ] && exit 0
exit 1
STUB
chmod +x "$bins/sts2-harness-runtime"

for name in sts2-mcp-server bridge.sh; do
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

# run_case NAME DELAY READY EXPECTED_STATUS [READY_TRIES] [--single-deployment]
#
# Runs the campaign for a short window, in the default (per-iteration gateway)
# topology or with --single-deployment. Leaving a readiness try count empty keeps
# the campaign's own default budget. Leaves the run's status in `status`, its
# combined output in `out_file`, its iteration records in `results_file`, and
# the component pid files in `mod_pid_file` / `gateway_pid_file`.
run_case() {
    case_name=$1 delay=$2 ready=$3 expected_status=$4
    shift 4
    ready_tries=
    single=
    for arg in "$@"; do
        case "$arg" in
            --single-deployment) single=$arg ;;
            *) ready_tries=$arg ;;
        esac
    done
    case_seq=$((case_seq + 1))
    case_dir=$work/case-$case_seq
    mkdir -p "$case_dir"
    out_file=$case_dir/output
    results_dir=$case_dir/results
    results_file=$results_dir/iterations.jsonl
    export STUB_GATEWAY_DELAY=$delay STUB_GATEWAY_READY=$ready
    export STUB_RESULTS=$results_dir
    mod_pid_file=$case_dir/mod.pid
    gateway_pid_file=$case_dir/gateway.pid
    export STUB_MOD_PID_FILE=$mod_pid_file STUB_GATEWAY_PID_FILE=$gateway_pid_file
    status=0
    if [ -n "$ready_tries" ]; then
        STS2_CAMPAIGN_GATEWAY_READY_TRIES=$ready_tries \
            sh "$campaign" --bin-dir "$bins" --results "$results_dir" \
            --duration-seconds 2 $single > "$out_file" 2>&1 || status=$?
    else
        sh "$campaign" --bin-dir "$bins" --results "$results_dir" \
            --duration-seconds 2 $single > "$out_file" 2>&1 || status=$?
    fi
    if [ "$status" -eq "$expected_status" ]; then
        record "$case_name status" 1 ""
    else
        record "$case_name status" 0 "expected $expected_status got $status: $(tail -n 1 "$out_file")"
    fi
    # The campaign reaps the components it killed before it exits, so this needs
    # no grace period; a small one keeps the check honest if that ever regresses.
    sleep 0.2
    assert_reaped "$case_name"
}

# assert_reaped NAME
#
# No component the campaign launched may still be running once it has exited.
# A survivor is not cosmetic on a supervised host: the next run cannot bind the
# address it holds, and it can only report that readiness never arrived.
assert_reaped() {
    leftover=
    for pid_file in "$mod_pid_file" "$gateway_pid_file"; do
        [ -f "$pid_file" ] || continue
        pid=$(cat "$pid_file" 2>/dev/null || printf '')
        [ -n "$pid" ] || continue
        state=$(ps -o stat= -p "$pid" 2>/dev/null || printf '')
        state=$(printf '%s' "$state" | tr -d ' \t')
        case "$state" in
            ''|Z*) ;;
            *) leftover="$leftover $pid" ;;
        esac
        kill "$pid" 2>/dev/null || true
    done
    if [ -n "$leftover" ]; then
        record "$1 reaped its components" 0 "still running:$leftover"
    else
        record "$1 reaped its components" 1 ""
    fi
}

# assert_recorded NAME EXPECTED
#
# EXPECTED is `pass` when the window must contain a passing iteration and `none`
# when the campaign must fail before the window opens.
assert_recorded() {
    name=$1 expected=$2
    got=none
    if [ -f "$results_file" ] && grep -q '"result":"pass"' "$results_file" 2>/dev/null; then
        got=pass
    fi
    if [ "$got" = "$expected" ]; then
        record "$name iterations" 1 ""
    else
        record "$name iterations" 0 "expected $expected iterations got $got"
    fi
}

# assert_readiness_named NAME
#
# The failure has to name the readiness that never arrived, so an operator reads
# the cause instead of the bring-up's opaque `status=000` refusal.
assert_readiness_named() {
    if grep -q 'never reported listening' "$out_file"; then
        record "$1 names readiness" 1 ""
    else
        record "$1 names readiness" 0 "no readiness message in campaign output"
    fi
}

# A gateway that reports readiness immediately is unchanged: the episode runs.
run_case immediate_ready 0 1 0
assert_recorded immediate_ready pass

# A gateway that reports readiness later than a fixed sleep would have allowed is
# waited for, so the episode never starts against a port nothing listens on. The
# delay is the stub's, not a measurement of the pinned binary: the point is the
# ordering, which a fixed sleep cannot express at any delay.
run_case late_ready_is_waited_for 1.5 1 0
assert_recorded late_ready_is_waited_for pass

# A gateway that never reports readiness ends the campaign before the window
# instead of recording a window of episodes that could only fail.
run_case never_ready_fails_closed 0 0 69 5
assert_recorded never_ready_fails_closed none
assert_readiness_named never_ready_fails_closed

# A gateway that exits immediately fails the wait straight away rather than
# burning the whole readiness budget.
run_case dead_gateway_fails_closed 0 die 69
assert_recorded dead_gateway_fails_closed none
assert_readiness_named dead_gateway_fails_closed

# The single window's own launch is the one the durable bring-up posts against,
# so the readiness gate has to hold there too: waited for when it is slow, and
# refused before the window when it never arrives.
run_case single_deployment_late_ready 1.5 1 0 --single-deployment
assert_recorded single_deployment_late_ready pass
run_case single_deployment_never_ready 0 0 69 5 --single-deployment
assert_recorded single_deployment_never_ready none
assert_readiness_named single_deployment_never_ready

# The single deployment's gateway dies at launch. The campaign fails closed --
# and it has to take the downstream it started with it. This is the shape of the
# leak that was observed for real: a fail-closed exit left `synthetic_mod_server`
# holding its address, and the next run on that host could only report that
# readiness never arrived.
run_case single_deployment_dead_gateway 0 die 69 --single-deployment
assert_recorded single_deployment_dead_gateway none
assert_readiness_named single_deployment_dead_gateway

if [ "$failures" -gt 0 ]; then
    printf '%s\n' "$failures failure(s)" >&2
    exit 1
fi
printf '%s\n' 'all gateway readiness regressions passed'
