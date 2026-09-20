#!/bin/sh
# Fail-closed regressions for the supervisor soak campaign's container
# bring-up: the systemd manager inside the container has to answer before the
# setup exec runs, and bring-up owns the container and the staging copy it
# created on every exit path.
#
# Run: sh deploy/soak/supervisor-soak-lifecycle.test.sh
#
# Drives the real supervisor-soak.sh with a stub `podman` and a stub `id`. The
# campaign refuses to run as anything but root, so the shim reports uid 0 the
# way deploy/linux/test-install-uninstall.sh does; nothing else about the
# campaign is bypassed. The stub container reports that its systemd manager is
# up only after a configured delay, and its setup exec refuses to run before
# that report: a launched container is not a booted container, and the fixed
# sleep that used to stand in for that ordering cannot express it at any delay.
#
# The bring-up also has to clean up after itself. A privileged container left
# behind by a failed bring-up holds the name every later run needs, and the
# staging copy it was fed is reachable only through that container, so a soak
# host that fails once could not start again.
set -eu

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
campaign=$dir/supervisor-soak.sh
[ -f "$campaign" ] || { printf '%s\n' "campaign not found: $campaign" >&2; exit 66; }

work=$(mktemp -d)
cleanup() {
    find "$work" -depth -mindepth 1 -delete 2>/dev/null || true
    rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

container=soak-campaign-stub
shim=$work/shim
mkdir -p "$shim"

cat > "$shim/id" <<'SHIM'
#!/bin/sh
if [ "${1:-}" = -u ]; then
    printf '0\n'
    exit 0
fi
exec /usr/bin/id "$@"
SHIM
chmod +x "$shim/id"

# A stub runtime that models the one thing the campaign depends on: a container
# whose PID 1 systemd manager becomes reachable on its own schedule, some
# seconds after the container is created, whether or not anyone probes it.
# `STUB_SYSTEMD` selects the shape (ready, late, never, dead). The setup exec
# refuses to run until the manager has answered and refuses to run in a
# container that is no longer running, exactly as `systemctl` does inside one,
# so a case can tell "the campaign waited" from "the campaign slept and hoped".
cat > "$shim/podman" <<'SHIM'
#!/bin/sh
printf '%s\n' "$*" >> "$STUB_LOG"
command=${1:-}
shift 2>/dev/null || true
case "$command" in
    run)
        [ "${STUB_RUN:-ok}" = ok ] || exit 125
        case "${STUB_SYSTEMD:-ready}" in
            dead) : > "$STUB_STATE/exited" ;;
            never) : > "$STUB_STATE/running" ;;
            *)
                : > "$STUB_STATE/running"
                ( sleep "${STUB_SYSTEMD_DELAY:-0}"; : > "$STUB_STATE/ready" ) &
                ;;
        esac
        printf '%s\n' "$STUB_CONTAINER"
        ;;
    rm)
        find "$STUB_STATE/running" -delete 2>/dev/null || true
        find "$STUB_STATE/ready" -delete 2>/dev/null || true
        ;;
    inspect)
        if [ -e "$STUB_STATE/running" ]; then printf 'true\n'; else printf 'false\n'; fi
        ;;
    logs)
        printf 'stub container boot log\n'
        ;;
    cp)
        [ "${STUB_CP:-ok}" = ok ] || exit 125
        ;;
    exec)
        if [ ! -e "$STUB_STATE/running" ]; then
            printf '%s\n' 'stub container is not running' >&2
            exit 125
        fi
        case "$*" in
            *systemctl*)
                if [ -e "$STUB_STATE/ready" ]; then printf 'running\n'; fi
                ;;
            *soak-setup.sh*)
                if [ ! -e "$STUB_STATE/ready" ]; then
                    printf '%s\n' 'setup ran before systemd reported ready' >&2
                    exit 1
                fi
                : > "$STUB_STATE/setup-ran"
                [ "${STUB_SETUP:-ok}" = ok ] || exit 1
                ;;
        esac
        ;;
esac
exit 0
SHIM
chmod +x "$shim/podman"

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

# run_case NAME EXPECTED_STATUS [STUB_...=VALUE ...]
#
# Runs the campaign's real bring-up against the stub runtime. The per-case
# assignments configure the stub; `STS2_SUPERVISOR_SOAK_SYSTEMD_READY_TRIES`
# is passed the same way, and is unset again for every case so one case cannot
# shorten another's budget. Leaves the run's status in `status`, its combined
# output in `out_file`, the runtime invocation log in `podman_log`, the stub's
# container state in `state_dir`, and the run's wall-clock in `case_seconds`.
run_case() {
    case_name=$1 expected_status=$2
    shift 2
    case_seq=$((case_seq + 1))
    case_dir=$work/case-$case_seq
    mkdir -p "$case_dir/tmp" "$case_dir/out" "$case_dir/state" "$case_dir/release"
    out_file=$case_dir/output
    podman_log=$case_dir/podman.log
    state_dir=$case_dir/state
    release=$case_dir/release
    printf '#!/bin/sh\nexit 0\n' > "$release/watchdog"
    chmod +x "$release/watchdog"
    printf '{"schema_version":1,"release":"stub"}\n' > "$release/release-manifest.json"
    : > "$podman_log"
    unset STS2_SUPERVISOR_SOAK_SYSTEMD_READY_TRIES 2>/dev/null || true
    export STUB_LOG=$podman_log STUB_STATE=$state_dir STUB_CONTAINER=$container
    export STUB_RUN=ok STUB_CP=ok STUB_SETUP=ok STUB_SYSTEMD=ready STUB_SYSTEMD_DELAY=0
    for assignment in "$@"; do
        export "$assignment"
    done
    started_at=$(date +%s)
    status=0
    TMPDIR=$case_dir/tmp PATH="$shim:$PATH" \
        sh "$campaign" start --release-dir "$release" --out-dir "$case_dir/out" \
        --container "$container" --duration-seconds 60 > "$out_file" 2>&1 || status=$?
    case_seconds=$(( $(date +%s) - started_at ))
    if [ "$status" -eq "$expected_status" ]; then
        record "$case_name status" 1 ""
    else
        record "$case_name status" 0 "expected $expected_status got $status: $(tail -n 1 "$out_file")"
    fi
}

# assert_started NAME / assert_window_not_opened NAME
#
# The campaign opens the window by printing `soak_started=`; nothing else may
# be reported as a started soak.
assert_started() {
    if grep -q '^soak_started=' "$out_file"; then
        record "$1 opened the window" 1 ""
    else
        record "$1 opened the window" 0 "no soak_started line: $(tail -n 1 "$out_file")"
    fi
}

assert_window_not_opened() {
    if grep -q '^soak_started=' "$out_file"; then
        record "$1 window stayed closed" 0 "reported a started soak: $(tail -n 1 "$out_file")"
    else
        record "$1 window stayed closed" 1 ""
    fi
}

# assert_setup_waited NAME
#
# The stub refuses a setup exec that arrives before its manager answered. This
# is the ordering a fixed sleep cannot express: the same assertion covers the
# waited-for case and the case where setup must never be reached at all.
assert_setup_waited() {
    if grep -qF 'setup ran before systemd reported ready' "$out_file"; then
        record "$1 setup waited for systemd" 0 'the setup exec arrived before the manager answered'
    else
        record "$1 setup waited for systemd" 1 ""
    fi
}

assert_setup_skipped() {
    if [ -e "$state_dir/setup-ran" ]; then
        record "$1 ran no setup exec" 0 'the container received a setup exec'
    else
        record "$1 ran no setup exec" 1 ""
    fi
}

# assert_named NAME PATTERN
#
# A fail-closed exit has to name what it refused; "exit 1" from whichever
# command happened to fail first is not an acceptable soak bring-up report.
assert_named() {
    name=$1 pattern=$2
    if grep -qF "$pattern" "$out_file"; then
        record "$name named the refusal" 1 ""
    else
        record "$name named the refusal" 0 "no \"$pattern\": $(tail -n 1 "$out_file")"
    fi
}

# reap_count is the number of `podman rm -f <container>` invocations. The
# campaign pre-cleans the name once before it creates anything, so a count of
# one means the container it created is still there and a count of two means
# bring-up took it back.
reap_count() {
    grep -cx "rm -f $container" "$podman_log" 2>/dev/null || true
}

assert_container_reaped() {
    if [ "$(reap_count)" -ge 2 ]; then
        record "$1 reaped its container" 1 ""
    else
        record "$1 reaped its container" 0 "reap invocations: $(reap_count)"
    fi
}

assert_container_left_running() {
    if [ "$(reap_count)" -eq 1 ]; then
        record "$1 left the window's container running" 1 ""
    else
        record "$1 left the window's container running" 0 "reap invocations: $(reap_count)"
    fi
}

# assert_staging_released NAME
#
# TMPDIR for the run is the case's own directory, so any staging copy the
# bring-up created is visible here if it was not released.
assert_staging_released() {
    leftover=$(find "$case_dir/tmp" -mindepth 1 2>/dev/null | head -n 3)
    if [ -z "$leftover" ]; then
        record "$1 released its staging copy" 1 ""
    else
        record "$1 released its staging copy" 0 "leftovers: $leftover"
    fi
}

# A container whose manager exits during bring-up fails the wait straight away
# rather than burning the readiness budget: on a supervised host the difference
# is minutes of a soak window that never opens.
assert_within() {
    name=$1 seconds=$2
    if [ "$case_seconds" -le "$seconds" ]; then
        record "$name failed closed promptly" 1 ""
    else
        record "$name failed closed promptly" 0 "took ${case_seconds}s, budget ${seconds}s"
    fi
}

# A container that boots normally opens the window, and the container it
# created is the window: reaping it would end the campaign immediately.
run_case ready_bringup_opens_the_window 0
assert_started ready_bringup_opens_the_window
assert_setup_waited ready_bringup_opens_the_window
assert_container_left_running ready_bringup_opens_the_window
assert_staging_released ready_bringup_opens_the_window

# The stub's manager answers 10 s after the container is created -- longer than
# the fixed `sleep 8` this replaced, so the ordering is what passes the case,
# not the delay. The number is the stub's, not a measurement of a real container.
run_case late_systemd_is_waited_for 0 STUB_SYSTEMD=late STUB_SYSTEMD_DELAY=10
assert_started late_systemd_is_waited_for
assert_setup_waited late_systemd_is_waited_for

# A manager that never answers ends the campaign before the window instead of
# starting a soak whose setup never ran.
run_case never_ready_fails_closed 69 STUB_SYSTEMD=never STS2_SUPERVISOR_SOAK_SYSTEMD_READY_TRIES=5
assert_window_not_opened never_ready_fails_closed
assert_named never_ready_fails_closed "never reported a running systemd manager"
assert_setup_skipped never_ready_fails_closed
assert_container_reaped never_ready_fails_closed
assert_staging_released never_ready_fails_closed

# A container that exits during bring-up fails the wait straight away rather
# than burning the whole readiness budget. The budget is 100 polls, so a
# campaign that only noticed at the end could not stay inside five seconds.
run_case dead_container_fails_closed 69 STUB_SYSTEMD=dead STS2_SUPERVISOR_SOAK_SYSTEMD_READY_TRIES=100
assert_window_not_opened dead_container_fails_closed
assert_named dead_container_fails_closed "exited before its systemd manager reported ready"
assert_setup_skipped dead_container_fails_closed
assert_container_reaped dead_container_fails_closed
assert_staging_released dead_container_fails_closed
assert_within dead_container_fails_closed 5

# The setup exec is the first thing that can fail inside a booted container, and
# the container is still the campaign's to take back when it does.
run_case setup_failure_fails_closed 69 STUB_SETUP=fail
assert_window_not_opened setup_failure_fails_closed
assert_named setup_failure_fails_closed "the supervisor soak setup failed inside $container"
assert_container_reaped setup_failure_fails_closed
assert_staging_released setup_failure_fails_closed

# The staging copy is delivered before the setup exec; a runtime that refuses
# the copy leaves the same privileged container behind.
run_case staging_delivery_failure_fails_closed 69 STUB_CP=fail
assert_window_not_opened staging_delivery_failure_fails_closed
assert_named staging_delivery_failure_fails_closed "the staging copy could not be delivered to $container"
assert_container_reaped staging_delivery_failure_fails_closed
assert_staging_released staging_delivery_failure_fails_closed

# The samples are the record of the window, so a log whose samples never saw an
# active supervisor must not finalize as a soak however long it ran. Elapsed
# wall-clock alone used to be the only gate, which let a campaign that never
# started the service be quoted as completed soak evidence.
mkdir -p "$work/finalize-inactive" "$work/finalize-supervised"
cat > "$work/finalize-inactive/soak.jsonl" <<'JSONL'
{"ts":"2026-09-01T00:00:00Z","active":"inactive","restarts":0,"rss_kb":0,"stable":0,"cycler":0,"components":[]}
{"ts":"2026-09-02T00:00:00Z","active":"inactive","restarts":0,"rss_kb":0,"stable":0,"cycler":0,"components":[]}
JSONL
cat > "$work/finalize-supervised/soak.jsonl" <<'JSONL'
{"ts":"2026-09-01T00:00:00Z","active":"inactive","restarts":0,"rss_kb":0,"stable":0,"cycler":0,"components":[]}
{"ts":"2026-09-02T00:00:00Z","active":"active","restarts":0,"rss_kb":0,"stable":1,"cycler":1,"components":[]}
JSONL

run_finalize() {
    case_name=$1 finalize_dir=$2 expected=$3
    status=0
    out_file=$work/finalize-$case_name.out
    PATH="$shim:$PATH" sh "$campaign" finalize --out-dir "$finalize_dir" \
        --duration-seconds 86400 > "$out_file" 2>&1 || status=$?
    if grep -qx "$expected" "$out_file"; then
        record "$case_name" 1 ""
    else
        record "$case_name" 0 "expected $expected got $(tail -n 1 "$out_file")"
    fi
}

run_finalize inactive_samples_do_not_finalize "$work/finalize-inactive" \
    'soak_complete=false required_active_samples=1 observed_active_samples=0'
run_finalize supervised_window_finalizes "$work/finalize-supervised" \
    'soak_complete=true'

if [ "$failures" -gt 0 ]; then
    printf '%s\n' "$failures failure(s)" >&2
    exit 1
fi
printf '%s\n' 'all supervisor soak bring-up regressions passed'
