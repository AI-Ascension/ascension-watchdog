#!/bin/sh
# Reproducible supervisor soak campaign.
#
# Runs the shipped systemd unit inside a disposable, privileged Podman container
# with systemd as PID 1, supervises synthetic components, and records one JSONL
# sample per minute to a host directory.  It is supervisor-scope evidence only:
# it is not the cross-repository gameplay soak, and a run shorter than the
# requested duration is reported as incomplete rather than as a soak.
#
# Usage (on a host with podman and root):
#   supervisor-soak.sh start --release-dir DIR --duration-seconds N \
#       [--container NAME] [--image IMAGE] [--out-dir DIR]
#   supervisor-soak.sh finalize --out-dir DIR --duration-seconds N
#
# Exit codes: 64 usage, 66 missing release artifact or soak log, 69 the
# container bring-up did not become ready, 77 not root.
set -eu

usage() {
    printf '%s\n' 'usage: supervisor-soak.sh start|finalize --duration-seconds N [--release-dir DIR] [--out-dir DIR] [--container NAME] [--image IMAGE]' >&2
    exit 64
}

command_name=${1:-}
[ -n "$command_name" ] || usage
shift

release_dir=
out_dir=/var/log/ascension-soak
container=ascension-soak-campaign
image=docker.io/jrei/systemd-ubuntu:24.04
duration=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --release-dir) [ "$#" -ge 2 ] || usage; release_dir=$2; shift 2 ;;
        --out-dir) [ "$#" -ge 2 ] || usage; out_dir=$2; shift 2 ;;
        --container) [ "$#" -ge 2 ] || usage; container=$2; shift 2 ;;
        --image) [ "$#" -ge 2 ] || usage; image=$2; shift 2 ;;
        --duration-seconds) [ "$#" -ge 2 ] || usage; duration=$2; shift 2 ;;
        *) usage ;;
    esac
done

[ -n "$duration" ] || usage
[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'supervisor-soak.sh must run as root' >&2; exit 77; }

# The samples are the whole record of the window: a run whose samples are all
# `inactive` observed a supervisor that was never up, so elapsed wall-clock
# alone must not qualify it as a soak. Each refusing gate is printed with the
# value that refused it, because this output is what a 24-hour campaign's
# evidence quotes.
finalize() {
    [ -f "$out_dir/soak.jsonl" ] || { printf '%s\n' 'soak log is missing' >&2; exit 66; }
    first=$(head -1 "$out_dir/soak.jsonl" | sed -n 's/.*"ts":"\([^"]*\)".*/\1/p')
    last=$(tail -1 "$out_dir/soak.jsonl" | sed -n 's/.*"ts":"\([^"]*\)".*/\1/p')
    samples=$(wc -l < "$out_dir/soak.jsonl")
    first_epoch=$(date -u -d "$first" +%s)
    last_epoch=$(date -u -d "$last" +%s)
    elapsed=$((last_epoch - first_epoch))
    active_samples=$(grep -c '"active":"active"' "$out_dir/soak.jsonl" || true)
    printf 'samples=%s first=%s last=%s elapsed_seconds=%s active_samples=%s\n' \
        "$samples" "$first" "$last" "$elapsed" "$active_samples"
    if [ "$elapsed" -lt "$duration" ]; then
        printf 'soak_complete=false required_seconds=%s observed_seconds=%s\n' "$duration" "$elapsed"
    elif [ "$active_samples" -eq 0 ]; then
        printf '%s\n' 'soak_complete=false required_active_samples=1 observed_active_samples=0'
    else
        printf '%s\n' 'soak_complete=true'
    fi
}

if [ "$command_name" = finalize ]; then
    finalize
    exit 0
fi

[ "$command_name" = start ] || usage
[ -n "$release_dir" ] || usage
[ -x "$release_dir/watchdog" ] || { printf '%s\n' "release watchdog is missing: $release_dir/watchdog" >&2; exit 66; }
[ -f "$release_dir/release-manifest.json" ] || { printf '%s\n' 'release manifest is missing' >&2; exit 66; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_script=$script_dir/../linux/install.sh
unit_file=$script_dir/../linux/ascension-watchdog.service
[ -f "$install_script" ] || { printf '%s\n' "install script is missing: $install_script" >&2; exit 66; }
[ -f "$unit_file" ] || { printf '%s\n' "unit file is missing: $unit_file" >&2; exit 66; }

# `podman run -d --systemd=always` returns when the container is created, not
# when the systemd manager inside it can answer: the next `podman exec` runs
# `systemctl daemon-reload` and `systemctl start`, which fail with "Failed to
# connect to bus" while PID 1 is still coming up. That is the same defect shape
# as a launched gateway that has not reported that it is listening, and a fixed
# sleep cannot express the ordering at any delay. Poll for a manager that
# answers, and fail closed on the container's own log instead of opening a soak
# window whose setup never ran. Tests may shorten the budget with
# `STS2_SUPERVISOR_SOAK_SYSTEMD_READY_TRIES`; the default is 300 polls (30
# seconds of sleep between polls).
systemd_ready_tries=${STS2_SUPERVISOR_SOAK_SYSTEMD_READY_TRIES:-300}

container_running() {
    [ "$(podman inspect -f '{{.State.Running}}' "$container" 2>/dev/null || printf '%s' false)" = true ]
}

wait_for_systemd() {
    tries=0
    while [ "$tries" -lt "$systemd_ready_tries" ]; do
        # `degraded` is a reachable manager with a failed unit, an ordinary
        # first-boot state inside a disposable container; `starting` and an
        # unreachable bus both mean `systemctl start` cannot work yet.
        case "$(podman exec "$container" systemctl is-system-running 2>/dev/null || true)" in
            running|degraded) return 0 ;;
        esac
        container_running || return 1
        sleep 0.1
        tries=$((tries + 1))
    done
    return 1
}

# Bring-up owns the container and the staging copy until the window is open.
# Without this, a failed bring-up leaves a privileged systemd container holding
# the name the next run needs, and the staging copy it was fed is reachable only
# through that container. Once `soak_started` is printed the container is the
# window, so it is deliberately left running for `finalize`.
staging=
container_owned=0
cleanup_bringup() {
    status=$?
    if [ "$container_owned" -eq 1 ]; then
        podman rm -f "$container" >/dev/null 2>&1 || true
    fi
    if [ -n "$staging" ]; then
        find "$staging" -depth -mindepth 1 -delete 2>/dev/null || true
        rmdir "$staging" 2>/dev/null || true
    fi
    exit "$status"
}
trap cleanup_bringup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$out_dir"
staging=$(mktemp -d)
podman rm -f "$container" >/dev/null 2>&1 || true
if ! podman run -d --name "$container" --privileged --systemd=always \
    -v "$out_dir":/var/log/soak "$image" >/dev/null; then
    printf '%s\n' "the supervisor soak container $container could not be launched" >&2
    exit 69
fi
container_owned=1

if ! wait_for_systemd; then
    if container_running; then
        printf '%s\n' "the supervisor soak container $container never reported a running systemd manager" >&2
    else
        printf '%s\n' "the supervisor soak container $container exited before its systemd manager reported ready" >&2
    fi
    podman logs --tail 20 "$container" 2>&1 | sed 's/^/  /' >&2 || true
    exit 69
fi

cp "$release_dir/watchdog" "$staging/watchdog"
cp "$release_dir/release-manifest.json" "$staging/release-manifest.json"
cp "$install_script" "$staging/install.sh"
cp "$unit_file" "$staging/ascension-watchdog.service"
cat > "$staging/soak-config.json" <<JSON
{"schema_version":1,"deployment_id":"soak-campaign","database":"/var/lib/ascension-watchdog/soak.sqlite3","desired_mode":"running","probe_interval_ms":2000,"components":[{"id":"stable","executable":"/bin/sleep","args":["100000"],"restart":true},{"id":"cycler","executable":"/bin/sh","args":["-c","sleep 90"],"restart":true}],"allow_synthetic_children":true}
JSON
cat > "$staging/soak-collect.sh" <<'COL'
#!/bin/sh
LOG=/var/log/soak/soak.jsonl
PID=$(systemctl show ascension-watchdog.service -p MainPID --value)
RSS=0
if [ -n "$PID" ] && [ "$PID" != "0" ] && [ -r "/proc/$PID/status" ]; then
  RSS=$(awk '/^VmRSS:/{print $2}' "/proc/$PID/status")
fi
ACTIVE=$(systemctl is-active ascension-watchdog.service)
RESTARTS=$(systemctl show ascension-watchdog.service -p NRestarts --value)
STABLE=$(ps -eo comm,args | awk '$1=="sleep" && $3=="100000"' | wc -l)
CYCLER=$(ps -eo comm,args | awk '$1=="sleep" && $3=="90"' | wc -l)
# Component-level restart/budget state when the release binary supports it.
COMPONENTS=$(su -s /bin/sh ascension-watchdog -c "/opt/ascension-watchdog/current/watchdog components --config /etc/ascension-watchdog/watchdog.json" 2>/dev/null || printf '[]')
printf '{"ts":"%s","active":"%s","restarts":%s,"rss_kb":%s,"stable":%s,"cycler":%s,"components":%s}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ACTIVE" "${RESTARTS:-0}" "${RSS:-0}" "$STABLE" "$CYCLER" "$COMPONENTS" >> "$LOG"
COL
cat > "$staging/soak-setup.sh" <<'SETUP'
set -eu
REL=/opt/ascension-watchdog/releases/soak-campaign
mkdir -p "$REL"
install -m 0755 /root/staging/watchdog "$REL/watchdog"
install -m 0644 /root/staging/release-manifest.json "$REL/release-manifest.json"
mkdir -p /etc/ascension-watchdog
cp /root/staging/soak-config.json /etc/ascension-watchdog/watchdog.json
chmod 0644 /etc/ascension-watchdog/watchdog.json
sh /root/staging/install.sh "$REL"
su -s /bin/sh ascension-watchdog -c "/opt/ascension-watchdog/current/watchdog init --config /etc/ascension-watchdog/watchdog.json" >/dev/null
systemctl start ascension-watchdog.service
install -m 0755 /root/staging/soak-collect.sh /usr/local/bin/soak-collect.sh
cat > /etc/systemd/system/soak-collect.service <<'UNIT'
[Unit]
Description=soak collector
[Service]
Type=oneshot
ExecStart=/usr/local/bin/soak-collect.sh
UNIT
cat > /etc/systemd/system/soak-collect.timer <<'UNIT'
[Unit]
Description=soak collector timer
[Timer]
OnBootSec=20s
OnUnitActiveSec=60s
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now soak-collect.timer >/dev/null 2>&1
sleep 3
/usr/local/bin/soak-collect.sh
SETUP

if ! podman cp "$staging" "$container":/root/staging; then
    printf '%s\n' "the staging copy could not be delivered to $container" >&2
    exit 69
fi
if ! podman exec "$container" sh /root/staging/soak-setup.sh; then
    printf '%s\n' "the supervisor soak setup failed inside $container" >&2
    podman logs --tail 20 "$container" 2>&1 | sed 's/^/  /' >&2 || true
    exit 69
fi

started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
container_owned=0
printf 'soak_started=%s container=%s out_dir=%s duration_seconds=%s\n' "$started" "$container" "$out_dir" "$duration"
printf '%s\n' "finalize with: supervisor-soak.sh finalize --out-dir $out_dir --duration-seconds $duration"
