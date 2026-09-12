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

finalize() {
    [ -f "$out_dir/soak.jsonl" ] || { printf '%s\n' 'soak log is missing' >&2; exit 66; }
    first=$(head -1 "$out_dir/soak.jsonl" | sed -n 's/.*"ts":"\([^"]*\)".*/\1/p')
    last=$(tail -1 "$out_dir/soak.jsonl" | sed -n 's/.*"ts":"\([^"]*\)".*/\1/p')
    samples=$(wc -l < "$out_dir/soak.jsonl")
    first_epoch=$(date -u -d "$first" +%s)
    last_epoch=$(date -u -d "$last" +%s)
    elapsed=$((last_epoch - first_epoch))
    inactive=$(grep -c '"active":"active"' "$out_dir/soak.jsonl" || true)
    printf 'samples=%s first=%s last=%s elapsed_seconds=%s active_samples=%s\n' \
        "$samples" "$first" "$last" "$elapsed" "$inactive"
    if [ "$elapsed" -ge "$duration" ]; then
        printf '%s\n' 'soak_complete=true'
    else
        printf 'soak_complete=false required_seconds=%s\n' "$duration"
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

mkdir -p "$out_dir"
podman rm -f "$container" >/dev/null 2>&1 || true
podman run -d --name "$container" --privileged --systemd=always \
    -v "$out_dir":/var/log/soak "$image" >/dev/null
sleep 8

staging=$(mktemp -d)
trap 'find "$staging" -type f -delete 2>/dev/null || true; rmdir "$staging" 2>/dev/null || true' EXIT
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
printf '{"ts":"%s","active":"%s","restarts":%s,"rss_kb":%s,"stable":%s,"cycler":%s}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ACTIVE" "${RESTARTS:-0}" "${RSS:-0}" "$STABLE" "$CYCLER" >> "$LOG"
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

podman cp "$staging" "$container":/root/staging
podman exec "$container" sh /root/staging/soak-setup.sh

started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf 'soak_started=%s container=%s out_dir=%s duration_seconds=%s\n' "$started" "$container" "$out_dir" "$duration"
printf '%s\n' "finalize with: supervisor-soak.sh finalize --out-dir $out_dir --duration-seconds $duration"
