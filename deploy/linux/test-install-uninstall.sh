#!/bin/sh
# Synthetic, namespace-isolated coverage for the Linux install/uninstall
# wrappers.  This never touches the host's /etc, /opt, or /var trees and never
# starts a service; it exercises only the wrapper control flow with command
# shims and a fake watchdog status binary.
set -eu

repository=$1

# Mount the private runtime scratch area before creating any fixture files;
# nothing under the host's /tmp is used by this test.
mount -t tmpfs tmpfs /run || {
    printf '%s\n' 'skipping namespace installer test: tmpfs mount unavailable' >&2
    exit 77
}

# Keep the namespace's /etc small but usable by dynamically linked utilities.
test_root=/run/ascension-watchdog-linux-install-test
mkdir -p "$test_root/etc-skel"
for file in /etc/ld.so.cache /etc/ld.so.conf; do
    if [ -f "$file" ]; then
        cp -- "$file" "$test_root/etc-skel/"
    fi
done
if [ -d /etc/ld.so.conf.d ]; then
    cp -R -- /etc/ld.so.conf.d "$test_root/etc-skel/"
fi
mount -t tmpfs tmpfs /etc || {
    printf '%s\n' 'skipping namespace installer test: tmpfs mount unavailable' >&2
    exit 77
}
mount -t tmpfs tmpfs /opt || {
    printf '%s\n' 'skipping namespace installer test: tmpfs mount unavailable' >&2
    exit 77
}
mount -t tmpfs tmpfs /var || {
    printf '%s\n' 'skipping namespace installer test: tmpfs mount unavailable' >&2
    exit 77
}
cp -R -- "$test_root/etc-skel/." /etc/
mkdir -p /etc/ascension-watchdog /etc/systemd/system

shim_bin=/run/shims
mkdir -p "$shim_bin"

cat >"$shim_bin/id" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-u" ]; then
    printf '%s\n' 0
else
    exec /usr/bin/id "$@"
fi
EOF

cat >"$shim_bin/getent" <<'EOF'
#!/bin/sh
case "${1:-}" in
    group)
        [ -e /run/group-created ]
        ;;
    passwd)
        [ -e /run/user-created ]
        ;;
    *)
        exit 2
        ;;
esac
EOF

cat >"$shim_bin/groupadd" <<'EOF'
#!/bin/sh
printf '%s\n' groupadd >>/run/commands.log
touch /run/group-created
EOF

cat >"$shim_bin/useradd" <<'EOF'
#!/bin/sh
printf '%s\n' useradd >>/run/commands.log
touch /run/user-created
EOF

cat >"$shim_bin/chown" <<'EOF'
#!/bin/sh
printf 'chown %s\n' "$*" >>/run/commands.log
EOF

cat >"$shim_bin/chmod" <<'EOF'
#!/bin/sh
printf 'chmod %s\n' "$*" >>/run/commands.log
exec /usr/bin/chmod "$@"
EOF

cat >"$shim_bin/install" <<'EOF'
#!/bin/sh
set -eu
directory=false
source=
destination=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -d)
            directory=true
            shift
            ;;
        -o|-g|-m)
            [ "$#" -ge 2 ]
            shift 2
            ;;
        --)
            shift
            ;;
        *)
            if [ -z "$source" ]; then
                source=$1
            else
                destination=$1
            fi
            shift
            ;;
    esac
done
if [ "$directory" = true ]; then
    mkdir -p -- "$source"
else
    [ -n "$source" ] && [ -n "$destination" ]
    mkdir -p -- "$(dirname -- "$destination")"
    cp -- "$source" "$destination"
fi
EOF

cat >"$shim_bin/systemctl" <<'EOF'
#!/bin/sh
set -eu
printf 'systemctl %s\n' "$*" >>/run/commands.log
case "${1:-}" in
    daemon-reload|enable|disable)
        exit 0
        ;;
    is-active)
        if [ -e /run/systemd-active ]; then
            exit 0
        fi
        # systemctl's documented inactive/not-running result.  Any other
        # status is intentionally not synthesized by this fixture.
        exit 3
        ;;
    stop)
        [ -e /run/systemd-active ]
        rm -f /run/systemd-active
        touch /run/stop-requested
        ;;
    *)
        exit 2
        ;;
esac
EOF

cat >"$shim_bin/jq" <<'EOF'
#!/bin/sh
set -eu
[ "${1:-}" = "-e" ]
[ "${2:-}" = '.desired_mode == "stopped"' ]
status=$(cat)
printf '%s' "$status" | grep -Eq '"desired_mode"[[:space:]]*:[[:space:]]*"stopped"'
EOF

chmod 0755 "$shim_bin"/*
export PATH="$shim_bin:$PATH"

release=/opt/ascension-watchdog/releases/test-release
mkdir -p "$release"
cat >"$release/watchdog" <<'EOF'
#!/bin/sh
if [ -e /run/stop-requested ]; then
    printf '%s\n' '{"desired_mode":"stopped"}'
else
    printf '%s\n' '{"desired_mode":"running"}'
fi
EOF
chmod 0755 "$release/watchdog"
printf '%s\n' '{}' >"$release/release-manifest.json"
printf '%s\n' '{}' > /etc/ascension-watchdog/watchdog.json

install_script=$repository/deploy/linux/install.sh
uninstall_script=$repository/deploy/linux/uninstall.sh

# Two installs must converge on one fixed current release and must not start
# anything.  Account creation is also expected exactly once.
sh "$install_script" "$release" >/run/install-first.out
current_target=$(readlink -f -- /opt/ascension-watchdog/current)
[ "$current_target" = "$release" ]
sh "$install_script" "$release" >/run/install-second.out
[ "$(readlink -f -- /opt/ascension-watchdog/current)" = "$release" ]
[ "$(grep -c '^groupadd$' /run/commands.log)" -eq 1 ]
[ "$(grep -c '^useradd$' /run/commands.log)" -eq 1 ]
! grep -Eq '(^| )start( |$)' /run/commands.log

# A stopped systemd unit with a still-running watchdog owner must not permit
# removal: this is the intentional-stop persistence gate.
rm -f /run/stop-requested /run/systemd-active
if sh "$uninstall_script" --watchdog /opt/ascension-watchdog/current/watchdog \
    --config /etc/ascension-watchdog/watchdog.json >/run/uninstall-not-stopped.out 2>/run/uninstall-not-stopped.err; then
    printf '%s\n' 'uninstall unexpectedly accepted non-stopped owner state' >&2
    exit 1
fi
[ -f /etc/systemd/system/ascension-watchdog.service ]

# Once the service manager reports an active unit, the wrapper stops it first;
# the same owner-local status then proves durable stopped intent. A second run
# is idempotent and preserves both state and releases.
touch /run/systemd-active
sh "$uninstall_script" --watchdog /opt/ascension-watchdog/current/watchdog \
    --config /etc/ascension-watchdog/watchdog.json >/run/uninstall-first.out
[ ! -e /etc/systemd/system/ascension-watchdog.service ]
[ -d /var/lib/ascension-watchdog ]
[ -d "$release" ]
[ -L /opt/ascension-watchdog/current ]
[ "$(readlink -f -- /opt/ascension-watchdog/current)" = "$release" ]
sh "$uninstall_script" --watchdog /opt/ascension-watchdog/current/watchdog \
    --config /etc/ascension-watchdog/watchdog.json >/run/uninstall-second.out
[ ! -e /etc/systemd/system/ascension-watchdog.service ]
[ "$(grep -c '^systemctl stop ' /run/commands.log)" -eq 1 ]

printf '%s\n' 'linux install/uninstall namespace test passed'
