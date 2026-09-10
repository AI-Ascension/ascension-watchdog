#!/bin/sh
set -eu

# Install the broker as one root-owned package. This script deliberately does
# not enable or start the service; activation is an operator change after the
# installed policy and peer identity have been reviewed.

if [ "$(id -u)" -ne 0 ]; then
    echo "install-systemd-broker: run as root" >&2
    exit 1
fi

# The standard installer publishes the approved release through this
# root-owned, immutable symlink.  Keep the broker's default aligned with that
# layout; callers may still provide an explicit release directory for an
# offline staged install.
release_root=/opt/ascension-watchdog/current
policy_source=
peer_group=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --release-root)
            [ "$#" -ge 2 ] || { echo "missing --release-root value" >&2; exit 2; }
            release_root=$2
            shift 2
            ;;
        --policy)
            [ "$#" -ge 2 ] || { echo "missing --policy value" >&2; exit 2; }
            policy_source=$2
            shift 2
            ;;
        --peer-group)
            [ "$#" -ge 2 ] || { echo "missing --peer-group value" >&2; exit 2; }
            peer_group=$2
            shift 2
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

[ -n "$policy_source" ] || { echo "--policy is required" >&2; exit 2; }
[ -n "$peer_group" ] || { echo "--peer-group is required" >&2; exit 2; }
[ -f "$release_root/linux-systemd-broker" ] || {
    echo "broker binary is missing from release root" >&2
    exit 1
}
[ -f "$release_root/watchdog" ] || {
    echo "watchdog peer executable is missing from release root" >&2
    exit 1
}
[ -f "$policy_source" ] || { echo "policy file is missing" >&2; exit 1; }

group_gid=$(getent group "$peer_group" | awk -F: 'NR == 1 { print $3 }')
[ -n "$group_gid" ] || { echo "peer group does not exist" >&2; exit 1; }
policy_gid=$(jq -er '.peer.gid | numbers' "$policy_source")
[ "$policy_gid" = "$group_gid" ] || {
    echo "policy peer gid does not match the installed peer group" >&2
    exit 1
}

install -d -o root -g root -m 0755 /opt/ascension-watchdog/current
install -d -o root -g root -m 0755 /etc/ascension-watchdog
install -d -o root -g root -m 0750 /var/lib/ascension-watchdog-broker
install -o root -g root -m 0755 "$release_root/linux-systemd-broker" \
    /opt/ascension-watchdog/current/linux-systemd-broker
install -o root -g root -m 0755 "$release_root/watchdog" \
    /opt/ascension-watchdog/current/watchdog
install -o root -g root -m 0600 "$policy_source" \
    /etc/ascension-watchdog/broker-policy.json
install -o root -g root -m 0644 \
    "$(dirname "$0")/ascension-watchdog-broker.service" \
    /etc/systemd/system/ascension-watchdog-broker.service
systemctl daemon-reload
echo "broker installed; review policy, then enable/start ascension-watchdog-broker.service"
