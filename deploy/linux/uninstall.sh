#!/bin/sh
# Disable and remove only the service definition.  State and releases are
# preserved by default and require an explicit, separately audited operation.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'uninstall.sh must run as root' >&2
    exit 77
fi

watchdog=/opt/ascension-watchdog/current/watchdog
config=/etc/ascension-watchdog/watchdog.json
while [ "$#" -gt 0 ]; do
    case "$1" in
        --watchdog)
            [ "$#" -ge 2 ] || { printf '%s\n' 'missing --watchdog value' >&2; exit 64; }
            watchdog=$2
            shift 2
            ;;
        --config)
            [ "$#" -ge 2 ] || { printf '%s\n' 'missing --config value' >&2; exit 64; }
            config=$2
            shift 2
            ;;
        *)
            printf 'usage: uninstall.sh [--watchdog PATH] [--config PATH]\n' >&2
            exit 64
            ;;
    esac
done

# A manager stop is not, by itself, durable watchdog intent: a forced service
# termination could leave the store in Running mode and a later reinstall
# could revive work. Require an existing owner binary/config, stop an active
# unit, then inspect the same owner-local store before removing the unit.
#
# The durable-mode check must not depend on the authenticated admin channel:
# `status` uses that channel when a deployment configures one, and the admin
# endpoint is owned by the service account, so the root uninstaller could not
# reach it. `diagnostics` is a bounded read-only owner-store snapshot that
# needs no admin transport, so it works for the root uninstaller.
[ -x "$watchdog" ] || { printf '%s\n' "watchdog executable is missing: $watchdog" >&2; exit 66; }
[ -f "$config" ] || { printf '%s\n' "watchdog configuration is missing: $config" >&2; exit 66; }
if systemctl is-active --quiet ascension-watchdog.service; then
    systemctl stop ascension-watchdog.service
fi
status_json=$("$watchdog" diagnostics --config "$config") || {
    printf '%s\n' 'watchdog diagnostics could not prove the owner-local store is readable' >&2
    exit 1
}
printf '%s' "$status_json" | jq -e '.desired_mode == "stopped"' >/dev/null || {
    printf '%s\n' 'watchdog desired mode is not durably stopped; service definition was preserved' >&2
    exit 1
}

systemctl disable ascension-watchdog.service >/dev/null 2>&1 || :
systemctl daemon-reload
rm -f -- /etc/systemd/system/ascension-watchdog.service
systemctl daemon-reload
printf '%s\n' 'ascension-watchdog service definition removed; state and releases were preserved.'
