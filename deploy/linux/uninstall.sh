#!/bin/sh
# Disable and remove only the service definition.  State and releases are
# preserved by default and require an explicit, separately audited operation.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'uninstall.sh must run as root' >&2
    exit 77
fi

systemctl disable ascension-watchdog.service >/dev/null 2>&1 || :
systemctl daemon-reload
rm -f -- /etc/systemd/system/ascension-watchdog.service
systemctl daemon-reload
printf '%s\n' 'ascension-watchdog service definition removed; state and releases were preserved.'
