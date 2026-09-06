#!/bin/sh
# Install one already validated immutable release.  Release validation and
# activation remain an audited watchdog operation; this wrapper only performs
# idempotent filesystem/service-manager setup.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'install.sh must run as root' >&2
    exit 77
fi
if [ "$#" -ne 1 ]; then
    printf '%s\n' 'usage: install.sh /absolute/path/to/validated-release' >&2
    exit 64
fi

release_dir=$(realpath -- "$1")
case "$release_dir" in
    /opt/ascension-watchdog/releases/*) : ;;
    *)
        printf '%s\n' 'release must already be under /opt/ascension-watchdog/releases' >&2
        exit 64
        ;;
esac
[ -d "$release_dir" ] || { printf '%s\n' 'release directory is missing' >&2; exit 66; }
[ -x "$release_dir/watchdog" ] || { printf '%s\n' 'release watchdog binary is missing' >&2; exit 66; }
[ -f "$release_dir/release-manifest.json" ] || { printf '%s\n' 'release manifest is missing' >&2; exit 66; }

if find -L "$release_dir" -type l -print -quit | grep -q .; then
    printf '%s\n' 'release contains a symbolic link' >&2
    exit 65
fi

install -d -o root -g root -m 0755 /etc/ascension-watchdog
install -d -o root -g root -m 0755 /opt/ascension-watchdog
install -d -o root -g root -m 0755 /opt/ascension-watchdog/releases

if ! getent group ascension-watchdog >/dev/null 2>&1; then
    groupadd --system ascension-watchdog
fi
if ! getent passwd ascension-watchdog >/dev/null 2>&1; then
    useradd --system --gid ascension-watchdog --home-dir /var/lib/ascension-watchdog \
        --no-create-home --shell /usr/sbin/nologin ascension-watchdog
fi
install -d -o ascension-watchdog -g ascension-watchdog -m 0750 /var/lib/ascension-watchdog

install -o root -g root -m 0644 \
    "$(dirname -- "$0")/ascension-watchdog.service" \
    /etc/systemd/system/ascension-watchdog.service

current=/opt/ascension-watchdog/current
if [ -e "$current" ] && [ "$(readlink -f -- "$current")" != "$release_dir" ]; then
    printf '%s\n' 'current release differs; use watchdog release activation before switching it' >&2
    exit 73
fi
if [ ! -e "$current" ]; then
    ln -s -- "$release_dir" "$current"
fi

chown -R root:root "$release_dir"
chmod -R a-w "$release_dir"
systemctl daemon-reload
systemctl enable ascension-watchdog.service >/dev/null
printf '%s\n' 'ascension-watchdog installation prepared; service was not started.'
