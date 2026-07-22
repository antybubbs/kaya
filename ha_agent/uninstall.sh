#!/bin/sh
set -eu

fail() { printf 'Kaya HA agent removal failed: %s\n' "$1" >&2; exit 1; }
usage() { printf 'Usage: sudo sh uninstall.sh --remove-kaya-ha-config\n' >&2; exit 2; }

[ "$(id -u)" -eq 0 ] || fail "run this uninstaller with sudo"
[ "${1:-}" = "--remove-kaya-ha-config" ] && [ "$#" -eq 1 ] || usage

printf 'Stopping and disabling the Kaya HA agent...\n'
systemctl disable --now kaya-ha-agent.service 2>/dev/null || true

MANAGED_CONFIG=/etc/keepalived/conf.d/kaya-ha.conf
CONFIG_BACKUP=""
if [ -f "$MANAGED_CONFIG" ]; then
    CONFIG_BACKUP=$(mktemp /tmp/kaya-ha-keepalived.XXXXXX)
    cp "$MANAGED_CONFIG" "$CONFIG_BACKUP"
    rm -f "$MANAGED_CONFIG"
    if command -v keepalived >/dev/null 2>&1 && ! keepalived --config-test >/dev/null 2>&1; then
        install -m 0644 -o root -g root "$CONFIG_BACKUP" "$MANAGED_CONFIG"
        rm -f "$CONFIG_BACKUP"
        fail "Keepalived configuration would be invalid without the Kaya include; it was restored"
    fi
    if systemctl is-active --quiet keepalived.service 2>/dev/null; then systemctl reload keepalived.service || systemctl restart keepalived.service; fi
    rm -f "$CONFIG_BACKUP"
fi

rm -f /etc/systemd/system/kaya-ha-agent.service /etc/sudoers.d/kaya-ha-agent
rm -rf /usr/lib/kaya-ha-agent /var/lib/kaya-ha-agent
systemctl daemon-reload
if id kaya-ha >/dev/null 2>&1; then deluser --system kaya-ha >/dev/null 2>&1 || true; fi
if getent group kaya-ha >/dev/null 2>&1; then delgroup --system kaya-ha >/dev/null 2>&1 || true; fi

printf 'Kaya HA agent, local identity, state, and Kaya-managed Keepalived configuration were removed. Pi-hole and the Keepalived package were not uninstalled.\n'
