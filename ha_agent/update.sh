#!/bin/sh
set -eu

fail() { printf 'Kaya HA agent update failed: %s\n' "$1" >&2; exit 1; }
usage() { printf 'Usage: sudo sh update.sh --kaya-url URL\n' >&2; exit 2; }
validate_service_unit() {
    grep -qx 'User=kaya-ha' "$1" || fail "the service unit must run as kaya-ha"
    grep -qx 'AmbientCapabilities=CAP_NET_RAW' "$1" || fail "the service unit is missing its required ICMP capability"
}
verify_running_service() {
    [ "$(systemctl show kaya-ha-agent.service --property=User --value)" = "kaya-ha" ] || fail "the agent service is not running as kaya-ha"
    systemctl show kaya-ha-agent.service --property=AmbientCapabilities --value | grep -qi 'cap_net_raw' || fail "the running agent service does not have CAP_NET_RAW"
}

[ "$(id -u)" -eq 0 ] || fail "run this updater with sudo"
KAYA_URL=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --kaya-url) [ "$#" -ge 2 ] || usage; KAYA_URL=${2%/}; shift 2 ;;
        *) usage ;;
    esac
done
case "$KAYA_URL" in http://*|https://*) ;; *) fail "Kaya URL must start with http:// or https://" ;; esac
[ -s /var/lib/kaya-ha-agent/config.json ] || fail "this Pi-hole is not linked to Kaya; use Install agent instead"
[ -s /var/lib/kaya-ha-agent/agent.key ] || fail "the existing agent identity is missing; use Re-link agent in Kaya"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"

TEMP_DIR=$(mktemp -d /tmp/kaya-ha-update.XXXXXX)
BACKUP_DIR="$TEMP_DIR/backup"
FILES_INSTALLED=0
UPDATE_OK=0
cleanup() {
    set +e
    if [ "$FILES_INSTALLED" -eq 1 ] && [ "$UPDATE_OK" -eq 0 ]; then
        printf 'Update did not complete; restoring the previous agent files...\n' >&2
        [ ! -d "$BACKUP_DIR/lib" ] || cp -a "$BACKUP_DIR/lib/." /usr/lib/kaya-ha-agent/
        [ ! -f "$BACKUP_DIR/service" ] || install -m 0644 -o root -g root "$BACKUP_DIR/service" /etc/systemd/system/kaya-ha-agent.service
        [ ! -f "$BACKUP_DIR/sudoers" ] || install -m 0440 -o root -g root "$BACKUP_DIR/sudoers" /etc/sudoers.d/kaya-ha-agent
        systemctl daemon-reload
        systemctl start kaya-ha-agent.service
    fi
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT HUP INT TERM

SOURCE_BASE="$KAYA_URL/api/ha/agent/v1/files"
for file in kaya_ha_agent.py keepalived_runtime.py failover_runtime.py kaya_ha_keepalived_helper.py kaya_ha_failover_helper.py kaya_ha_transition.py check-pihole-dns kaya-ha-agent.service kaya-ha-agent.sudoers; do
    curl --fail --show-error --silent --location "$SOURCE_BASE/$file" --output "$TEMP_DIR/$file" || fail "could not download $file from Kaya"
done
python3 -m py_compile "$TEMP_DIR/kaya_ha_agent.py" "$TEMP_DIR/keepalived_runtime.py" "$TEMP_DIR/failover_runtime.py" "$TEMP_DIR/kaya_ha_keepalived_helper.py" "$TEMP_DIR/kaya_ha_failover_helper.py" "$TEMP_DIR/kaya_ha_transition.py" || fail "downloaded Python files did not validate"
visudo -cf "$TEMP_DIR/kaya-ha-agent.sudoers" >/dev/null || fail "the restricted sudo policy did not validate"
validate_service_unit "$TEMP_DIR/kaya-ha-agent.service"

mkdir -p "$BACKUP_DIR/lib"
cp -a /usr/lib/kaya-ha-agent/. "$BACKUP_DIR/lib/"
[ ! -f /etc/systemd/system/kaya-ha-agent.service ] || cp -a /etc/systemd/system/kaya-ha-agent.service "$BACKUP_DIR/service"
[ ! -f /etc/sudoers.d/kaya-ha-agent ] || cp -a /etc/sudoers.d/kaya-ha-agent "$BACKUP_DIR/sudoers"
systemctl stop kaya-ha-agent.service
FILES_INSTALLED=1
install -m 0755 -o root -g root "$TEMP_DIR/kaya_ha_agent.py" "$TEMP_DIR/keepalived_runtime.py" "$TEMP_DIR/failover_runtime.py" "$TEMP_DIR/kaya_ha_keepalived_helper.py" "$TEMP_DIR/kaya_ha_failover_helper.py" "$TEMP_DIR/kaya_ha_transition.py" "$TEMP_DIR/check-pihole-dns" /usr/lib/kaya-ha-agent/
install -m 0440 -o root -g root "$TEMP_DIR/kaya-ha-agent.sudoers" /etc/sudoers.d/kaya-ha-agent
install -m 0644 -o root -g root "$TEMP_DIR/kaya-ha-agent.service" /etc/systemd/system/kaya-ha-agent.service
systemctl daemon-reload
systemctl start kaya-ha-agent.service
systemctl is-active --quiet kaya-ha-agent.service || fail "the updated agent service did not start"
verify_running_service
UPDATE_OK=1
printf 'Kaya HA agent updated successfully. The existing node identity and Kaya link were preserved.\n'
