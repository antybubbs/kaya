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
# "active" right after "systemctl start" proves only that the process was launched.  Success
# requires the same agent process to stay up for MIN_STABLE seconds AND Kaya to have accepted a
# heartbeat reporting the new version after this update started.  Otherwise the update fails and
# the trap restores the previous agent files.
accepted_version_since() {
    python3 - "$1" <<'PY'
import json, sqlite3, sys
from datetime import datetime, timezone
try:
    with sqlite3.connect("file:/var/lib/kaya-ha-agent/state.sqlite3?mode=ro", uri=True, timeout=5) as db:
        row = db.execute("SELECT value FROM state WHERE key = 'last_accepted_heartbeat'").fetchone()
    value = json.loads(row[0]) if row else {}
    at = datetime.fromisoformat(str(value.get("at")))
    ok = at.timestamp() >= int(sys.argv[1])
    print(value.get("agent_version") if ok else "")
except Exception:
    print("")
PY
}
confirm_updated_agent() {
    expected="$1"
    first_pid="$(systemctl show kaya-ha-agent.service --property=MainPID --value)"
    case "$first_pid" in ''|0|*[!0-9]*) fail "the updated agent service has no running process" ;; esac
    elapsed=0
    while [ "$elapsed" -lt "$HEALTH_TIMEOUT" ]; do
        sleep 2
        elapsed=$((elapsed + 2))
        systemctl is-active --quiet kaya-ha-agent.service || fail "the updated agent stopped running after it started"
        [ "$(systemctl show kaya-ha-agent.service --property=MainPID --value)" = "$first_pid" ] || fail "the updated agent restarted after it started (unstable)"
        if [ "$elapsed" -ge "$MIN_STABLE" ] && [ "$(accepted_version_since "$UPDATE_STARTED")" = "$expected" ]; then
            return 0
        fi
    done
    fail "Kaya did not confirm a heartbeat from agent $expected within ${HEALTH_TIMEOUT}s"
}

[ "$(id -u)" -eq 0 ] || fail "run this updater with sudo"
HEALTH_TIMEOUT=${KAYA_UPDATE_HEALTH_TIMEOUT:-120}
MIN_STABLE=${KAYA_UPDATE_MIN_STABLE:-20}
case "$HEALTH_TIMEOUT$MIN_STABLE" in *[!0-9]*|'') fail "health-check timings must be whole seconds" ;; esac
[ "$MIN_STABLE" -ge 10 ] && [ "$HEALTH_TIMEOUT" -ge "$MIN_STABLE" ] && [ "$HEALTH_TIMEOUT" -le 600 ] || fail "health-check timings are out of range"
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
        # Stop the updated agent first: otherwise "start" is a no-op and the new code keeps running.
        systemctl stop kaya-ha-agent.service
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
for file in kaya_ha_agent.py keepalived_runtime.py failover_runtime.py resolver_runtime.py kaya_ha_keepalived_helper.py kaya_ha_failover_helper.py kaya_ha_resolver_helper.py kaya_ha_transition.py check-pihole-dns kaya-ha-agent.service kaya-ha-agent.sudoers; do
    curl --fail --show-error --silent --location "$SOURCE_BASE/$file" --output "$TEMP_DIR/$file" || fail "could not download $file from Kaya"
done
python3 -m py_compile "$TEMP_DIR/kaya_ha_agent.py" "$TEMP_DIR/keepalived_runtime.py" "$TEMP_DIR/failover_runtime.py" "$TEMP_DIR/resolver_runtime.py" "$TEMP_DIR/kaya_ha_keepalived_helper.py" "$TEMP_DIR/kaya_ha_failover_helper.py" "$TEMP_DIR/kaya_ha_resolver_helper.py" "$TEMP_DIR/kaya_ha_transition.py" || fail "downloaded Python files did not validate"
visudo -cf "$TEMP_DIR/kaya-ha-agent.sudoers" >/dev/null || fail "the restricted sudo policy did not validate"
validate_service_unit "$TEMP_DIR/kaya-ha-agent.service"
EXPECTED_VERSION=$(sed -n 's/^AGENT_VERSION = "\([0-9][0-9.]*\)".*$/\1/p' "$TEMP_DIR/kaya_ha_agent.py" | head -1)
[ -n "$EXPECTED_VERSION" ] || fail "the downloaded agent does not declare its version"

mkdir -p "$BACKUP_DIR/lib"
cp -a /usr/lib/kaya-ha-agent/. "$BACKUP_DIR/lib/"
[ ! -f /etc/systemd/system/kaya-ha-agent.service ] || cp -a /etc/systemd/system/kaya-ha-agent.service "$BACKUP_DIR/service"
[ ! -f /etc/sudoers.d/kaya-ha-agent ] || cp -a /etc/sudoers.d/kaya-ha-agent "$BACKUP_DIR/sudoers"
systemctl stop kaya-ha-agent.service
FILES_INSTALLED=1
install -m 0755 -o root -g root "$TEMP_DIR/kaya_ha_agent.py" "$TEMP_DIR/keepalived_runtime.py" "$TEMP_DIR/failover_runtime.py" "$TEMP_DIR/resolver_runtime.py" "$TEMP_DIR/kaya_ha_keepalived_helper.py" "$TEMP_DIR/kaya_ha_failover_helper.py" "$TEMP_DIR/kaya_ha_resolver_helper.py" "$TEMP_DIR/kaya_ha_transition.py" "$TEMP_DIR/check-pihole-dns" /usr/lib/kaya-ha-agent/
install -m 0440 -o root -g root "$TEMP_DIR/kaya-ha-agent.sudoers" /etc/sudoers.d/kaya-ha-agent
install -m 0644 -o root -g root "$TEMP_DIR/kaya-ha-agent.service" /etc/systemd/system/kaya-ha-agent.service
systemctl daemon-reload
UPDATE_STARTED=$(date +%s)
systemctl start kaya-ha-agent.service
systemctl is-active --quiet kaya-ha-agent.service || fail "the updated agent service did not start"
verify_running_service
printf 'Waiting for the updated agent (%s) to stay healthy and for Kaya to confirm its heartbeat...\n' "$EXPECTED_VERSION"
confirm_updated_agent "$EXPECTED_VERSION"
UPDATE_OK=1
printf 'Kaya HA agent updated successfully. The existing node identity and Kaya link were preserved.\n'
