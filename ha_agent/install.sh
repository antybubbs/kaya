#!/bin/sh
set -eu

fail() { printf 'Kaya HA agent installation failed: %s\n' "$1" >&2; exit 1; }
usage() { printf 'Usage: sudo sh install.sh --kaya-url URL --cluster-id UUID --node-id UUID\n' >&2; exit 2; }

[ "$(id -u)" -eq 0 ] || fail "run this installer with sudo"

KAYA_URL=""
CLUSTER_ID=""
NODE_ID=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --kaya-url) [ "$#" -ge 2 ] || usage; KAYA_URL=${2%/}; shift 2 ;;
        --cluster-id) [ "$#" -ge 2 ] || usage; CLUSTER_ID=$2; shift 2 ;;
        --node-id) [ "$#" -ge 2 ] || usage; NODE_ID=$2; shift 2 ;;
        *) usage ;;
    esac
done

case "$KAYA_URL" in http://*|https://*) ;; *) fail "Kaya URL must start with http:// or https://" ;; esac
[ -n "$CLUSTER_ID" ] && [ -n "$NODE_ID" ] || usage
command -v apt-get >/dev/null 2>&1 || fail "this installer currently supports Debian, Ubuntu, and Raspberry Pi OS"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"

printf 'Installing Keepalived and Kaya HA agent dependencies...\n'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl keepalived python3 python3-cryptography sudo

if ! getent group kaya-ha >/dev/null 2>&1; then addgroup --system kaya-ha; fi
if ! id kaya-ha >/dev/null 2>&1; then
    adduser --system --ingroup kaya-ha --home /var/lib/kaya-ha-agent --no-create-home --shell /usr/sbin/nologin kaya-ha
fi

install -d -m 0755 -o root -g root /usr/lib/kaya-ha-agent /etc/keepalived/conf.d
install -d -m 0700 -o kaya-ha -g kaya-ha /var/lib/kaya-ha-agent
TEMP_DIR=$(mktemp -d /tmp/kaya-ha-install.XXXXXX)
WAS_ACTIVE=0
INSTALL_OK=0
cleanup() {
    stty echo </dev/tty 2>/dev/null || true
    rm -rf "$TEMP_DIR"
    if [ "$WAS_ACTIVE" -eq 1 ] && [ "$INSTALL_OK" -eq 0 ]; then systemctl start kaya-ha-agent.service 2>/dev/null || true; fi
}
trap cleanup EXIT HUP INT TERM
SOURCE_BASE="$KAYA_URL/api/ha/agent/v1/files"

for file in kaya_ha_agent.py keepalived_runtime.py failover_runtime.py kaya_ha_keepalived_helper.py kaya_ha_failover_helper.py kaya_ha_transition.py check-pihole-dns kaya-ha-agent.service kaya-ha-agent.sudoers; do
    curl --fail --show-error --silent --location "$SOURCE_BASE/$file" --output "$TEMP_DIR/$file" || fail "could not download $file from Kaya"
done

python3 -m py_compile "$TEMP_DIR/kaya_ha_agent.py" "$TEMP_DIR/keepalived_runtime.py" "$TEMP_DIR/failover_runtime.py" "$TEMP_DIR/kaya_ha_keepalived_helper.py" "$TEMP_DIR/kaya_ha_failover_helper.py" "$TEMP_DIR/kaya_ha_transition.py" || fail "downloaded Python files did not validate"
visudo -cf "$TEMP_DIR/kaya-ha-agent.sudoers" >/dev/null || fail "the restricted sudo policy did not validate"
install -m 0755 -o root -g root "$TEMP_DIR/kaya_ha_agent.py" "$TEMP_DIR/keepalived_runtime.py" "$TEMP_DIR/failover_runtime.py" "$TEMP_DIR/kaya_ha_keepalived_helper.py" "$TEMP_DIR/kaya_ha_failover_helper.py" "$TEMP_DIR/kaya_ha_transition.py" "$TEMP_DIR/check-pihole-dns" /usr/lib/kaya-ha-agent/
install -m 0440 -o root -g root "$TEMP_DIR/kaya-ha-agent.sudoers" /etc/sudoers.d/kaya-ha-agent
install -m 0644 -o root -g root "$TEMP_DIR/kaya-ha-agent.service" /etc/systemd/system/kaya-ha-agent.service
if [ -e /etc/pihole/dhcp.leases ] && getent passwd pihole >/dev/null 2>&1 && getent group pihole >/dev/null 2>&1; then
    chown pihole:pihole /etc/pihole/dhcp.leases
    chmod u+rw /etc/pihole/dhcp.leases
fi

printf 'Paste the one-time registration token from Kaya (input is hidden): '
stty -echo </dev/tty
IFS= read -r REGISTRATION_TOKEN </dev/tty || { stty echo </dev/tty; fail "could not read the registration token"; }
stty echo </dev/tty
printf '\n'
[ -n "$REGISTRATION_TOKEN" ] || fail "registration token cannot be empty"

if systemctl is-active --quiet kaya-ha-agent.service 2>/dev/null; then WAS_ACTIVE=1; systemctl stop kaya-ha-agent.service; fi
printf '%s\n' "$REGISTRATION_TOKEN" | runuser -u kaya-ha -- /usr/bin/python3 /usr/lib/kaya-ha-agent/kaya_ha_agent.py register --kaya-url "$KAYA_URL" --cluster-id "$CLUSTER_ID" --node-id "$NODE_ID" --token-stdin
unset REGISTRATION_TOKEN
systemctl daemon-reload
systemctl enable keepalived.service >/dev/null
systemctl enable --now kaya-ha-agent.service
systemctl is-active --quiet kaya-ha-agent.service || fail "the agent service did not start"
INSTALL_OK=1
printf 'Kaya HA agent registered and running. Return to the Agents page and wait for its first heartbeat.\n'
