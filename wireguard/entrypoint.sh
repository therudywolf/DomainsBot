#!/bin/sh
set -e

CONFIG=/etc/wireguard/wg0.conf
if [ ! -f "$CONFIG" ]; then
    echo "No $CONFIG found"
    exit 1
fi

TMP=/tmp/wg0.conf
cp "$CONFIG" "$TMP"

# Add Table = off in [Interface] so wg-quick does not use fwmark/sysctl (works in any container)
if ! grep -qE '^\s*Table\s*=' "$TMP"; then
    sed -i '/^\[Peer\]/i Table = off' "$TMP"
fi

finish() {
    wg-quick down wg0 2>/dev/null || true
    exit 0
}
trap finish SIGTERM SIGINT SIGQUIT

# Bring up interface without policy routing (no src_valid_mark needed)
wg-quick up "$TMP"

# Add default route for full-tunnel (0.0.0.0/0)
ip route add 0.0.0.0/0 dev wg0 2>/dev/null || true

sleep infinity &
wait $!
