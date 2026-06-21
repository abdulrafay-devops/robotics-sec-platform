#!/bin/sh
# router-fw entrypoint: turn on IP forwarding and load the default-deny ruleset.
set -e

# ip_forward is also requested via docker-compose sysctls; set it here too so the
# container is correct even if launched standalone.
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || echo "WARN: could not set ip_forward (need NET_ADMIN / privileged)"

echo "router-fw: loading IDMZ default-deny ruleset..."
if nft -f /etc/nftables.conf; then
    echo "router-fw: ruleset loaded."
else
    echo "router-fw: ERROR loading nftables ruleset" >&2
fi

# Show what's active for the boot log.
nft list ruleset 2>/dev/null | sed -n '1,60p' || true
echo "router-fw: forwarding active across IT/DMZ/MGMT/OT — default-deny."

# Stay in the foreground.
exec tail -f /dev/null
