#!/usr/bin/env bash
# Docker host-level firewall rules to enforce Purdue model zone isolation.
# Run this script on the Docker host after 'docker compose up -d'.
# Requires: iptables, root/sudo access on the Docker host.
set -euo pipefail

# Allow established traffic in all directions (required for Docker networking)
iptables -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

# Block IT zone (192.168.20.0/24) from directly reaching OT zone (192.168.10.0/24)
iptables -I DOCKER-USER -s 192.168.20.0/24 -d 192.168.10.0/24 -j DROP

# Block OT zone from directly reaching IT zone
iptables -I DOCKER-USER -s 192.168.10.0/24 -d 192.168.20.0/24 -j DROP

# Allow MGMT zone to reach all zones (operator access)
iptables -I DOCKER-USER -s 192.168.40.0/24 -j RETURN

echo "Docker host firewall rules applied."
echo "To remove: iptables -F DOCKER-USER"
