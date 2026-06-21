# Setup and Running the Robotics Security Platform

## Start the stack
```bash
docker compose up -d --build
```

## Network isolation — no host firewall step
Isolation is enforced **inside** the stack by the dedicated `router-fw` container (Alpine + nftables),
which is the only multi-homed node. It comes up with the stack, enables IP forwarding, and loads a
**default-deny** forwarding policy that permits only the eight cross-zone conduits. There is no
host-level firewall script to run.

## Verify segmentation any time
```bash
python infra/tests/stage1_connectivity_matrix_docker.py   # expect: 16/16 all-green
```

## Inspect / reload the firewall policy
```bash
docker exec router-fw nft list ruleset            # view live conduits
docker compose up -d --build router-fw            # apply edits to infra/router/nftables.conf
```
