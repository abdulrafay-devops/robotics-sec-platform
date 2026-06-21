#!/usr/bin/env bash
# =============================================================================
# IDMZ Stage 5 — signed PLC-program publisher (CI / release side)
# =============================================================================
# GPG-signs a PLC program with the lab release key and publishes the program +
# detached signature + the release public key to the DMZ artifact store (a shared
# volume the historian serves read-only). The OT deploy agent later PULLS these
# over the OT->DMZ:80 conduit and verifies the signature before loading anything.
#
# Runs where the release key lives (container-ai). Invoke from the host with:
#   docker exec container-ai bash /vagrant/infra/deploy/publish.sh <program.st> [name]
#
# The optional [--tamper] flag corrupts the published .st AFTER signing, to prove
# the OT side rejects modified code (the artifact no longer matches its signature).
# =============================================================================
set -euo pipefail

TAMPER=0
ARGS=()
for a in "$@"; do
  if [ "$a" = "--tamper" ]; then TAMPER=1; else ARGS+=("$a"); fi
done
set -- "${ARGS[@]}"

SRC="${1:?usage: publish.sh <program.st> [name] [--tamper]}"
NAME="${2:-program}"
STORE="${LAB_DEPLOY_STORE:-/var/lab/deploy-store}"
KEY="${LAB_RELEASE_KEY:-lab-release@lab.local}"

[ -f "$SRC" ] || { echo "source program not found: $SRC" >&2; exit 1; }
mkdir -p "$STORE"

cp -f "$SRC" "$STORE/${NAME}.st"
gpg --batch --yes --local-user "$KEY" \
    --detach-sign --output "$STORE/${NAME}.st.sig" "$STORE/${NAME}.st"
gpg --batch --yes --armor --export "$KEY" > "$STORE/release_pubkey.asc"

if [ "$TAMPER" = "1" ]; then
  printf '\n(* injected by an attacker after signing *)\n' >> "$STORE/${NAME}.st"
  echo "WARNING: ${NAME}.st was TAMPERED after signing — OT must reject it."
fi

chmod -R a+r "$STORE"
echo "published ${NAME}.st (+ .sig + release_pubkey.asc) to $STORE"
ls -l "$STORE"
