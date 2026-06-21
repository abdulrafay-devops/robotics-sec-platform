#!/usr/bin/env python3
"""
OT-side deploy agent — the "OT pulls, IT never pushes" half of the IDMZ deploy flow.

Pulls a candidate PLC program + detached GPG signature + the release public key
from the DMZ artifact store (served by the historian over the allowed OT->DMZ:80
conduit), VERIFIES the signature against the trusted release key, and only on
success compiles + stages it into OpenPLC. A tampered or unsigned program is
REJECTED and never loaded — the controller only ever runs code signed by CI.

Usage (inside container-ot):
    python3 /vagrant/vm-ot/deploy_agent.py --store http://192.168.30.40/deploy --name program
"""
from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

LOG = logging.getLogger("deploy_agent")


def _fetch(url: str, dest: str) -> None:
    with urllib.request.urlopen(url, timeout=10) as r, open(dest, "wb") as f:
        f.write(r.read())


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    p.add_argument("--store", default="http://192.168.30.40/deploy")
    p.add_argument("--name", default="program")
    p.add_argument("--openplc-dir", default="/opt/lab/openplc/webserver")
    p.add_argument("--activate", action="store_true",
                   help="set as OpenPLC active program after a successful verify")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    work = tempfile.mkdtemp(prefix="deploy_")
    st = os.path.join(work, f"{a.name}.st")
    sig = os.path.join(work, f"{a.name}.st.sig")
    pub = os.path.join(work, "release_pubkey.asc")

    # 1. PULL the artifact from the DMZ store (OT -> DMZ:80, the allowed conduit).
    try:
        LOG.info("pulling signed program from %s ...", a.store)
        _fetch(f"{a.store}/{a.name}.st", st)
        _fetch(f"{a.store}/{a.name}.st.sig", sig)
        _fetch(f"{a.store}/release_pubkey.asc", pub)
    except Exception as exc:  # noqa: BLE001
        LOG.error("pull failed (store unreachable?): %s", exc)
        print("DEPLOY ERROR: could not pull artifact from the DMZ store")
        return 2

    # 2. VERIFY the detached GPG signature against the trusted release key, in an
    #    ephemeral keyring (we trust only the published release pubkey).
    gnupg = os.path.join(work, "gnupg")
    os.makedirs(gnupg, mode=0o700, exist_ok=True)
    env = {**os.environ, "GNUPGHOME": gnupg}
    subprocess.run(["gpg", "--batch", "--import", pub], env=env, capture_output=True, text=True)

    LOG.info("verifying GPG signature ...")
    v = subprocess.run(["gpg", "--batch", "--verify", sig, st], env=env,
                       capture_output=True, text=True)
    if v.returncode != 0:
        tail = (v.stderr or "").strip().splitlines()
        LOG.error("SIGNATURE INVALID — rejecting (program NOT loaded). gpg: %s",
                  tail[-1] if tail else "verify failed")
        print("DEPLOY REJECTED: signature verification failed — controller untouched")
        return 1
    LOG.info("signature VALID — signed by the trusted release key")

    # 3. Stage + compile into OpenPLC (only reached for verified programs).
    st_files = os.path.join(a.openplc_dir, "st_files")
    os.makedirs(st_files, exist_ok=True)
    shutil.copy2(st, os.path.join(st_files, f"{a.name}.st"))
    LOG.info("compiling %s.st in OpenPLC ...", a.name)
    c = subprocess.run(["bash", "./scripts/compile_program.sh", f"{a.name}.st"],
                       cwd=a.openplc_dir, capture_output=True, text=True)
    if c.returncode != 0:
        LOG.error("compile failed: %s", (c.stderr or c.stdout)[-300:])
        print("DEPLOY FAILED: program verified but did not compile")
        return 1
    LOG.info("compiled OK")

    if a.activate:
        with open(os.path.join(a.openplc_dir, "active_program"), "w", encoding="utf-8") as f:
            f.write(f"{a.name}.st")
        LOG.info("set active_program=%s.st (restart the OpenPLC runtime to run it)", a.name)

    print(f"DEPLOY ACCEPTED: {a.name}.st signature-verified and compiled (staged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
