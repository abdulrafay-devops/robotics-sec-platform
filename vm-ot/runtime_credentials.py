#!/usr/bin/env python3
"""Apply required OT service passwords from the container environment."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import sys

OPENPLC_DB = Path('/opt/lab/openplc/webserver/openplc.db')
RDP_ACCOUNT = 'lab'
OPENPLC_ACCOUNT = 'openplc'
MIN_PASSWORD_LENGTH = 16


def required_secret(name: str) -> str:
    value = os.environ.get(name, '')
    if len(value) < MIN_PASSWORD_LENGTH:
        raise RuntimeError(
            f'{name} must be set and contain at least {MIN_PASSWORD_LENGTH} characters'
        )
    if '\r' in value or '\n' in value:
        raise RuntimeError(f'{name} must not contain a line break')
    return value


def main() -> int:
    rdp_password = required_secret('OT_RDP_PASSWORD')
    openplc_password = required_secret('OPENPLC_WEB_PASSWORD')
    if ':' in rdp_password:
        raise RuntimeError('OT_RDP_PASSWORD must not contain a colon')
    if not OPENPLC_DB.exists():
        raise RuntimeError(f'OpenPLC database is missing: {OPENPLC_DB}')

    subprocess.run(
        ['chpasswd'],
        input=f'{RDP_ACCOUNT}:{rdp_password}\n',
        text=True,
        check=True,
    )

    with sqlite3.connect(OPENPLC_DB) as conn:
        updated = conn.execute(
            'UPDATE Users SET password = ? WHERE username = ?',
            (openplc_password, OPENPLC_ACCOUNT),
        ).rowcount
        if updated != 1:
            raise RuntimeError(
                f'expected exactly one OpenPLC account named {OPENPLC_ACCOUNT}, found {updated}'
            )

    print('OT runtime credentials configured from environment')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'OT runtime credential configuration failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
