#!/usr/bin/env python3
"""Seed ntopng's Redis-backed administrator credential from the environment."""

from __future__ import annotations

import hashlib
import os
import sys

MIN_PASSWORD_LENGTH = 16


def main() -> int:
    password = os.environ.get('NTOPNG_ADMIN_PASSWORD', '')
    if len(password) < MIN_PASSWORD_LENGTH:
        raise RuntimeError(
            f'NTOPNG_ADMIN_PASSWORD must be set and contain at least {MIN_PASSWORD_LENGTH} characters'
        )

    try:
        import redis
    except ImportError as exc:
        raise RuntimeError(f'redis module unavailable: {exc}') from exc

    client = redis.Redis(
        host=os.environ.get('LAB_REDIS_HOST', '192.168.40.30'),
        port=int(os.environ.get('LAB_REDIS_PORT', '6379')),
        password=os.environ.get('LAB_REDIS_PASSWORD'),
        decode_responses=True,
        socket_connect_timeout=3,
    )
    client.ping()
    client.set('ntopng.user.admin.password', hashlib.md5(password.encode()).hexdigest())
    client.set('ntopng.user.admin.full_name', 'Administrator')
    client.set('ntopng.user.admin.group', 'administrator')
    client.set('ntopng.user.admin.allowed_nets', '0.0.0.0/0,::/0')
    client.set('ntopng.user.admin.allowed_interface', '')
    client.set('ntopng.prefs.admin_password_changed', '1')
    print('ntopng admin credential configured from environment')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'ntopng credential configuration failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
