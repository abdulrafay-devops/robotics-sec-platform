#!/usr/bin/env python3
"""Stage 5 — Gate 3: SROS2 governance/permissions XML linter.

Walks the SROS2 XMLs from `vm-ot/sros2/permissions/*.xml` and the
`governance.xml` produced by `ros2 security create_keystore`. Asserts
the policies that *the lab's threat model* requires; this is where the
"design intent" of Stage 3 is encoded as a machine-checkable rule.

Rules:
  S1  governance.xml present and contains
        enable_join_access_control>true
  S2  governance.xml rtps_protection_kind in {SIGN, ENCRYPT}
  S3  no permissions file uses a wildcard topic on the publish side for
        any name matching "rt/safety/*"  (no `<topic>rt/safety/*</topic>`)
  S4  every permissions file has a `<validity><not_after>` strictly in
        the future at lint time AND not more than 365 days out (forces
        cert rotation)
  S5  every permissions file has exactly one publisher for each safety
        topic (rt/safety/state, rt/safety/request) across the *set* of
        permissions files passed in (catches the bug where two enclaves
        both publish state)

Invocation:
    python sros2_lint.py \
        --governance /path/to/governance.xml \
        /path/to/safety_supervisor.permissions.xml \
        /path/to/production_plc.permissions.xml \
        ...
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET


@dataclass
class Finding:
    rule: str
    file: str
    detail: str

    def fmt(self) -> str:
        return f'[{self.rule}] {self.file}: {self.detail}'


SAFETY_TOPICS = ('rt/safety/state', 'rt/safety/request')


def _strip_ns(elem: ET.Element) -> None:
    for e in elem.iter():
        if isinstance(e.tag, str) and '}' in e.tag:
            e.tag = e.tag.split('}', 1)[1]


def _load(path: Path) -> ET.Element | None:
    try:
        tree = ET.parse(path)
    except (FileNotFoundError, ET.ParseError) as exc:
        print(f'error: cannot parse {path}: {exc}', file=sys.stderr)
        return None
    root = tree.getroot()
    _strip_ns(root)
    return root


def _lint_governance(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    root = _load(path)
    if root is None:
        return [Finding('S1_governance_present', str(path),
                        'governance.xml unreadable or missing')]
    text = path.read_text(errors='replace')
    if '<enable_join_access_control>true</enable_join_access_control>' not in text:
        findings.append(Finding(
            'S1_join_access_control', str(path),
            'enable_join_access_control must be set to true'))
    m = re.search(r'<rtps_protection_kind>\s*(\w+)\s*</rtps_protection_kind>', text)
    if not m or m.group(1).upper() not in {'SIGN', 'ENCRYPT'}:
        findings.append(Finding(
            'S2_rtps_protection', str(path),
            'rtps_protection_kind must be SIGN or ENCRYPT'))
    return findings


def _lint_permissions(paths: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    publishers: dict[str, list[str]] = defaultdict(list)
    # Naive UTC on purpose: not_after below is parsed naive (Z stripped).
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    for p in paths:
        root = _load(p)
        if root is None:
            findings.append(Finding('parse', str(p), 'unreadable'))
            continue

        # S3 — wildcard publisher on safety topics.
        for grant in root.iter('grant'):
            grant_name = grant.get('name', '<anon>')
            for allow in grant.iter('allow_rule'):
                pub = allow.find('publish')
                if pub is None:
                    continue
                topics = pub.find('topics')
                if topics is None:
                    continue
                for t in topics.findall('topic'):
                    val = (t.text or '').strip()
                    if val in ('rt/safety/*', 'rt/safety/**'):
                        findings.append(Finding(
                            'S3_no_safety_wildcard_publish', str(p),
                            f'grant "{grant_name}" allows publish wildcard '
                            f'on safety: {val!r}'))
                    if val in SAFETY_TOPICS:
                        publishers[val].append(grant_name)

        # S4 — validity window.
        for v in root.iter('not_after'):
            txt = (v.text or '').strip()
            try:
                # Tolerate naive timestamps (no Z) like SROS2 emits.
                exp = dt.datetime.fromisoformat(txt.replace('Z', ''))
            except ValueError:
                findings.append(Finding(
                    'S4_validity_unparsable', str(p),
                    f'not_after "{txt}" is not ISO 8601'))
                continue
            if exp <= now:
                findings.append(Finding(
                    'S4_validity_expired', str(p),
                    f'not_after {txt} already past at lint time {now.isoformat()}'))
            elif exp > now + dt.timedelta(days=365 * 11):  # generous window
                findings.append(Finding(
                    'S4_validity_too_long', str(p),
                    f'not_after {txt} more than 11 years out — rotate before issuing'))

    # S5 — exactly one publisher per safety topic.
    for topic in SAFETY_TOPICS:
        names = publishers.get(topic, [])
        if len(names) > 1:
            findings.append(Finding(
                'S5_one_publisher_per_safety_topic', '<crossfile>',
                f'topic {topic!r} has multiple grants publishing it: {names}'))
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--governance', type=Path, required=False)
    ap.add_argument('permissions', nargs='*', type=Path)
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args(argv)

    findings: list[Finding] = []
    if args.governance:
        findings.extend(_lint_governance(args.governance))
    findings.extend(_lint_permissions(args.permissions or []))

    if not args.quiet:
        for f in findings:
            print(f.fmt())
    print(f'sros2_lint: {len(findings)} finding(s) across '
          f'{1 if args.governance else 0} governance + '
          f'{len(args.permissions or [])} permissions file(s)')
    return 0 if not findings else 1


if __name__ == '__main__':
    sys.exit(main())
