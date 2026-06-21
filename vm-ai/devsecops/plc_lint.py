#!/usr/bin/env python3
"""Stage 5 — Gate 1: PLC Structured Text static analysis.

Walks an OpenPLC `.st` file (IEC 61131-3 Structured Text) and applies a
small, auditable set of safety- and security-focused rules. The intent
is to be *the second pair of eyes that never gets tired* — not a
replacement for human review, but a deterministic backstop for the
patterns most commonly weaponised in ICS incidents.

The lint deliberately does NOT use a full IEC parser (MATIEC's grammar
is fragile and adds a heavyweight build dependency). Instead each rule
is a focused regex with a clear failure message. This keeps the lint
auditable in ~250 lines and easy for an engineer to extend.

Rules:
  R1  no_default_credentials
        Block hard-coded "openplc"/"admin"/"password" string literals.
  R2  estop_in_motion_path
        Every block whose name contains MOTION/MOVE/JOG must reference
        an E_STOP / e_stop_active / SAFETY_OK guard.
  R3  no_safety_register_writes_outside_safety_program
        Direct writes to %QX0.0 (safety output) only allowed inside a
        block whose name starts with SAFETY_.
  R4  no_unbounded_for
        FOR loops must have a static integer bound (no FOR i := 0 TO N
        DO with N as a non-constant).
  R5  no_disabled_safety_calls
        Any call site that comments out a SAFETY_* function call (i.e.
        a `(* SAFETY_CHECK(... *)` block) is flagged.
  R6  signed_program_marker
        First non-empty line must contain
        `(* SIGNED_BY: <name> @ <iso8601> *)` — Stage 5 audit trail tie-in.

Usage:
    python plc_lint.py path/to/program.st [path2.st ...]

Exit codes:
    0  all files pass
    1  one or more lint violations
    2  invocation error / file not readable
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    rule: str
    file: str
    line: int
    text: str
    detail: str

    def fmt(self) -> str:
        return (f'[{self.rule}] {self.file}:{self.line}: {self.detail}\n'
                f'        > {self.text.rstrip()}')


# --- rule helpers ------------------------------------------------------

DEFAULT_CREDENTIAL_PATTERNS = [
    re.compile(r"'openplc'", re.IGNORECASE),
    re.compile(r"'admin'", re.IGNORECASE),
    re.compile(r"'password'", re.IGNORECASE),
    re.compile(r"'1234'"),
    re.compile(r"'changeme'", re.IGNORECASE),
]
ESTOP_GUARDS = re.compile(
    r'\b(E_STOP|e_stop_active|SAFETY_OK|SAFE_TO_RUN)\b'
)
SAFETY_OUTPUT_WRITE = re.compile(
    r'%QX0\.[0-9]\s*:='
)
MOTION_BLOCK = re.compile(
    r'^\s*(?:FUNCTION_BLOCK|PROGRAM)\s+([A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)
SAFETY_BLOCK = re.compile(
    r'^\s*(?:FUNCTION_BLOCK|PROGRAM)\s+SAFETY_',
    re.IGNORECASE,
)
END_BLOCK = re.compile(r'^\s*END_(?:FUNCTION_BLOCK|PROGRAM)\b', re.IGNORECASE)
FOR_LOOP = re.compile(
    r'^\s*FOR\s+\w+\s*:=\s*[-+]?\d+\s+TO\s+([^\s]+)\s+DO',
    re.IGNORECASE,
)
COMMENTED_SAFETY_CALL = re.compile(
    r'\(\*\s*SAFETY_[A-Za-z0-9_]+\(.*?\*\)'
)
SIGNED_MARKER = re.compile(
    r'\(\*\s*SIGNED_BY:\s*(.+?)\s*@\s*([0-9T:\-Z+\.]+)\s*\*\)'
)


def _lint_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    text = path.read_text(errors='replace')
    lines = text.splitlines()

    # R6 — first non-empty, non-comment-shebang line must carry the marker.
    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if SIGNED_MARKER.search(line):
            break
        findings.append(Finding(
            rule='R6_signed_program_marker',
            file=str(path), line=i, text=line,
            detail='first non-empty line must contain '
                   '"(* SIGNED_BY: <name> @ <iso8601> *)"',
        ))
        break  # only report once

    # Walk to find motion/safety blocks for context.
    in_block: str | None = None
    block_lines: list[tuple[int, str]] = []
    for i, line in enumerate(lines, start=1):
        m = MOTION_BLOCK.match(line)
        if m:
            in_block = m.group(1).upper()
            block_lines = [(i, line)]
            continue
        if in_block is not None:
            block_lines.append((i, line))
            if END_BLOCK.match(line):
                # End of block — apply per-block rules.
                if any(s in in_block for s in ('MOTION', 'MOVE', 'JOG')):
                    block_text = '\n'.join(t for _, t in block_lines)
                    if not ESTOP_GUARDS.search(block_text):
                        findings.append(Finding(
                            rule='R2_estop_in_motion_path',
                            file=str(path), line=block_lines[0][0],
                            text=block_lines[0][1],
                            detail=f'motion-class block "{in_block}" has '
                                   'no E_STOP / e_stop_active / SAFETY_OK guard',
                        ))
                in_block = None
                block_lines = []

    # Whole-file rules.
    in_safety_block = False
    for i, line in enumerate(lines, start=1):
        # R1 — default credentials.
        for pat in DEFAULT_CREDENTIAL_PATTERNS:
            if pat.search(line):
                findings.append(Finding(
                    rule='R1_no_default_credentials',
                    file=str(path), line=i, text=line,
                    detail='hard-coded default credential string literal',
                ))

        # Track whether we are in a SAFETY_* block.
        if SAFETY_BLOCK.match(line):
            in_safety_block = True
        elif END_BLOCK.match(line):
            in_safety_block = False

        # R3 — direct writes to safety outputs.
        if SAFETY_OUTPUT_WRITE.search(line) and not in_safety_block:
            findings.append(Finding(
                rule='R3_no_safety_register_writes_outside_safety_program',
                file=str(path), line=i, text=line,
                detail='direct write to %QX0.x outside SAFETY_* block',
            ))

        # R4 — unbounded FOR loop.
        m = FOR_LOOP.match(line)
        if m:
            bound = m.group(1).strip()
            if not bound.replace('-', '', 1).isdigit():
                findings.append(Finding(
                    rule='R4_no_unbounded_for',
                    file=str(path), line=i, text=line,
                    detail=f'FOR loop bound "{bound}" is not a static '
                           'integer literal',
                ))

        # R5 — commented-out SAFETY_* call.
        if COMMENTED_SAFETY_CALL.search(line):
            findings.append(Finding(
                rule='R5_no_disabled_safety_calls',
                file=str(path), line=i, text=line,
                detail='SAFETY_* call appears to be commented out',
            ))

    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('paths', nargs='+', type=Path,
                    help='one or more Structured Text files')
    ap.add_argument('--quiet', action='store_true',
                    help='only print summary, suppress per-finding output')
    args = ap.parse_args(argv)

    all_findings: list[Finding] = []
    for p in args.paths:
        if not p.exists():
            print(f'error: file not found: {p}', file=sys.stderr)
            return 2
        all_findings.extend(_lint_file(p))

    if not args.quiet:
        for f in all_findings:
            print(f.fmt())
    print(f'plc_lint: {len(all_findings)} finding(s) across {len(args.paths)} file(s)')
    return 0 if not all_findings else 1


if __name__ == '__main__':
    sys.exit(main())
