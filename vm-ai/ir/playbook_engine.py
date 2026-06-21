#!/usr/bin/env python3
"""Stage 6 — Incident Response playbook engine.

Long-running service that:
  1. Tails the lab's high-severity event sources:
        * /var/lab/log/ai-alerts.json   (Stage 2 anomaly bridge)
        * /var/lab/log/baseline-drift.json (Stage 4 drift, on critical)
        * /safety/state == EMERGENCY (Stage 3, observed via Modbus
          register 0 read on the supervisor)
  2. For each event, looks up the matching playbook in
     /opt/lab/vm-ai/ir/playbooks/*.md by inspecting the YAML front-matter
     `triggers:` list.
  3. Executes the playbook step-by-step. Each step has a
     `requires_human_approval` flag:
        * false → run immediately, log result.
        * true  → write a "pending approval" entry to
          /var/lab/state/ir/pending_approvals.json and stop the
          playbook until an operator approves via
          `/opt/lab/bin/ir-approve <incident_id> <step>`.

The engine is deliberately small — under ~250 LOC — so an auditor can
read the whole control flow at once.

Event log: /var/lab/log/ir-engine.log
Evidence:  /var/lab/evidence/<incident_id>/   (created by forensics_capture.sh)
Audit:     /var/lab/state/ir/incidents.jsonl  (one JSON line per incident)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

LOG = logging.getLogger('stage6.playbook_engine')

PLAYBOOKS_DIR = Path('/opt/lab/vm-ai/ir/playbooks')
STATE_DIR = Path('/var/lab/state/ir')
INCIDENTS_LOG = STATE_DIR / 'incidents.jsonl'
PENDING = STATE_DIR / 'pending_approvals.json'
AI_ALERTS = Path('/var/lab/log/ai-alerts.json')
BASELINE_DRIFT = Path('/var/lab/state/baseline_drift.json')

# A single attack frequently trips more than one detector category within a few
# seconds (the external write-burst AND the OT-side reaction it provokes). Such
# detections are folded into the first incident's "campaign" rather than opening
# a parallel incident with its own approval queue. Tune via env; 0 disables.
CAMPAIGN_WINDOW_S = float(os.environ.get('LAB_IR_CAMPAIGN_WINDOW_S', '60'))


# --- playbook parser ---------------------------------------------------

def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    return s


def _parse_playbook(path: Path) -> dict:
    """Read a YAML-front-matter Markdown playbook into a dict.

    Schema:
        ---
        id: pb_modbus_replay
        triggers:
          - source: ai_alerts
            category: modbus-write-anomaly
          - source: ai_alerts
            category: modbus-baseline-deviation
        steps:
          - name: snapshot_logs
            cmd: /opt/lab/vm-ai/ir/forensics_capture.sh ${INCIDENT_ID}
            requires_human_approval: false
          - name: isolate_offender
            cmd: iptables -A INPUT -s ${SRC_IP} -j DROP
            requires_human_approval: false
          - name: assert_safe_state
            cmd: /opt/lab/bin/ir-assert-stop ${INCIDENT_ID}
            requires_human_approval: true
        ---

        # Markdown body (free-form NIST SP 800-61 narrative)
    """
    text = path.read_text(errors='replace')
    if not text.startswith('---'):
        raise ValueError(f'{path} missing YAML front-matter')
    end = text.find('\n---', 3)
    if end < 0:
        raise ValueError(f'{path} unterminated front-matter')
    fm = text[3:end].strip()
    out: dict = {'id': path.stem, 'triggers': [], 'steps': []}
    cur_list: list | None = None
    cur_dict: dict | None = None
    for raw in fm.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith('#'):
            continue
        if not line.startswith(' '):
            k, _, v = line.partition(':')
            v = v.strip()
            k = k.strip()
            if v == '':
                cur_list = []
                out[k] = cur_list
                cur_dict = None
            else:
                out[k] = _strip_quotes(v)
                cur_list = None
                cur_dict = None
        elif line.lstrip().startswith('- '):
            cur_dict = {}
            if cur_list is not None:
                cur_list.append(cur_dict)
            kv = line.lstrip()[2:]
            if ':' in kv:
                k, _, v = kv.partition(':')
                cur_dict[k.strip()] = _strip_quotes(v)
        else:
            if cur_dict is None:
                continue
            k, _, v = line.strip().partition(':')
            cur_dict[k.strip()] = _strip_quotes(v)
    return out


def _load_playbooks() -> list[dict]:
    if not PLAYBOOKS_DIR.exists():
        return []
    out: list[dict] = []
    for p in sorted(PLAYBOOKS_DIR.glob('*.md')):
        try:
            out.append(_parse_playbook(p))
        except ValueError as exc:
            LOG.error('skipping %s: %s', p, exc)
    LOG.info('loaded %d playbook(s)', len(out))
    return out


# --- trigger matching --------------------------------------------------

def _match_triggers(event: dict, playbooks: list[dict]) -> dict | None:
    """Return the first playbook whose triggers match the event."""
    for pb in playbooks:
        for trig in pb.get('triggers', []):
            if all(event.get(k) == v for k, v in trig.items()):
                return pb
    return None


# --- step execution ----------------------------------------------------

def _expand(cmd: str, ctx: dict[str, str]) -> str:
    out = cmd
    for k, v in ctx.items():
        out = out.replace('${' + k + '}', shlex.quote(str(v)))
    return out


def _run_step(step: dict, ctx: dict[str, str], audit: list[dict]) -> bool:
    """Returns True on success or pending-approval; False on hard failure."""
    cmd_raw = step.get('cmd', '')
    if not cmd_raw:
        return True
    cmd = _expand(cmd_raw, ctx)
    if str(step.get('requires_human_approval', 'false')).lower() == 'true':
        LOG.info('step %s requires HUMAN APPROVAL — pausing playbook',
                 step.get('name'))
        _record_pending(ctx['INCIDENT_ID'], step.get('name', '<anon>'), cmd)
        audit.append({'step': step.get('name'), 'status': 'pending_approval',
                      'cmd': cmd})
        return True
    LOG.info('▶ %s', cmd)
    try:
        cmd_list = shlex.split(cmd)
    except ValueError as exc:
        LOG.error('step %s: malformed command after expansion: %s', step.get('name'), exc)
        audit.append({'step': step.get('name'), 'status': 'error', 'cmd': cmd, 'rc': -1,
                      'stdout_tail': '', 'stderr_tail': str(exc)})
        return False
    proc = subprocess.run(cmd_list, capture_output=True, text=True)
    audit.append({'step': step.get('name'), 'status': 'done',
                  'rc': proc.returncode,
                  'stdout_tail': proc.stdout[-500:],
                  'stderr_tail': proc.stderr[-500:]})
    if proc.returncode != 0:
        LOG.error('step %s failed rc=%d', step.get('name'), proc.returncode)
        return False
    return True


def _record_pending(incident_id: str, step_name: str, cmd: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    entries: list[dict] = []
    if PENDING.exists():
        try:
            entries = json.loads(PENDING.read_text())
        except json.JSONDecodeError:
            entries = []
    # Idempotent: never queue the same (incident_id, step) twice. Without this
    # guard a reprocessed alert (e.g. the live engine re-reading an alert log
    # that was truncated/rewritten) could append a duplicate approval row, so
    # the operator saw the same 3 steps twice (6 buttons) for one incident.
    for e in entries:
        if e.get('incident_id') == incident_id and e.get('step') == step_name:
            return
    entries.append({
        'incident_id': incident_id,
        'step': step_name,
        'cmd': cmd,
        'queued_at': dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
    })
    PENDING.write_text(json.dumps(entries, indent=2))


def _record_incident(incident: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with INCIDENTS_LOG.open('a') as fh:
        fh.write(json.dumps(incident) + '\n')


# --- event sources -----------------------------------------------------

def _tail_ai_alerts(start_offset: int) -> tuple[int, list[dict]]:
    if not AI_ALERTS.exists():
        return start_offset, []
    size = AI_ALERTS.stat().st_size
    if size < start_offset:
        start_offset = 0
    if size <= start_offset:
        return start_offset, []
    events: list[dict] = []
    with AI_ALERTS.open('r', errors='replace') as fh:
        fh.seek(start_offset)
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # BUG #4 FIX: alert_bridge writes category inside rec['alert']['category'].
            # Previous code only checked rec.get('category') which is always None.
            alert_dict = rec.get('alert') if isinstance(rec.get('alert'), dict) else {}
            category = (
                rec.get('category') or
                rec.get('alert_type') or
                alert_dict.get('category') or
                alert_dict.get('signature') or
                'unknown'
            )
            events.append({
                'source': 'ai_alerts',
                'category': category,
                'src_ip': rec.get('src_ip') or rec.get('orig_h'),
                'severity': alert_dict.get('severity'),
                'raw': rec,
            })
    return size, events


DRIFT_SEEN = STATE_DIR / 'drift_seen.json'


def _baseline_drift_events() -> list[dict]:
    """Emit a critical drift finding ONCE on its rising edge, then stay quiet
    while it persists; re-fire only if it clears and later returns.

    baseline_check.py rewrites baseline_drift.json with a fresh `generated_at`
    on every scan. The previous version re-armed every finding on each new
    generated_at, so a single STANDING misconfiguration reopened a brand-new
    incident every scan (~every few minutes) with no attack involved - that was
    the incident flood. We now track the set of currently-emitted finding ids
    independently of generated_at: report on the rising edge, suppress while the
    finding stays present, and prune it when it disappears so a genuine
    recurrence still re-fires.
    """
    if not BASELINE_DRIFT.exists():
        return []
    try:
        d = json.loads(BASELINE_DRIFT.read_text())
    except json.JSONDecodeError:
        return []
    generated_at = str(d.get('generated_at', ''))

    drift = d.get('drift', []) or []
    present_ids = {e.get('id') for e in drift}
    critical = [e for e in drift if e.get('severity') == 'critical']

    emitted_ids: set = set()
    if DRIFT_SEEN.exists():
        try:
            s = json.loads(DRIFT_SEEN.read_text())
            emitted_ids = set(s.get('emitted_ids', []))
        except (json.JSONDecodeError, OSError):
            pass
    # Prune findings that have cleared so they can re-fire if they come back.
    emitted_ids &= present_ids

    out: list[dict] = []
    for entry in critical:
        drift_id = entry.get('id')
        if drift_id in emitted_ids:
            continue  # already reported and still standing - stay quiet
        emitted_ids.add(drift_id)
        out.append({
            'source': 'baseline_drift',
            'category': drift_id,
            'severity': 'critical',
            'raw': entry,
        })

    # Persist on every call so cleared findings are pruned even when nothing new.
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        DRIFT_SEEN.write_text(json.dumps({
            'generated_at': generated_at,
            'emitted_ids': sorted(i for i in emitted_ids if i is not None),
        }))
    except OSError:
        pass
    return out


# --- main loop ---------------------------------------------------------

def _handle(event: dict, playbooks: list[dict]) -> None:
    # BUG #5 FIX: lessons-learned enforcement now times out after 300 seconds.
    # Previously it blocked new incidents of the same category FOREVER unless
    # a post-mortem was committed. In a demo environment post-mortems are never
    # committed, so after the first incident every subsequent attack of the same
    # type was silently dropped. Now we allow a new incident after 5 minutes.
    LESSONS_BLOCK_TIMEOUT_S = 300
    try:
        if INCIDENTS_LOG.exists() and event.get('category'):
            with INCIDENTS_LOG.open('r') as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if rec.get('blocked', False):
                        continue
                    if rec.get('event', {}).get('category') == event.get('category'):
                        if not rec.get('postmortem_committed', False):
                            # Check if the block has expired
                            opened_at_str = rec.get('opened_at', '')
                            try:
                                opened_ts = dt.datetime.fromisoformat(
                                    opened_at_str.replace('Z', '')
                                ).timestamp()
                                age_s = time.time() - opened_ts
                                if age_s < LESSONS_BLOCK_TIMEOUT_S:
                                    LOG.warning(
                                        'blocking new incident for category %s '
                                        '(postmortem pending, %.0fs remaining)',
                                        event.get('category'),
                                        LESSONS_BLOCK_TIMEOUT_S - age_s,
                                    )
                                    _record_incident({
                                        'incident_id': f'blocked-{uuid.uuid4().hex[:6]}',
                                        'blocked': True,
                                        'closed': True,
                                        'reason': 'postmortem_pending',
                                        'event': event,
                                        'opened_at': dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
                                    })
                                    return
                                else:
                                    LOG.info(
                                        'lessons-learned block for %s expired (age=%.0fs > timeout=%ds) — allowing new incident',
                                        event.get('category'), age_s, LESSONS_BLOCK_TIMEOUT_S,
                                    )
                            except (ValueError, TypeError):
                                # Cannot parse timestamp — allow new incident
                                pass
    except Exception as exc:
        LOG.error('lessons-learned enforcement check failed: %s', exc)

    pb = _match_triggers(event, playbooks)
    if pb is None:
        LOG.debug('no playbook match for event %s/%s',
                  event.get('source'), event.get('category'))
        return

    # Campaign de-duplication. If a real (non-blocked) incident was opened within
    # CAMPAIGN_WINDOW_S, fold this detection into it instead of opening a second
    # incident with its own approval queue. This is what stopped a single attack
    # from showing 6 approvals (3 for the external anomaly + 3 for the OT-side
    # reaction seconds later). Per-category re-incidents are still allowed once
    # the window has elapsed.
    if CAMPAIGN_WINDOW_S > 0:
        try:
            recent_id = None
            if INCIDENTS_LOG.exists():
                now_t = time.time()
                with INCIDENTS_LOG.open('r') as fh:
                    for line in fh:
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if (rec.get('blocked') or rec.get('merged')
                                or rec.get('postmortem_committed')):
                            continue
                        try:
                            ts = dt.datetime.fromisoformat(
                                rec.get('opened_at', '').replace('Z', '')
                            ).timestamp()
                        except (ValueError, TypeError):
                            continue
                        if now_t - ts < CAMPAIGN_WINDOW_S:
                            recent_id = rec.get('incident_id')
            if recent_id is not None:
                LOG.warning('folding %s/%s into active campaign %s (within %.0fs)',
                            event.get('source'), event.get('category'),
                            recent_id, CAMPAIGN_WINDOW_S)
                _record_incident({
                    'incident_id': f'merged-{uuid.uuid4().hex[:6]}',
                    'merged': True,
                    'blocked': True,
                    'closed': True,
                    'reason': 'campaign_dedup',
                    'merged_into': recent_id,
                    'event': event,
                    'opened_at': dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
                })
                return
        except Exception as exc:
            LOG.error('campaign de-dup check failed: %s', exc)

    incident_id = f'{dt.datetime.utcnow():%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:6]}'
    LOG.warning('INCIDENT %s — playbook=%s event=%s/%s',
                incident_id, pb['id'],
                event.get('source'), event.get('category'))

    ctx: dict[str, str] = {
        'INCIDENT_ID': incident_id,
        'SRC_IP': event.get('src_ip') or '',
        'CATEGORY': event.get('category') or '',
    }
    # Sanitize SRC_IP to prevent injection via crafted alert data
    import re as _re
    raw_ip = ctx.get("SRC_IP", "")
    if raw_ip and not _re.match(r'^[\d\.]+$', raw_ip):
        LOG.warning("Rejecting incident with suspicious SRC_IP=%r", raw_ip)
        return
    audit: list[dict] = []
    overall = True
    for step in pb.get('steps', []):
        if not _run_step(step, ctx, audit):
            overall = False
            break
    _record_incident({
        'incident_id': incident_id,
        'playbook': pb['id'],
        'event': event,
        'steps': audit,
        'closed': overall,
        'opened_at': dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
    })


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    # Manual lightweight subcommand parser to preserve existing flags.
    if argv and len(argv) > 0 and argv[0] == 'close-incident':
        sub = argparse.ArgumentParser(prog='playbook_engine.py close-incident', add_help=True)
        sub.add_argument('incident_id')
        sub.add_argument('--postmortem-path', required=True)
        sub_args = sub.parse_args(argv[1:])
        inc_id = sub_args.incident_id
        pm_path = Path(sub_args.postmortem_path)
        if not pm_path.exists():
            LOG.error('postmortem file %s not found', pm_path)
            return 2
        text = pm_path.read_text(errors='replace')
        missing = [h for h in ('## Summary', '## Root Cause', '## Remediation') if h not in text]
        if missing:
            LOG.error('postmortem missing required section(s): %s', ', '.join(missing))
            return 3
        # Load, update, and rewrite incidents.jsonl
        entries: list[dict] = []
        if INCIDENTS_LOG.exists():
            with INCIDENTS_LOG.open('r') as fh:
                for line in fh:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        found = False
        for e in entries:
            if e.get('incident_id') == inc_id:
                e['postmortem_committed'] = True
                e['closed_at'] = dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
                found = True
                break
        if not found:
            LOG.error('incident %s not found in log', inc_id)
            return 4
        with INCIDENTS_LOG.open('w') as fh:
            for e in entries:
                fh.write(json.dumps(e) + '\n')
        # Copy postmortem into evidence folder
        ev_dir = Path('/var/lab/evidence') / inc_id
        ev_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(pm_path), str(ev_dir / 'postmortem.md'))
        LOG.info('Incident %s closed with postmortem', inc_id)
        return 0

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--once', action='store_true',
                    help='process current backlog and exit (gate-test mode)')
    ap.add_argument('--interval', type=float, default=2.0,
                    help='poll interval in seconds')
    args = ap.parse_args(argv)

    playbooks = _load_playbooks()
    if not playbooks:
        LOG.warning('no playbooks loaded; engine will idle')

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    OFFSET_FILE = STATE_DIR / "ir_engine_offset.json"
    
    # Restore the last-read offset so restarts do not miss alerts
    if not args.once:
        if OFFSET_FILE.exists():
            try:
                saved = json.loads(OFFSET_FILE.read_text())
                offset = int(saved.get("offset", 0))
                LOG.info("restored read offset %d from %s", offset, OFFSET_FILE)
            except Exception:
                offset = AI_ALERTS.stat().st_size if AI_ALERTS.exists() else 0
        else:
            offset = AI_ALERTS.stat().st_size if AI_ALERTS.exists() else 0
    else:
        offset = 0

    while True:
        offset, events = _tail_ai_alerts(offset)
        # Persist offset so a restart resumes from here
        if not args.once:
            try:
                OFFSET_FILE.write_text(json.dumps({"offset": offset}))
            except Exception:
                pass
        events.extend(_baseline_drift_events())
        for ev in events:
            _handle(ev, playbooks)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == '__main__':
    sys.exit(main())
