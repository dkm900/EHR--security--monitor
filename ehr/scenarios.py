"""Demo attack / workflow scenarios.

Each scenario is a short, self-contained script that drives the monitor the way
a real system would, and returns a human-readable narration of what happened
and which rules fired. The portal runs these so the detection logic can be
demonstrated without having to hand-craft traffic.

Timestamps are *back-dated* so that time-window logic (the 10-minute bulk-read
window, the 15-minute failed-login window) is exercised deterministically
instead of depending on how fast the HTTP requests happen to arrive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from .audit import AuditEvent
from .detectors import Alert
from .models import Action, RecordCategory
from .monitor import EHRMonitor


@dataclass
class ScenarioResult:
    """Narration of one scenario run."""

    key: str
    title: str
    intent: str
    should_alert: bool
    steps: list[dict] = field(default_factory=list)
    rule_ids_fired: list[str] = field(default_factory=list)

    @property
    def behaved_as_expected(self) -> bool:
        return bool(self.rule_ids_fired) == self.should_alert

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "title": self.title,
            "intent": self.intent,
            "should_alert": self.should_alert,
            "behaved_as_expected": self.behaved_as_expected,
            "rule_ids_fired": self.rule_ids_fired,
            "steps": self.steps,
        }


def _base_time() -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=30)


def _collect(result: ScenarioResult, alerts: list[Alert]) -> None:
    for alert in alerts:
        if alert.rule_id not in result.rule_ids_fired:
            result.rule_ids_fired.append(alert.rule_id)


# ---------------------------------------------------------------------------
# The scenarios
# ---------------------------------------------------------------------------
def brute_force(monitor: EHRMonitor) -> ScenarioResult:
    """Six wrong passwords, then a correct one. Should raise EHR-001."""
    out = ScenarioResult(
        key="brute_force",
        title="Credential stuffing on a doctor account",
        intent="Hammer an account with bad passwords, then succeed.",
        should_alert=True,
    )
    t = _base_time()
    for i in range(5):
        res = monitor.attempt_login(
            "dr.ivanov", password=f"guess-{i}", source_ip="203.0.113.44",
            timestamp=t + timedelta(seconds=i * 20),
        )
        out.steps.append({
            "label": f"login attempt {i + 1}",
            "outcome": res.event.outcome.value,
            "note": res.event.reason or "rejected",
            "alerts": [a.rule_id for a in res.alerts],
        })
        _collect(out, res.alerts)
    res = monitor.attempt_login(
        "dr.ivanov", password="correct-horse", source_ip="203.0.113.44",
        timestamp=t + timedelta(seconds=110),
    )
    out.steps.append({
        "label": "login attempt 6 (correct password)",
        "outcome": res.event.outcome.value,
        "note": "credentials accepted -- account may now be compromised",
        "alerts": [a.rule_id for a in res.alerts],
    })
    _collect(out, res.alerts)
    return out


def bulk_exfiltration(monitor: EHRMonitor) -> ScenarioResult:
    """A billing clerk pulls 70 charts' billing sections in one request."""
    out = ScenarioResult(
        key="bulk_exfiltration",
        title="Bulk export by a Billing clerk",
        intent="In-scope section, but 70 records in a single request.",
        should_alert=True,
    )
    ids = monitor.records.ids_with_section(RecordCategory.BILLING, 70)
    res = monitor.access_records(
        "clerk.bianchi", ids, sections=[RecordCategory.BILLING],
        source_ip="198.51.100.7", timestamp=_base_time(),
    )
    out.steps.append({
        "label": f"single request touching {len(ids)} billing sections",
        "outcome": res.event.outcome.value,
        "note": f"authorized, but volume is anomalous: batch_size={res.event.batch_size}",
        "alerts": [a.rule_id for a in res.alerts],
    })
    _collect(out, res.alerts)
    return out


def role_scope_violation(monitor: EHRMonitor) -> ScenarioResult:
    """Billing staff open psychiatric notes, a nurse leaves their ward, a nurse
    tries to prescribe. All three flavours of EHR-003."""
    out = ScenarioResult(
        key="role_scope_violation",
        title="Role-out-of-scope access attempts",
        intent="Three distinct ways to ask for something the role cannot have.",
        should_alert=True,
    )
    t = _base_time()

    psych = monitor.records.ids_with_section(RecordCategory.PSYCH, 2)
    res = monitor.access_records(
        "clerk.bianchi", psych, sections=[RecordCategory.PSYCH],
        source_ip="198.51.100.7", timestamp=t,
    )
    out.steps.append({
        "label": "Billing clerk opens PSYCH notes",
        "outcome": res.event.outcome.value,
        "note": res.event.reason or "granted",
        "alerts": [a.rule_id for a in res.alerts],
    })
    _collect(out, res.alerts)

    wards = [r.record_id for r in monitor.records.all()
             if r.department == "Psychiatry"][:2]
    res = monitor.access_records(
        "nurse.diaz", wards, sections=[RecordCategory.CLINICAL],
        timestamp=t + timedelta(minutes=1),
    )
    out.steps.append({
        "label": "Cardiology nurse opens a Psychiatry chart",
        "outcome": res.event.outcome.value,
        "note": res.event.reason or "granted",
        "alerts": [a.rule_id for a in res.alerts],
    })
    _collect(out, res.alerts)

    cardio = [r.record_id for r in monitor.records.all()
              if r.department == "Cardiology"][:1]
    res = monitor.access_records(
        "nurse.diaz", cardio, action=Action.PRESCRIBE,
        sections=[RecordCategory.CLINICAL],
        timestamp=t + timedelta(minutes=2),
    )
    out.steps.append({
        "label": "Nurse attempts to prescribe",
        "outcome": res.event.outcome.value,
        "note": res.event.reason or "granted",
        "alerts": [a.rule_id for a in res.alerts],
    })
    _collect(out, res.alerts)
    return out


def busy_clinician(monitor: EHRMonitor) -> ScenarioResult:
    """70 charts, one at a time, one second apart. This is the FALSE POSITIVE
    the heuristic exists to prevent -- it must stay silent."""
    out = ScenarioResult(
        key="busy_clinician",
        title="Busy clinician on morning rounds",
        intent="70 individual chart opens at ~1/sec. Legitimate. Must NOT alert.",
        should_alert=False,
    )
    ids = monitor.records.ids_for_role(monitor.staff["dr.okafor"].role, 70)
    t = _base_time()
    exempt_count = 0
    for i, rid in enumerate(ids):
        res = monitor.access_records(
            "dr.okafor", [rid], timestamp=t + timedelta(seconds=i * 1.0),
        )
        exempt_count += int(res.exempt)
        if res.alerts:
            out.steps.append({
                "label": f"unexpected alert on chart {i + 1}",
                "outcome": res.event.outcome.value,
                "note": "; ".join(a.rule_id for a in res.alerts),
                "alerts": [a.rule_id for a in res.alerts],
            })
            _collect(out, res.alerts)
    out.steps.append({
        "label": f"{len(ids)} charts opened individually, 1 second apart",
        "outcome": "success",
        "note": f"{exempt_count}/{len(ids)} reads exempted as clinical workflow "
                f"(batch_size=1, human click pace)",
        "alerts": [],
    })
    return out


def scripted_account(monitor: EHRMonitor) -> ScenarioResult:
    """Same doctor account, but a script: 70 reads at 20/sec. The heuristic's
    safety valve should revoke the exemption and EHR-002 should fire."""
    out = ScenarioResult(
        key="scripted_account",
        title="Scripted harvesting through a doctor account",
        intent="Valid clinical role, but machine pace defeats the exemption.",
        should_alert=True,
    )
    ids = monitor.records.ids_for_role(monitor.staff["dr.okafor"].role, 70)
    t = _base_time()
    first_exempt: bool | None = None
    for i, rid in enumerate(ids):
        res = monitor.access_records(
            "dr.okafor", [rid], timestamp=t + timedelta(seconds=i * 0.05),
        )
        if first_exempt is None:
            first_exempt = res.exempt
        _collect(out, res.alerts)
    out.steps.append({
        "label": f"{len(ids)} charts opened at 20 reads/sec (no think time)",
        "outcome": "success",
        "note": f"exemption started {'granted' if first_exempt else 'denied'} "
                f"then revoked once the human click floor was breached",
        "alerts": sorted(set(out.rule_ids_fired)),
    })
    return out


def terminated_account(monitor: EHRMonitor) -> ScenarioResult:
    """A deactivated doctor whose session cookie is still alive."""
    out = ScenarioResult(
        key="terminated_account",
        title="Deactivated account with a live session",
        intent="Offboarded staff still holding a valid session token.",
        should_alert=True,
    )
    ids = [r.record_id for r in monitor.records.all()
           if r.department == "Cardiology"][:2]
    res = monitor.access_records(
        "dr.terminated", ids, timestamp=_base_time(),
    )
    out.steps.append({
        "label": "Terminated doctor opens 2 charts",
        "outcome": res.event.outcome.value,
        "note": res.event.reason or "granted",
        "alerts": [a.rule_id for a in res.alerts],
    })
    _collect(out, res.alerts)
    return out


def normal_operations(monitor: EHRMonitor) -> ScenarioResult:
    """Baseline: a normal shift. Should produce zero alerts, proving the rules
    are not simply firing on everything."""
    out = ScenarioResult(
        key="normal_operations",
        title="A normal quiet shift (negative control)",
        intent="Ordinary care traffic. Confirms the rules stay quiet.",
        should_alert=False,
    )
    t = _base_time()
    cardio = [r.record_id for r in monitor.records.all()
              if r.department == "Cardiology"][:6]
    res = monitor.access_records(
        "nurse.diaz", cardio[:3], sections=[RecordCategory.CLINICAL],
        timestamp=t,
    )
    out.steps.append({
        "label": "Nurse reviews 3 Cardiology charts",
        "outcome": res.event.outcome.value,
        "note": "in scope, small batch, no alert expected",
        "alerts": [a.rule_id for a in res.alerts],
    })
    _collect(out, res.alerts)

    res = monitor.access_records(
        "clerk.bianchi", cardio[:2], sections=[RecordCategory.BILLING],
        timestamp=t + timedelta(minutes=20),
    )
    out.steps.append({
        "label": "Billing clerk codes 2 charts, 20 min later",
        "outcome": res.event.outcome.value,
        "note": "in scope, outside the 10-min bulk window",
        "alerts": [a.rule_id for a in res.alerts],
    })
    _collect(out, res.alerts)

    res = monitor.attempt_login(
        "dr.okafor", timestamp=t + timedelta(minutes=30),
    )
    out.steps.append({
        "label": "Doctor logs in",
        "outcome": res.event.outcome.value,
        "note": "successful authentication",
        "alerts": [a.rule_id for a in res.alerts],
    })
    _collect(out, res.alerts)
    return out


#: Scenario key -> runner function. Keys are the runner function names.
SCENARIOS: dict[str, Callable[[EHRMonitor], ScenarioResult]] = {
    fn.__name__: fn for fn in (
        brute_force,
        bulk_exfiltration,
        role_scope_violation,
        busy_clinician,
        scripted_account,
        terminated_account,
        normal_operations,
    )
}

#: Presentation metadata for the portal's launcher, in display order.
_CATALOGUE: list[dict] = [
    {"key": "normal_operations",   "title": "Normal shift",       "blurb": "Negative control. Should stay silent.",                "expect": "no alert"},
    {"key": "busy_clinician",    "title": "Busy clinician",     "blurb": "70 charts, 1/sec. Tests the false-positive suppressor.", "expect": "no alert"},
    {"key": "brute_force",       "title": "Brute force login",  "blurb": "5 bad passwords then success.",                        "expect": "EHR-001"},
    {"key": "bulk_exfiltration",  "title": "Bulk export",        "blurb": "70 records in one request.",                           "expect": "EHR-002"},
    {"key": "role_scope_violation","title": "Out-of-scope access","blurb": "Psych notes, wrong ward, prescribing.",                "expect": "EHR-003"},
    {"key": "scripted_account",  "title": "Scripted harvesting","blurb": "Clinical role, machine pace. Exemption revoked.",       "expect": "EHR-002"},
    {"key": "terminated_account","title": "Zombie session",     "blurb": "Deactivated account still active.",                    "expect": "EHR-003"},
]


def catalogue() -> list[dict]:
    """Scenario metadata for the UI, without running anything."""
    return [c for c in _CATALOGUE if c["key"] in SCENARIOS]
