"""Detection rules.

Three rules, each an independent class implementing the same tiny interface so
they are interchangeable and individually testable:

    rule.evaluate(event, window_log) -> list[Alert]

`window_log` is the slice of audit events relevant to this event (usually that
user's recent history), so rules never have to reach into global state.

A fourth concern lives here too: alert de-duplication. Without it, a scripted
harvest of 5,000 records would emit 5,000 near-identical alerts and bury the
signal. `AlertBoard` collapses repeats per (rule, subject) inside a cooldown.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

from .audit import AuditEvent
from .models import Action, Outcome


class Severity(str):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass
class Alert:
    """A detection finding, ready to show in the UI or forward to a SIEM."""

    rule_id: str
    rule_name: str
    severity: str
    user_id: str
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    occurrences: int = 1

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "user_id": self.user_id,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence[:12],
            "evidence_total": len(self.evidence),
            "created_at": self.created_at.isoformat(),
            "occurrences": self.occurrences,
        }


class Rule(ABC):
    """Base class: every detection rule is a pure-ish function of an event."""

    rule_id: str = "base"
    rule_name: str = "base"
    default_window: timedelta = timedelta(minutes=10)
    default_cooldown: timedelta = timedelta(minutes=5)

    def __init__(self, window: Optional[timedelta] = None,
                 cooldown: Optional[timedelta] = None):
        #: How far back the rule looks when measuring volume or frequency.
        self.window = window or self.default_window
        #: How long a (rule, user) pair stays collapsed on the alert board.
        self.cooldown = cooldown or self.default_cooldown

    @abstractmethod
    def evaluate(self, event: AuditEvent, window: Sequence[AuditEvent]) -> list[Alert]:
        """Return alerts triggered by `event`, judged against `window`.

        `window` is whatever history the caller thinks is relevant. Subclasses
        should pass it through `self.recent()` so the rule's own time window is
        always enforced, even when used standalone.
        """

    def recent(self, event: AuditEvent,
               window: Sequence[AuditEvent]) -> list[AuditEvent]:
        """Trim a history slice to this rule's window, relative to `event`.

        Bounded on *both* sides: nothing older than the window, and nothing
        newer than the event being judged. Defensive on purpose -- the monitor
        already filters, but a rule handed an unordered or over-wide history
        must not count future traffic.
        """
        cutoff = event.timestamp - self.window
        return [e for e in window if cutoff <= e.timestamp <= event.timestamp]

    def _alert(
        self,
        event: AuditEvent,
        severity: str,
        title: str,
        detail: str,
        evidence: Sequence[AuditEvent] = (),
    ) -> Alert:
        return Alert(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=severity,
            user_id=event.user_id,
            title=title,
            detail=detail,
            evidence=[e.record_ids[0] if e.record_ids else e.action.value for e in evidence],
            created_at=datetime.now(timezone.utc),
        )


# ---------------------------------------------------------------------------
# Rule 1 -- 3+ failed logins
# ---------------------------------------------------------------------------
class FailedLoginRule(Rule):
    """ALERT when an account records `threshold` or more failed logins.

    Only `Outcome.FAILED` events count. A *denied* access (valid credentials,
    no permission) is a different problem and is handled by rule 3.

    Severity escalates with the count: 3 -> medium, 5 -> high, 8+ -> critical.
    """

    rule_id = "EHR-001"
    rule_name = "Repeated Failed Logins"
    default_window = timedelta(minutes=15)

    def __init__(self, threshold: int = 3, severe_threshold: int = 5,
                 critical_threshold: int = 8,
                 window: Optional[timedelta] = None,
                 cooldown: Optional[timedelta] = None):
        super().__init__(window=window, cooldown=cooldown)
        self.threshold = threshold
        self.severe_threshold = severe_threshold
        self.critical_threshold = critical_threshold

    def evaluate(self, event: AuditEvent, window: Sequence[AuditEvent]) -> list[Alert]:
        if event.action is not Action.LOGIN or event.outcome is not Outcome.FAILED:
            return []

        failures = [
            e for e in self.recent(event, window)
            if e.action is Action.LOGIN and e.outcome is Outcome.FAILED
        ]
        # `event` is the newest; count it plus prior failures in-window.
        if event not in failures:
            failures.append(event)
        failures.sort(key=lambda e: e.timestamp)

        if len(failures) < self.threshold:
            return []

        if len(failures) >= self.critical_threshold:
            severity = Severity.CRITICAL
        elif len(failures) >= self.severe_threshold:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        minutes = self.window.total_seconds() / 60
        return [self._alert(
            event,
            severity,
            f"{len(failures)} failed logins for {event.user_id}",
            f"{event.user_id} failed authentication {len(failures)} times in "
            f"{minutes:.0f} minutes (threshold {self.threshold}). Possible "
            f"credential stuffing or brute force from {event.source_ip}.",
            failures,
        )]


# ---------------------------------------------------------------------------
# Rule 2 -- bulk record reads
# ---------------------------------------------------------------------------
class BulkReadRule(Rule):
    """ALERT when more than `threshold` records are read inside `window`.

    Reads that the busy-clinician heuristic marked `exempt_reason` are counted
    separately and do not contribute to the total. That exemption is the whole
    point: a rounding doctor stays under the line, a harvesting script does
    not (it either batches records per request or exceeds the human click
    floor, and both cost it the exemption).
    """

    rule_id = "EHR-002"
    rule_name = "Bulk Record Read"
    default_window = timedelta(minutes=10)

    def __init__(self, threshold: int = 50,
                 window: Optional[timedelta] = None,
                 cooldown: Optional[timedelta] = None):
        super().__init__(window=window, cooldown=cooldown)
        self.threshold = threshold

    def evaluate(self, event: AuditEvent, window: Sequence[AuditEvent]) -> list[Alert]:
        if not event.is_read or event.outcome is not Outcome.SUCCESS:
            return []

        reads = [
            e for e in self.recent(event, window)
            if e.is_read and e.outcome is Outcome.SUCCESS
        ]
        if event not in reads:
            reads.append(event)

        counted = sum(e.batch_size for e in reads if not e.exempt_reason)
        exempted = sum(e.batch_size for e in reads if e.exempt_reason)
        if counted <= self.threshold:
            return []

        distinct = len({rid for e in reads for rid in e.record_ids})
        batches = len(reads)
        biggest = max((e.batch_size for e in reads), default=0)
        severity = (
            Severity.CRITICAL
            if (biggest > self.threshold or distinct > self.threshold * 2)
            else Severity.HIGH
        )
        minutes = self.window.total_seconds() / 60
        return [self._alert(
            event,
            severity,
            f"{counted} records read by {event.user_id} in {minutes:.0f} min",
            f"Threshold is {self.threshold} records/{minutes:.0f} min. "
            f"Observed {counted} counted records across {batches} request(s) "
            f"({distinct} distinct charts, largest single request {biggest}). "
            f"{exempted} record(s) were exempt as clinical single-chart "
            f"workflow. Consistent with automated export.",
            [e for e in reads if not e.exempt_reason],
        )]


# ---------------------------------------------------------------------------
# Rule 3 -- role out of scope
# ---------------------------------------------------------------------------
class RoleScopeRule(Rule):
    """ALERT when an access is refused because it fell outside the role's scope.

    Catches the two flavours defined in `models.check_access`:
      * role may not perform this action at all      (Billing trying to prescribe)
      * role may not touch this record category      (Billing opening PSYCH notes)
      * staff not assigned to the record's ward      (Cardiology nurse in Psychiatry)

    This rule only reacts to `Outcome.DENIED` -- a denial is the access-control
    layer telling us the request was out of scope. A *successful* cross-department
    read by a doctor is not suspicious; that is just a doctor covering the hospital.
    """

    rule_id = "EHR-003"
    rule_name = "Role-Out-of-Scope Access"
    default_window = timedelta(minutes=30)

    def __init__(self, threshold: int = 1,
                 window: Optional[timedelta] = None,
                 cooldown: Optional[timedelta] = None):
        super().__init__(window=window, cooldown=cooldown)
        self.threshold = threshold

    def evaluate(self, event: AuditEvent, window: Sequence[AuditEvent]) -> list[Alert]:
        if event.outcome is not Outcome.DENIED:
            return []

        denials = [e for e in self.recent(event, window)
                   if e.outcome is Outcome.DENIED]
        if event not in denials:
            denials.append(event)
        denials.sort(key=lambda e: e.timestamp)

        if len(denials) < self.threshold:
            return []

        cats = sorted({c.value for e in denials for c in e.categories}) or ["-"]
        severity = Severity.HIGH if len(denials) > self.threshold else Severity.MEDIUM
        return [self._alert(
            event,
            severity,
            f"{event.user_id} ({event.role}) denied {event.action.value} "
            f"on {', '.join(cats)}",
            f"{len(denials)} out-of-scope access attempt(s) in "
            f"{self.window.total_seconds() / 60:.0f} min. Latest refusal: "
            f"{event.reason}. Category(s) touched: {', '.join(cats)}. "
            f"Source {event.source_ip}.",
            denials,
        )]


# ---------------------------------------------------------------------------
# Alert board with de-duplication
# ---------------------------------------------------------------------------
class AlertBoard:
    """Collects alerts, collapsing repeats so one incident stays one card.

    Args:
        cooldown: how long a (rule_id, user_id) pair stays collapsed. New
            occurrences inside the window bump `occurrences` on the existing
            alert instead of creating a new one.
        history: keep dismissed/suppressed alerts here for the UI's "resolved"
            panel rather than deleting them (auditability).
    """

    def __init__(self, cooldown: timedelta = timedelta(minutes=5), history: int = 500):
        self.cooldown = cooldown
        self._by_key: dict[tuple[str, str], Alert] = {}
        self._open: list[Alert] = []
        self._history: list[Alert] = []
        self._max_history = history

    def submit(self, alerts: Sequence[Alert]) -> list[Alert]:
        """Record incoming alerts. Returns only the ones that were new.

        The caller uses the return value to decide whether to notify; the UI
        animates a new card for each element returned.
        """
        fresh: list[Alert] = []
        now = datetime.now(timezone.utc)
        for alert in alerts:
            key = (alert.rule_id, alert.user_id)
            existing = self._by_key.get(key)
            if existing and now - existing.created_at < self.cooldown:
                existing.occurrences += 1
                existing.title = alert.title
                existing.detail = alert.detail
                existing.evidence = alert.evidence
                existing.severity = alert.severity
                continue
            self._by_key[key] = alert
            self._open.append(alert)
            fresh.append(alert)
        if len(self._open) > self._max_history:
            del self._open[: len(self._open) - self._max_history]
        return fresh

    @property
    def open_alerts(self) -> list[Alert]:
        return sorted(
            self._open,
            key=lambda a: (-SEVERITY_ORDER.get(a.severity, 0), a.created_at),
            reverse=False,
        )

    @property
    def acknowledged_alerts(self) -> list[Alert]:
        """Alerts that were triaged and closed out. Kept, never deleted."""
        return list(self._history)

    def acknowledge(self, alert_id: str) -> bool:
        """Move an alert out of the open list and into history."""
        for i, alert in enumerate(self._open):
            if alert.alert_id == alert_id:
                self._open.pop(i)
                self._history.append(alert)
                self._by_key.pop((alert.rule_id, alert.user_id), None)
                return True
        return False

    def acknowledge_all(self) -> int:
        count = len(self._open)
        self._history.extend(self._open)
        self._open.clear()
        self._by_key.clear()
        return count

    def reset(self) -> None:
        self._by_key.clear()
        self._open.clear()
        self._history.clear()
