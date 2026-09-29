"""The monitor: the single entry point every access attempt flows through.

Call order matters and is enforced here:

    1. authorise   -- models.check_access decides allow / deny
    2. audit       -- the attempt is written to the immutable log (always)
    3. heuristic   -- busy-clinician check may mark a read as clinical workflow
    4. detect      -- each rule inspects the new event + the user's recent window
    5. board       -- alerts are de-duplicated and surfaced

Note the ordering of 2 and 3: the event is logged *before* the heuristic runs,
so nothing can be read without leaving a trace. The exemption is then attached
to the logged event as `exempt_reason` (it is an annotation on the record, not
a deletion of it) and detectors read that annotation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Sequence

from .audit import AuditEvent, AuditLog
from .detectors import Alert, AlertBoard, BulkReadRule, FailedLoginRule, RoleScopeRule
from .heuristics import BusyClinicianHeuristic
from .models import (
    Action,
    Outcome,
    RecordCategory,
    Role,
    Staff,
    check_access,
)
from .records import RecordStore, seed_staff


@dataclass
class AccessResult:
    """What the caller gets back after attempting an access."""

    allowed: bool
    event: AuditEvent
    alerts: list[Alert]
    exempt: bool = False
    exempt_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "event": self.event.to_dict(),
            "alerts": [a.to_dict() for a in self.alerts],
            "exempt": self.exempt,
            "exempt_reason": self.exempt_reason,
        }


class EHRMonitor:
    """Security monitor for a mock EHR.

    Args:
        audit_path:   where to mirror the audit log (JSONL). None = memory only.
        bulk_threshold:   records per window before EHR-002 fires.
        login_threshold:  failed logins before EHR-001 fires.
        heuristic:    pass a pre-configured BusyClinicianHeuristic, or None for
                      the defaults.
    """

    def __init__(
        self,
        audit_path: Optional[Path | str] = None,
        bulk_threshold: int = 50,
        login_threshold: int = 3,
        heuristic: Optional[BusyClinicianHeuristic] = None,
    ):
        self.audit = AuditLog(path=audit_path)
        self.heuristic = heuristic or BusyClinicianHeuristic()
        self.board = AlertBoard()
        self.rules = [
            FailedLoginRule(threshold=login_threshold),
            BulkReadRule(threshold=bulk_threshold),
            RoleScopeRule(),
        ]
        self.records = RecordStore()
        self.staff: dict[str, Staff] = seed_staff()
        self._login_state: dict[str, dict] = {}

    # -- staff ----------------------------------------------------------
    def register(self, staff: Staff) -> None:
        self.staff[staff.user_id] = staff

    def get_staff(self, user_id: str) -> Optional[Staff]:
        return self.staff.get(user_id)

    # -- session --------------------------------------------------------
    def _window_for(self, event: AuditEvent, window: timedelta) -> list[AuditEvent]:
        """The slice of history a rule should judge `event` against."""
        cutoff = event.timestamp - window
        return [
            e for e in self.audit.recent(limit=5000)
            if e.user_id == event.user_id and e.timestamp <= event.timestamp
            and e.timestamp >= cutoff
        ]

    # -- the one method everything goes through -------------------------
    def _process(
        self,
        *,
        user_id: str,
        action: Action,
        record_ids: Sequence[str] = (),
        categories: Sequence[RecordCategory] = (),
        department: "frozenset[str] | tuple[str, ...]" = (),
        outcome_override: Optional[Outcome] = None,
        reason_override: str = "",
        source_ip: str = "127.0.0.1",
        timestamp: Optional[datetime] = None,
        skip_authz: bool = False,
    ) -> AccessResult:
        staff = self.staff.get(user_id)

        # --- 1. authorise ------------------------------------------------
        if outcome_override is not None:
            # caller already knows the outcome (e.g. simulating a bad password)
            outcome, reason = outcome_override, reason_override
        elif staff is None:
            outcome, reason = Outcome.FAILED, "unknown user id"
        elif not skip_authz:
            decision = check_access(staff, action, set(categories), department)
            outcome = Outcome.SUCCESS if decision else Outcome.DENIED
            reason = "" if decision else decision.reason
        else:
            outcome, reason = Outcome.SUCCESS, ""

        # --- 2. busy-clinician heuristic (pre-log annotation) -----------
        # The heuristic keeps its own cadence state, so it can judge a
        # provisional event before that event is committed to the log. We
        # evaluate first and log once, which means the exemption is stored as
        # an annotation on the permanent record rather than as an edit to it.
        provisional = AuditEvent(
            event_id="",
            timestamp=timestamp or datetime.now(timezone.utc),
            user_id=user_id,
            role=staff.role.value if staff else "Unknown",
            action=action,
            outcome=outcome,
            reason=reason,
            record_ids=tuple(record_ids),
            categories=tuple(categories),
            department=department,
            batch_size=len(record_ids),
            source_ip=source_ip,
        )
        verdict = self.heuristic.evaluate(provisional)

        # --- 3. audit (always) ------------------------------------------
        event = self.audit.record(
            user_id=user_id,
            role=provisional.role,
            action=action,
            outcome=outcome,
            reason=reason,
            record_ids=record_ids,
            categories=categories,
            department=department,
            batch_size=len(record_ids),
            source_ip=source_ip,
            exempt_reason=verdict.reason if verdict.exempt else "",
            timestamp=provisional.timestamp,
        )

        # --- 4. run every rule ------------------------------------------
        triggered: list[Alert] = []
        for rule in self.rules:
            window = self._window_for(event, rule.window)
            triggered.extend(rule.evaluate(event, window))

        # --- 5. de-duplicate + surface ----------------------------------
        fresh = self.board.submit(triggered)
        return AccessResult(
            allowed=outcome is Outcome.SUCCESS,
            event=event,
            alerts=fresh,
            exempt=verdict.exempt,
            exempt_reason=verdict.reason,
        )

    # -- public operations ----------------------------------------------
    def attempt_login(self, user_id: str, password: str = "correct-horse",
                      source_ip: str = "127.0.0.1",
                      timestamp: Optional[datetime] = None) -> AccessResult:
        """Simulate authentication.

        The demo directory has no passwords, so anything other than the sentinel
        is a failure. Swap this body for a real IdP call in production; the
        monitoring downstream is unchanged.
        """
        staff = self.staff.get(user_id)
        if password != "correct-horse":
            return self._process(
                user_id=user_id,
                action=Action.LOGIN,
                outcome_override=Outcome.FAILED,
                reason_override="invalid credentials",
                source_ip=source_ip,
                timestamp=timestamp,
            )
        if staff is None:
            return self._process(
                user_id=user_id,
                action=Action.LOGIN,
                outcome_override=Outcome.FAILED,
                reason_override="unknown user id",
                source_ip=source_ip,
                timestamp=timestamp,
            )
        state = self._login_state.setdefault(user_id, {"failures": 0, "locked": False})
        state["failures"] = 0
        state["locked"] = False
        return self._process(
            user_id=user_id,
            action=Action.LOGIN,
            source_ip=source_ip,
            timestamp=timestamp,
        )

    def is_locked_out(self, user_id: str) -> bool:
        return self._login_state.get(user_id, {}).get("locked", False)

    def access_records(
        self,
        user_id: str,
        record_ids: Sequence[str],
        action: Action = Action.VIEW,
        sections: Optional[Sequence[RecordCategory]] = None,
        source_ip: str = "127.0.0.1",
        timestamp: Optional[datetime] = None,
        bypass_authorization: bool = False,
    ) -> AccessResult:
        """Open a set of charts as `user_id`.

        Args:
            record_ids: charts to touch.
            action:     VIEW / WRITE / PRESCRIBE / EXPORT.
            sections:   which parts of each chart to open. `None` means "the
                        whole chart". Passing e.g. `[RecordCategory.BILLING]`
                        models a Billing clerk opening only the billing tab of
                        a chart -- in scope, even though the same chart also
                        holds clinical notes the clerk may not see.
                        Sections are intersected with what each record actually
                        contains, so a caller cannot request a section that does
                        not exist.
        """
        records = self.records.many(record_ids)
        found_ids = [r.record_id for r in records]
        missing = [r for r in record_ids if r not in found_ids]

        # The union of everything actually being opened across these records.
        categories: set[RecordCategory] = set()
        departments: set[str] = set()
        for rec in records:
            present = set(rec.categories)
            categories |= (set(sections) & present) if sections else present
            departments.add(rec.department)

        if not records or not categories:
            return self._process(
                user_id=user_id,
                action=action,
                record_ids=list(record_ids),
                outcome_override=Outcome.DENIED,
                reason_override=(
                    f"no such record(s): {', '.join(missing[:5])}"
                    if not records
                    else f"requested section(s) not present in {', '.join(found_ids[:5])}"
                ),
                source_ip=source_ip,
                timestamp=timestamp,
            )

        department: frozenset[str] = frozenset(departments)
        if missing:
            return self._process(
                user_id=user_id,
                action=action,
                record_ids=found_ids,
                categories=sorted(categories, key=lambda c: c.value),
                department=department,
                outcome_override=Outcome.DENIED,
                reason_override=f"{len(missing)} requested record(s) do not exist",
                source_ip=source_ip,
                timestamp=timestamp,
            )

        return self._process(
            user_id=user_id,
            action=action,
            record_ids=found_ids,
            categories=sorted(categories, key=lambda c: c.value),
            department=department,
            source_ip=source_ip,
            timestamp=timestamp,
            skip_authz=bypass_authorization,
        )

    # -- reporting -------------------------------------------------------
    def stats(self) -> dict:
        outcomes = self.audit.counts_by_outcome()
        reads = [
            e for e in self.audit.recent(limit=5000)
            if e.is_read and e.outcome is Outcome.SUCCESS
        ]
        return {
            "total_events": len(self.audit),
            "outcomes": outcomes,
            "reads": len(reads),
            "records_read": sum(e.batch_size for e in reads),
            "records_exempt": sum(e.batch_size for e in reads if e.exempt_reason),
            "open_alerts": len(self.board.open_alerts),
            "acknowledged": len(self.board.acknowledged_alerts),
            "by_severity": self._severity_tally(),
            "staff_count": len(self.staff),
            "record_count": len(self.records),
            "chain_ok": self.audit.verify_chain()[0],
        }

    def _severity_tally(self) -> dict[str, int]:
        tally = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for alert in self.board.open_alerts:
            if alert.severity in tally:
                tally[alert.severity] += 1
        return tally

    def reset(self) -> None:
        """Clear all runtime state (used by the portal's Reset button)."""
        self.audit = AuditLog(path=self.audit._path)
        self.board.reset()
        self.heuristic.reset()
        self._login_state.clear()
