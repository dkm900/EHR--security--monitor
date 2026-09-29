"""EHR security monitor -- a lightweight, dependency-light prototype.

Layered so each concern can be tested (and replaced) on its own:

    models      roles, permissions, data-scope rules
    records     synthetic patient chart store
    audit       tamper-evident append-only log of every access attempt
    heuristics  the "busy clinician" false-positive suppressor
    detectors   the detection rules + alert de-duplication board
    monitor     the orchestrator that wires the above together
"""

from .audit import AuditEvent, AuditLog
from .detectors import (
    Alert,
    AlertBoard,
    BulkReadRule,
    FailedLoginRule,
    RoleScopeRule,
    Severity,
)
from .heuristics import BusyClinicianHeuristic, HeuristicVerdict
from .models import (
    Action,
    Outcome,
    RecordCategory,
    Role,
    Staff,
    check_access,
)
from .monitor import AccessResult, EHRMonitor
from .records import PatientRecord, RecordStore, seed_staff

__all__ = [
    "Action",
    "Alert",
    "AlertBoard",
    "AuditEvent",
    "AuditLog",
    "AccessResult",
    "BulkReadRule",
    "BusyClinicianHeuristic",
    "EHRMonitor",
    "FailedLoginRule",
    "HeuristicVerdict",
    "Outcome",
    "PatientRecord",
    "RecordCategory",
    "RecordStore",
    "Role",
    "RoleScopeRule",
    "Severity",
    "Staff",
    "check_access",
    "seed_staff",
]
