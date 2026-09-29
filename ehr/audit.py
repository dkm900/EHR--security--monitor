"""Tamper-evident, append-only audit log.

Every access attempt -- successful, denied, or failed -- lands here first.
Detectors read *from* this log; nothing in the system is allowed to observe an
access without it being recorded.

Each entry stores a SHA-256 hash of (previous entry's hash + this entry's
payload). That forms a hash chain: if anyone edits or deletes a historical
row, `verify_chain()` will fail and the tampering becomes detectable.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence

from .models import Action, Outcome, RecordCategory

GENESIS_HASH = "0" * 64


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class AuditEvent:
    """One immutable access attempt.

    `batch_size` matters: it distinguishes "a clinician clicking through 60
    charts one at a time" (batch_size == 1) from "a script dumping the whole
    table" (batch_size == 5000). The bulk-read heuristic keys off it.
    """

    event_id: str
    timestamp: datetime
    user_id: str
    role: str
    action: Action
    outcome: Outcome
    reason: str = ""
    record_ids: tuple[str, ...] = ()
    categories: tuple[RecordCategory, ...] = ()
    #: Owning ward(s) touched. A single access can span several charts in
    #: several wards, so this is a tuple rather than one string.
    department: tuple[str, ...] = ()
    batch_size: int = 0
    source_ip: str = "127.0.0.1"
    #: Set by the busy-clinician heuristic when this access looks like normal
    #: ward-round workflow rather than automated harvesting.
    exempt_reason: str = ""
    prev_hash: str = GENESIS_HASH
    entry_hash: str = ""

    @property
    def department_label(self) -> str:
        """Human-readable single string, for the UI and alert text."""
        return ", ".join(self.department)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["action"] = self.action.value
        data["outcome"] = self.outcome.value
        data["categories"] = [c.value for c in self.categories]
        data["record_ids"] = list(self.record_ids)
        data["department"] = list(self.department)
        data["department_label"] = self.department_label
        return data

    @property
    def is_read(self) -> bool:
        return self.action in (Action.VIEW, Action.EXPORT)

    def compute_hash(self) -> str:
        payload = {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "role": self.role,
            "action": self.action.value,
            "outcome": self.outcome.value,
            "reason": self.reason,
            "record_ids": list(self.record_ids),
            "categories": [c.value for c in self.categories],
            "department": list(self.department),
            "batch_size": self.batch_size,
            "source_ip": self.source_ip,
            "exempt_reason": self.exempt_reason,
            "prev_hash": self.prev_hash,
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class AuditLog:
    """Thread-safe append-only log with an optional JSONL mirror on disk.

    Args:
        path: when given, every event is also appended to this file as one JSON
            object per line. The file is append-only by convention; the hash
            chain is what actually *enforces* tamper-evidence.
        max_memory: soft cap on retained events. Older events are dropped from
            memory only -- the JSONL file, if configured, keeps everything.
    """

    def __init__(self, path: Optional[Path | str] = None, max_memory: int = 20_000):
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()
        self._last_hash = GENESIS_HASH
        self._path = Path(path) if path else None
        self._max_memory = max_memory
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    # -- properties -----------------------------------------------------
    @property
    def last_hash(self) -> str:
        return self._last_hash

    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self) -> Iterator[AuditEvent]:
        return iter(tuple(self._events))

    # -- writing --------------------------------------------------------
    def record(
        self,
        *,
        user_id: str,
        role: str,
        action: Action,
        outcome: Outcome,
        reason: str = "",
        record_ids: Sequence[str] = (),
        categories: Sequence[RecordCategory] = (),
        department: "str | Iterable[str]" = (),
        batch_size: int = 0,
        source_ip: str = "127.0.0.1",
        exempt_reason: str = "",
        timestamp: Optional[datetime] = None,
    ) -> AuditEvent:
        """Append one access attempt. Returns the stored (hashed) event.

        `batch_size` defaults to `len(record_ids)` when not supplied, but can be
        passed explicitly to represent a search/export that touched N records
        without materialising all of their IDs.
        """
        with self._lock:
            event = AuditEvent(
                event_id=uuid.uuid4().hex[:12],
                timestamp=timestamp or _utc_now(),
                user_id=user_id,
                role=role,
                action=action,
                outcome=outcome,
                reason=reason,
                record_ids=tuple(record_ids),
                categories=tuple(categories),
                department=(
                    (department,) if isinstance(department, str)
                    else tuple(department)
                ),
                batch_size=batch_size or len(record_ids),
                source_ip=source_ip,
                exempt_reason=exempt_reason,
                prev_hash=self._last_hash,
            )
            event = replace(event, entry_hash=event.compute_hash())
            self._last_hash = event.entry_hash
            self._events.append(event)
            if len(self._events) > self._max_memory:
                del self._events[: len(self._events) - self._max_memory]
            if self._path is not None:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event.to_dict()) + "\n")
            return event

    # -- reading --------------------------------------------------------
    def recent(self, limit: int = 100) -> list[AuditEvent]:
        """Newest-first slice of the log."""
        with self._lock:
            return list(reversed(self._events[-limit:]))

    def since(self, moment: datetime) -> list[AuditEvent]:
        """All events at or after `moment` (oldest-first)."""
        with self._lock:
            return [e for e in self._events if e.timestamp >= moment]

    def for_user(self, user_id: str, limit: Optional[int] = None) -> list[AuditEvent]:
        with self._lock:
            out = [e for e in self._events if e.user_id == user_id]
        return out[-limit:] if limit else out

    def counts_by_outcome(self) -> dict[str, int]:
        tally = {o.value: 0 for o in Outcome}
        for event in self._events:
            tally[event.outcome.value] += 1
        return tally

    # -- integrity ------------------------------------------------------
    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """Recompute every hash. Returns (ok, first_bad_event_id).

        A `None` id with ok=True means the log is intact. A non-None id means
        that entry (or one before it) was altered after being written.
        """
        prev = GENESIS_HASH
        with self._lock:
            for event in self._events:
                if event.prev_hash != prev:
                    return False, event.event_id
                if event.compute_hash() != event.entry_hash:
                    return False, event.event_id
                prev = event.entry_hash
        return True, None
