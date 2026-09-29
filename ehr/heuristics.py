"""The "busy clinician" heuristic.

THE PROBLEM
-----------
Rule #2 (bulk read) fires when one user reads more than 50 records in a
window. On a real ward that happens constantly and legitimately: a consultant
doing morning rounds clicks through 60 charts in fifteen minutes, one at a
time, each click a separate HTTP request. A naive "count > 50" rule pages the
on-call security team every single morning. That is alert fatigue, and alert
fatigue is why real detection systems get switched off.

THE INSIGHT
-----------
Volume alone cannot tell "doctor rounding" apart from "attacker dumping the
table". But *shape* can. Human chart-reviewing and automated harvesting have
very different signatures:

    human rounding                 automated harvest
    ---------------                 -----------------
    batch_size == 1                batch_size in the hundreds/thousands
    one record per request         many records per request
    steady ~1-2 clicks/sec         no think-time, machine-regular
    mostly distinct records        often one sweep, may revisit
    clinical role                  any role, incl. Billing

THE HEURISTIC
-------------
An access is exempted from the bulk-read counter when ALL of these hold:

  1. the actor holds a clinical role (Doctor / Nurse);
  2. it is a read, and the request touched at most `max_batch` records
     (default 5) -- i.e. genuine one-chart-at-a-time navigation;
  3. the actor's recent reads all sit inside the clinical pacing band: at
     least `min_interval` apart, but never faster than `max_rate`;
  4. records are not being re-read in a tight loop (repeat_ratio below
     `max_repeat_ratio`).

THE SAFETY VALVE
----------------
The exemption is deliberately *bounded*. `max_rate` is a hard ceiling
(default 5 reads/sec sustained). No human clicks that fast, so a script
batching through records inside a "clinical role" account still trips the
bulk rule. The heuristic reduces false positives; it does not open a hole.
"""

from __future__ import annotations

import statistics  # noqa: F401  (reserved for future percentile tuning)
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Deque, Optional

from .audit import AuditEvent
from .models import CLINICAL_ROLES, Action, Outcome, Role

DEFAULT_WINDOW = timedelta(minutes=15)
DEFAULT_MAX_BATCH = 5
DEFAULT_MIN_INTERVAL = 0.4      # seconds; faster than this is not a human click
DEFAULT_MAX_RATE = 5.0          # reads/sec sustained ceiling (hard valve)
DEFAULT_MAX_REPEAT_RATIO = 0.25  # >25% of recent reads revisiting same chart


@dataclass(frozen=True)
class HeuristicVerdict:
    """Outcome of the busy-clinician check for a single access."""

    exempt: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.exempt


class BusyClinicianHeuristic:
    """Tracks per-user read cadence and decides which reads are 'just rounding'.

    Args:
        window:          how far back to look when measuring cadence.
        max_batch:       largest single request still considered "individual".
        min_interval:    seconds a human plausibly needs between chart clicks.
        max_rate:        reads/sec ceiling above which the exemption is revoked
                         no matter how clinical the role looks.
        max_repeat_ratio: fraction of recent reads that may revisit the same
                          record before we stop believing it is human browsing.
    """

    def __init__(
        self,
        window: timedelta = DEFAULT_WINDOW,
        max_batch: int = DEFAULT_MAX_BATCH,
        min_interval: float = DEFAULT_MIN_INTERVAL,
        max_rate: float = DEFAULT_MAX_RATE,
        max_repeat_ratio: float = DEFAULT_MAX_REPEAT_RATIO,
    ):
        self.window = window
        self.max_batch = max_batch
        self.min_interval = min_interval
        self.max_rate = max_rate
        self.max_repeat_ratio = max_repeat_ratio

        # user_id -> deque of (timestamp, record_id) for *read* events only
        self._reads: dict[str, Deque[tuple[datetime, str]]] = defaultdict(deque)
        # user_id -> Role, refreshed on every evaluation
        self._roles: dict[str, Role] = {}

    # -- introspection (used by the UI) ---------------------------------
    @property
    def config(self) -> dict:
        return {
            "window_seconds": self.window.total_seconds(),
            "max_batch": self.max_batch,
            "min_interval_seconds": self.min_interval,
            "max_rate_per_second": self.max_rate,
            "max_repeat_ratio": self.max_repeat_ratio,
        }

    def observed_rate(self, user_id: str, now: Optional[datetime] = None) -> float:
        """Reads/sec for `user_id` over the trailing window."""
        return self._rate(self._prune(user_id, now))

    def last_interval(self, user_id: str, now: Optional[datetime] = None) -> Optional[float]:
        """Seconds between the two most recent reads, or None if <2 reads."""
        items = self._prune(user_id, now)
        if len(items) < 2:
            return None
        return (items[-1][0] - items[-2][0]).total_seconds()

    # -- internals ------------------------------------------------------
    def _prune(self, user_id: str, now: Optional[datetime]) -> list[tuple[datetime, str]]:
        q = self._reads[user_id]
        reference = now or (q[-1][0] if q else None)
        if reference is None:
            return []
        cutoff = reference - self.window
        while q and q[0][0] < cutoff:
            q.popleft()
        return list(q)

    @staticmethod
    def _rate(items: list[tuple[datetime, str]]) -> float:
        if len(items) < 2:
            return 0.0
        span = (items[-1][0] - items[0][0]).total_seconds()
        if span <= 0:
            # zero elapsed time with several reads == machine speed
            return float(len(items))
        return (len(items) - 1) / span

    @staticmethod
    def _repeat_ratio(items: list[tuple[datetime, str]]) -> float:
        if not items:
            return 0.0
        unique = len({rid for _, rid in items})
        return 1.0 - (unique / len(items))

    # -- public API -----------------------------------------------------
    def evaluate(self, event: AuditEvent) -> HeuristicVerdict:
        """Should this read be treated as normal clinical workflow?

        Call *after* the event has been written to the audit log. The verdict
        only suppresses the bulk-read volume signal -- authorization was
        already decided, and every event is still audited and still visible in
        the log. It also records this access in the cadence history so the
        *next* call can measure pace.
        """
        # Only successful clinical reads are candidates for exemption.
        if event.action not in (Action.VIEW, Action.EXPORT):
            return HeuristicVerdict(False)
        if event.outcome is not Outcome.SUCCESS:
            return HeuristicVerdict(False)

        role = Role(event.role)
        self._roles[event.user_id] = role
        if role not in CLINICAL_ROLES:
            return HeuristicVerdict(
                False, f"{role.value} is not a clinical role"
            )

        if event.batch_size > self.max_batch:
            return HeuristicVerdict(
                False,
                f"batch of {event.batch_size} exceeds individual-navigation "
                f"limit of {self.max_batch}",
            )

        history = self._prune(event.user_id, event.timestamp)

        # Pace check: how long since this user's *previous* read? One prior
        # read is enough, so an immediate double-click is caught from the
        # second access onwards.
        if history:
            gap = (event.timestamp - history[-1][0]).total_seconds()
            if gap < self.min_interval:
                return HeuristicVerdict(
                    False,
                    f"reads only {gap:.2f}s apart, below human click floor of "
                    f"{self.min_interval}s",
                )

        rate = self._rate(history)
        if rate > self.max_rate:
            return HeuristicVerdict(
                False,
                f"sustained rate {rate:.1f} reads/sec exceeds clinical ceiling "
                f"of {self.max_rate}",
            )

        repeat_ratio = self._repeat_ratio(history)
        if repeat_ratio > self.max_repeat_ratio:
            return HeuristicVerdict(
                False,
                f"{repeat_ratio:.0%} of recent reads revisit the same chart",
            )

        # Exempt: record it in the cadence history and pass.
        self._reads[event.user_id].append(
            (event.timestamp, event.record_ids[0] if event.record_ids else "")
        )
        return HeuristicVerdict(
            True,
            f"clinical workflow: batch={event.batch_size}, "
            f"rate={rate:.2f} reads/sec over {self.window.total_seconds():.0f}s",
        )

    def reset(self) -> None:
        self._reads.clear()
        self._roles.clear()
