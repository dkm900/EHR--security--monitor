"""Tests for the busy-clinician heuristic.

These are the tests that matter most. A detection system that pages you every
morning because a consultant opened 60 charts is worse than no system at all,
so the exemption and -- just as importantly -- its limits are pinned down here.
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ehr.audit import AuditEvent  # noqa: E402
from ehr.heuristics import BusyClinicianHeuristic  # noqa: E402
from ehr.models import Action, Outcome, RecordCategory, Role  # noqa: E402

T0 = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)


def read_event(
    seq: int,
    *,
    role: str = Role.DOCTOR.value,
    outcome: Outcome = Outcome.SUCCESS,
    batch: int = 1,
    action: Action = Action.VIEW,
    record_id: str | None = None,
    exempt: str = "",
) -> AuditEvent:
    """Build a synthetic read event `seq` seconds after T0."""
    ids = tuple(f"MRN-{1000 + (seq if record_id is None else record_id)}"
                for _ in range(batch))
    return AuditEvent(
        event_id=f"e{seq}",
        timestamp=T0 + timedelta(seconds=seq),
        user_id="dr.okafor",
        role=role,
        action=action,
        outcome=outcome,
        record_ids=ids,
        categories=(RecordCategory.CLINICAL,),
        department=("Cardiology",),
        batch_size=batch,
        exempt_reason=exempt,
    )


class TestBusyClinicianExemption(unittest.TestCase):
    """The exemption MUST be granted in these situations."""

    def setUp(self):
        self.h = BusyClinicianHeuristic()

    def test_single_read_is_exempt(self):
        self.assertTrue(self.h.evaluate(read_event(0)))

    def test_seventy_reads_one_second_apart_all_exempt(self):
        """The headline false-positive case: a doctor on rounds."""
        verdicts = [self.h.evaluate(read_event(i)) for i in range(70)]
        self.assertTrue(all(verdicts), "every rounds read should be exempt")
        self.assertEqual(self.h.observed_rate("dr.okafor"), 1.0)

    def test_seventy_reads_two_seconds_apart_all_exempt(self):
        verdicts = [self.h.evaluate(read_event(i * 2)) for i in range(70)]
        self.assertTrue(all(verdicts))

    def test_nurse_gets_the_same_exemption(self):
        h = BusyClinicianHeuristic()
        verdicts = [h.evaluate(read_event(i, role=Role.NURSE.value))
                    for i in range(70)]
        self.assertTrue(all(verdicts))

    def test_batch_of_five_is_still_individual_navigation(self):
        h = BusyClinicianHeuristic()
        self.assertTrue(h.evaluate(read_event(0, batch=5)))

    def test_exemption_reason_is_populated(self):
        v = self.h.evaluate(read_event(0))
        self.assertIn("clinical workflow", v.reason)

    def test_observed_rate_and_interval(self):
        self.h.evaluate(read_event(0))
        self.h.evaluate(read_event(2))
        self.assertAlmostEqual(self.h.observed_rate("dr.okafor"), 0.5, places=3)
        self.assertAlmostEqual(self.h.last_interval("dr.okafor"), 2.0, places=3)


class TestExemptionLimits(unittest.TestCase):
    """The exemption MUST be revoked in these situations -- otherwise the
    heuristic is a hole an attacker walks straight through."""

    def setUp(self):
        self.h = BusyClinicianHeuristic()

    def test_billing_never_gets_the_exemption(self):
        v = self.h.evaluate(read_event(0, role=Role.BILLING.value))
        self.assertFalse(v)
        self.assertIn("not a clinical role", v.reason)

    def test_admin_never_gets_the_exemption(self):
        v = self.h.evaluate(read_event(0, role=Role.ADMIN.value))
        self.assertFalse(v)

    def test_large_batch_loses_the_exemption(self):
        v = self.h.evaluate(read_event(0, batch=6))
        self.assertFalse(v)
        self.assertIn("individual-navigation", v.reason)

    def test_huge_batch_loses_the_exemption(self):
        v = self.h.evaluate(read_event(0, batch=5000))
        self.assertFalse(v)

    def test_machine_pace_loses_the_exemption(self):
        """20 reads/sec: the safety valve. First few pass, then it closes."""
        verdicts = [self.h.evaluate(read_event(i * 0.05)) for i in range(70)]
        self.assertFalse(all(verdicts), "scripted pace must not stay exempt")
        self.assertTrue(any(not v for v in verdicts))

    def test_too_fast_immediately_loses_the_exemption(self):
        self.h.evaluate(read_event(0))
        v = self.h.evaluate(read_event(0.1))     # 0.1s gap, below 0.4s floor
        self.assertFalse(v)
        self.assertIn("human click floor", v.reason)

    def test_repeated_same_chart_loses_the_exemption(self):
        """Looping the same chart is a script, not a clinician."""
        h = BusyClinicianHeuristic(max_repeat_ratio=0.25)
        verdicts = [h.evaluate(read_event(i, record_id=0)) for i in range(20)]
        self.assertFalse(all(verdicts), "one repeated chart is not rounds")

    def test_failed_read_is_not_exempt(self):
        v = self.h.evaluate(read_event(0, outcome=Outcome.FAILED))
        self.assertFalse(v)

    def test_denied_read_is_not_exempt(self):
        v = self.h.evaluate(read_event(0, outcome=Outcome.DENIED))
        self.assertFalse(v)

    def test_write_is_not_exempt(self):
        v = self.h.evaluate(read_event(0, action=Action.WRITE))
        self.assertFalse(v)

    def test_stale_reads_outside_window_are_forgotten(self):
        """Activity older than the window must not poison current judgement."""
        self.h.evaluate(read_event(0))
        self.h.evaluate(read_event(1))
        # 20 minutes later, well outside the 15-minute window.
        v = self.h.evaluate(read_event(20 * 60))
        self.assertTrue(v)


class TestHeuristicConfig(unittest.TestCase):
    def test_config_is_reportable(self):
        cfg = BusyClinicianHeuristic().config
        for key in ("window_seconds", "max_batch", "min_interval_seconds",
                    "max_rate_per_second", "max_repeat_ratio"):
            self.assertIn(key, cfg)

    def test_reset_clears_history(self):
        h = BusyClinicianHeuristic()
        h.evaluate(read_event(0))
        h.evaluate(read_event(1))
        h.reset()
        self.assertEqual(h.observed_rate("dr.okafor"), 0.0)

    def test_thresholds_are_configurable(self):
        """A hospital that rounds faster can loosen the click floor."""
        h = BusyClinicianHeuristic(min_interval=0.05, max_rate=50.0)
        verdicts = [h.evaluate(read_event(i * 0.1)) for i in range(60)]
        self.assertTrue(all(verdicts), "loosened thresholds should exempt all")


if __name__ == "__main__":
    unittest.main(verbosity=2)
