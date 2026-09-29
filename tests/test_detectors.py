"""Tests for the three detection rules and the alert board."""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ehr.audit import AuditEvent, AuditLog  # noqa: E402
from ehr.detectors import (  # noqa: E402
    Alert,
    AlertBoard,
    BulkReadRule,
    FailedLoginRule,
    RoleScopeRule,
    Severity,
)
from ehr.models import Action, Outcome, RecordCategory  # noqa: E402

T0 = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)


def ev(
    offset_s: float = 0,
    *,
    action: Action = Action.VIEW,
    outcome: Outcome = Outcome.SUCCESS,
    user: str = "dr.x",
    role: str = "Doctor",
    batch: int = 1,
    exempt: str = "",
    reason: str = "",
    categories=(RecordCategory.CLINICAL,),
) -> AuditEvent:
    return AuditEvent(
        event_id=f"e{offset_s}",
        timestamp=T0 + timedelta(seconds=offset_s),
        user_id=user,
        role=role,
        action=action,
        outcome=outcome,
        reason=reason,
        record_ids=tuple(f"MRN-{i}" for i in range(batch)),
        categories=tuple(categories),
        department=("Cardiology",),
        batch_size=batch,
        exempt_reason=exempt,
    )


# ---------------------------------------------------------------------------
class TestFailedLoginRule(unittest.TestCase):
    def setUp(self):
        self.rule = FailedLoginRule(threshold=3)

    def _run(self, failures: int):
        history = [ev(i * 10, action=Action.LOGIN, outcome=Outcome.FAILED)
                   for i in range(failures - 1)]
        latest = ev((failures - 1) * 10, action=Action.LOGIN,
                    outcome=Outcome.FAILED)
        return self.rule.evaluate(latest, history)

    def test_one_failure_is_silent(self):
        self.assertEqual(self._run(1), [])

    def test_two_failures_is_silent(self):
        self.assertEqual(self._run(2), [])

    def test_three_failures_alerts(self):
        alerts = self._run(3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "EHR-001")
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)

    def test_five_failures_escalates_to_high(self):
        self.assertEqual(self._run(5)[0].severity, Severity.HIGH)

    def test_eight_failures_escalates_to_critical(self):
        self.assertEqual(self._run(8)[0].severity, Severity.CRITICAL)

    def test_successful_login_does_not_re_alert(self):
        """Rule 1 fires on the failure that crosses the threshold, not on the
        later success. The success is still audited -- it just is not a new
        authentication failure."""
        history = [ev(i * 10, action=Action.LOGIN, outcome=Outcome.FAILED)
                   for i in range(5)]
        latest = ev(60, action=Action.LOGIN, outcome=Outcome.SUCCESS)
        self.assertEqual(self.rule.evaluate(latest, history), [])

    def test_denied_access_does_not_count_as_failed_login(self):
        """A denial is a permissions problem, not an auth problem."""
        history = [ev(i * 10, action=Action.VIEW, outcome=Outcome.DENIED)
                   for i in range(5)]
        latest = ev(60, action=Action.VIEW, outcome=Outcome.DENIED)
        self.assertEqual(self.rule.evaluate(latest, history), [])

    def test_failures_outside_window_do_not_count(self):
        rule = FailedLoginRule(threshold=3, window=timedelta(minutes=15))
        history = [ev(i * 20 * 60, action=Action.LOGIN, outcome=Outcome.FAILED)
                   for i in range(2)]        # 20 and 40 minutes ago
        latest = ev(60 * 60, action=Action.LOGIN, outcome=Outcome.FAILED)
        self.assertEqual(rule.evaluate(latest, history), [])

    def test_alert_mentions_the_user_and_ip(self):
        alert = self._run(3)[0]
        self.assertIn("dr.x", alert.title)
        self.assertIn("brute force", alert.detail.lower())


# ---------------------------------------------------------------------------
class TestBulkReadRule(unittest.TestCase):
    def setUp(self):
        self.rule = BulkReadRule(threshold=50)

    def test_fifty_one_records_alerts(self):
        history = [ev(0, batch=50)]
        latest = ev(1, batch=1)
        alerts = self.rule.evaluate(latest, history)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "EHR-002")

    def test_exactly_fifty_is_silent(self):
        history = [ev(0, batch=49)]
        self.assertEqual(self.rule.evaluate(ev(1, batch=1), history), [])

    def test_exempt_reads_are_not_counted(self):
        """The whole point: 70 exempt reads must stay under the line."""
        history = [ev(i, batch=1, exempt="clinical workflow") for i in range(69)]
        latest = ev(69, batch=1, exempt="clinical workflow")
        self.assertEqual(self.rule.evaluate(latest, history), [])

    def test_mix_of_exempt_and_uncounted_only_counts_the_uncounted(self):
        history = [ev(i, batch=1, exempt="clinical workflow") for i in range(70)]
        history += [ev(100 + i, batch=1) for i in range(49)]
        latest = ev(200, batch=2)          # 49 + 2 = 51 counted
        alerts = self.rule.evaluate(latest, history)
        self.assertEqual(len(alerts), 1)
        self.assertIn("exempt", alerts[0].detail)

    def test_denied_reads_are_not_counted(self):
        history = [ev(i, batch=100, outcome=Outcome.DENIED) for i in range(5)]
        self.assertEqual(self.rule.evaluate(ev(9, batch=1), history), [])

    def test_writes_are_not_counted_as_reads(self):
        history = [ev(i, batch=100, action=Action.WRITE) for i in range(5)]
        self.assertEqual(self.rule.evaluate(ev(9, batch=1, action=Action.WRITE),
                                            history), [])

    def test_one_giant_request_is_critical(self):
        history = [ev(0, batch=0)]
        latest = ev(1, batch=5000)
        alerts = self.rule.evaluate(latest, history)
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)

    def test_slow_steady_burn_is_high_not_critical(self):
        history = [ev(i, batch=1) for i in range(50)]
        latest = ev(50, batch=1)
        self.assertEqual(self.rule.evaluate(latest, history)[0].severity,
                         Severity.HIGH)

    def test_threshold_is_configurable(self):
        strict = BulkReadRule(threshold=10)
        history = [ev(i, batch=1) for i in range(10)]
        self.assertEqual(len(strict.evaluate(ev(10, batch=1), history)), 1)

    def test_reads_outside_window_do_not_count(self):
        rule = BulkReadRule(threshold=50, window=timedelta(minutes=10))
        history = [ev(i * 11 * 60, batch=1) for i in range(60)]
        self.assertEqual(rule.evaluate(ev(60 * 60, batch=1), history), [])


# ---------------------------------------------------------------------------
class TestRoleScopeRule(unittest.TestCase):
    def setUp(self):
        self.rule = RoleScopeRule()

    def test_single_denial_alerts(self):
        alerts = self.rule.evaluate(
            ev(0, outcome=Outcome.DENIED, role="Billing",
               categories=(RecordCategory.PSYCH,),
               reason="role Billing may not read 'psych' records"),
            [],
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "EHR-003")
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)

    def test_repeat_denials_escalate_to_high(self):
        history = [ev(i, outcome=Outcome.DENIED, reason="nope") for i in range(3)]
        latest = ev(9, outcome=Outcome.DENIED, reason="nope")
        self.assertEqual(self.rule.evaluate(latest, history)[0].severity,
                         Severity.HIGH)

    def test_successful_access_does_not_alert(self):
        """A doctor reading across the hospital is not a violation."""
        self.assertEqual(self.rule.evaluate(ev(0), []), [])

    def test_failed_login_does_not_alert(self):
        """A bad password is an auth problem (rule 1), not a scope problem."""
        event = ev(0, action=Action.LOGIN, outcome=Outcome.FAILED)
        self.assertEqual(self.rule.evaluate(event, []), [])

    def test_alert_lists_categories_and_reason(self):
        alert = self.rule.evaluate(
            ev(0, outcome=Outcome.DENIED, role="Billing",
               categories=(RecordCategory.PSYCH, RecordCategory.CLINICAL),
               reason="role Billing may not read 'psych' records"),
            [],
        )[0]
        self.assertIn("psych", alert.title)
        self.assertIn("clinical", alert.title)
        self.assertIn("Billing may not read", alert.detail)

    def test_role_is_included_in_the_title(self):
        alert = self.rule.evaluate(
            ev(0, outcome=Outcome.DENIED, role="Nurse"), []
        )[0]
        self.assertIn("Nurse", alert.title)


# ---------------------------------------------------------------------------
class TestAlertBoard(unittest.TestCase):
    def _alert(self, rule_id="EHR-002", user="dr.x", severity=Severity.HIGH,
               title="t"):
        return Alert(rule_id=rule_id, rule_name=rule_id, severity=severity,
                     user_id=user, title=title, detail="d")

    def test_first_submission_is_fresh(self):
        board = AlertBoard()
        self.assertEqual(len(board.submit([self._alert()])), 1)

    def test_duplicates_within_cooldown_collapse(self):
        board = AlertBoard()
        board.submit([self._alert()])
        self.assertEqual(board.submit([self._alert()]), [])
        self.assertEqual(len(board.open_alerts), 1)
        self.assertEqual(board.open_alerts[0].occurrences, 2)

    def test_collapse_updates_title_and_severity(self):
        board = AlertBoard()
        board.submit([self._alert(title="3 failed", severity=Severity.MEDIUM)])
        board.submit([self._alert(title="5 failed", severity=Severity.HIGH)])
        alert = board.open_alerts[0]
        self.assertEqual(alert.title, "5 failed")
        self.assertEqual(alert.severity, Severity.HIGH)

    def test_different_users_do_not_collapse(self):
        board = AlertBoard()
        board.submit([self._alert(user="a")])
        board.submit([self._alert(user="b")])
        self.assertEqual(len(board.open_alerts), 2)

    def test_different_rules_do_not_collapse(self):
        board = AlertBoard()
        board.submit([self._alert(rule_id="EHR-001")])
        board.submit([self._alert(rule_id="EHR-002")])
        self.assertEqual(len(board.open_alerts), 2)

    def test_sorted_by_severity(self):
        board = AlertBoard()
        board.submit([self._alert(rule_id="r1", user="a", severity=Severity.LOW)])
        board.submit([self._alert(rule_id="r2", user="b", severity=Severity.CRITICAL)])
        board.submit([self._alert(rule_id="r3", user="c", severity=Severity.MEDIUM)])
        self.assertEqual(
            [a.severity for a in board.open_alerts],
            [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW],
        )

    def test_acknowledge_moves_to_history(self):
        board = AlertBoard()
        fresh = board.submit([self._alert()])
        self.assertTrue(board.acknowledge(fresh[0].alert_id))
        self.assertEqual(board.open_alerts, [])
        self.assertEqual(len(board.acknowledged_alerts), 1)

    def test_acknowledge_unknown_id_returns_false(self):
        self.assertFalse(AlertBoard().acknowledge("nope"))

    def test_acknowledge_all(self):
        board = AlertBoard()
        board.submit([self._alert(rule_id="r1", user="a")])
        board.submit([self._alert(rule_id="r2", user="b")])
        self.assertEqual(board.acknowledge_all(), 2)
        self.assertEqual(board.open_alerts, [])

    def test_ack_all_then_new_alert_is_fresh_again(self):
        board = AlertBoard()
        board.submit([self._alert()])
        board.acknowledge_all()
        self.assertEqual(len(board.submit([self._alert()])), 1)

    def test_cooldown_is_configurable(self):
        board = AlertBoard(cooldown=timedelta(seconds=0))
        board.submit([self._alert()])
        self.assertEqual(len(board.submit([self._alert()])), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
