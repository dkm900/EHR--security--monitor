"""End-to-end tests through the monitor, and the scenario suite.

These are the tests that prove the whole pipeline works together: authorise ->
audit -> heuristic -> detect -> board.
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ehr import EHRMonitor, RecordCategory, Role  # noqa: E402
from ehr.models import Action, Outcome  # noqa: E402
from ehr.scenarios import SCENARIOS, catalogue  # noqa: E402

T0 = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)


class MonitorTestCase(unittest.TestCase):
    def setUp(self):
        self.m = EHRMonitor()

    def rule_ids(self):
        return [a.rule_id for a in self.m.board.open_alerts]


class TestRule1FailedLogins(MonitorTestCase):
    def test_two_failures_silent_third_alerts(self):
        r1 = self.m.attempt_login("dr.ivanov", password="x", timestamp=T0)
        r2 = self.m.attempt_login("dr.ivanov", password="x",
                                 timestamp=T0 + timedelta(seconds=10))
        r3 = self.m.attempt_login("dr.ivanov", password="x",
                                 timestamp=T0 + timedelta(seconds=20))
        self.assertEqual(r1.alerts, [])
        self.assertEqual(r2.alerts, [])
        self.assertEqual(len(r3.alerts), 1)
        self.assertEqual(r3.alerts[0].rule_id, "EHR-001")

    def test_failures_are_audited(self):
        self.m.attempt_login("dr.ivanov", password="x", timestamp=T0)
        last = self.m.audit.recent(limit=1)[0]
        self.assertEqual(last.action, Action.LOGIN)
        self.assertEqual(last.outcome, Outcome.FAILED)
        self.assertEqual(last.source_ip, "127.0.0.1")

    def test_unknown_user_login_fails_and_is_audited(self):
        res = self.m.attempt_login("ghost", password="x", timestamp=T0)
        self.assertFalse(res.allowed)
        self.assertEqual(res.event.outcome, Outcome.FAILED)
        self.assertEqual(res.event.role, "Unknown")

    def test_correct_password_succeeds(self):
        res = self.m.attempt_login("dr.ivanov", password="correct-horse",
                                   timestamp=T0)
        self.assertTrue(res.allowed)
        self.assertEqual(res.event.outcome, Outcome.SUCCESS)

    def test_failures_outside_the_window_do_not_accumulate(self):
        for i in range(3):
            self.m.attempt_login("dr.ivanov", password="x",
                                 timestamp=T0 + timedelta(hours=i * 2))
        self.assertEqual(self.rule_ids(), [])

    def test_two_users_failing_do_not_trip_each_other(self):
        self.m.attempt_login("dr.ivanov", password="x", timestamp=T0)
        self.m.attempt_login("nurse.diaz", password="x",
                             timestamp=T0 + timedelta(seconds=5))
        self.assertEqual(self.rule_ids(), [])


class TestRule2BulkRead(MonitorTestCase):
    def test_billing_clerk_bulk_read_alerts(self):
        ids = self.m.records.ids_with_section(RecordCategory.BILLING, 60)
        res = self.m.access_records("clerk.bianchi", ids,
                                    sections=[RecordCategory.BILLING],
                                    timestamp=T0)
        self.assertTrue(res.allowed, "reading billing sections is in scope")
        self.assertIn("EHR-002", [a.rule_id for a in res.alerts])

    def test_small_read_is_silent(self):
        ids = self.m.records.ids_for_role(Role.DOCTOR, 10)
        res = self.m.access_records("dr.okafor", ids, timestamp=T0)
        self.assertTrue(res.allowed)
        self.assertEqual(res.alerts, [])

    def test_bulk_reads_outside_the_window_do_not_count(self):
        ids = self.m.records.ids_with_section(RecordCategory.BILLING, 40)
        for i, rid in enumerate(ids):
            self.m.access_records("clerk.bianchi", [rid],
                                  sections=[RecordCategory.BILLING],
                                  timestamp=T0 + timedelta(hours=i * 2))
        self.assertNotIn("EHR-002", self.rule_ids())

    def test_denied_reads_do_not_count_toward_bulk(self):
        """Out-of-scope reads hit rule 3, not rule 2."""
        ids = self.m.records.ids_with_section(RecordCategory.PSYCH, 60)
        for i, rid in enumerate(ids):
            self.m.access_records("clerk.bianchi", [rid],
                                  sections=[RecordCategory.PSYCH],
                                  timestamp=T0 + timedelta(seconds=i))
        self.assertNotIn("EHR-002", self.rule_ids())
        self.assertIn("EHR-003", self.rule_ids())


class TestRule3RoleScope(MonitorTestCase):
    def test_billing_reading_psych_is_denied_and_alerts(self):
        ids = self.m.records.ids_with_section(RecordCategory.PSYCH, 2)
        res = self.m.access_records("clerk.bianchi", ids,
                                    sections=[RecordCategory.PSYCH],
                                    timestamp=T0)
        self.assertFalse(res.allowed)
        self.assertEqual(res.event.outcome, Outcome.DENIED)
        self.assertIn("psych", res.event.reason)
        self.assertIn("EHR-003", [a.rule_id for a in res.alerts])

    def test_nurse_in_wrong_ward_is_denied(self):
        wards = [r.record_id for r in self.m.records.all()
                 if r.department == "Psychiatry"][:1]
        res = self.m.access_records("nurse.diaz", wards,
                                    sections=[RecordCategory.CLINICAL],
                                    timestamp=T0)
        self.assertFalse(res.allowed)
        self.assertIn("not assigned", res.event.reason)

    def test_nurse_prescribing_is_denied(self):
        ids = [r.record_id for r in self.m.records.all()
               if r.department == "Cardiology"][:1]
        res = self.m.access_records("nurse.diaz", ids,
                                    action=Action.PRESCRIBE,
                                    sections=[RecordCategory.CLINICAL],
                                    timestamp=T0)
        self.assertFalse(res.allowed)
        self.assertIn("may not perform", res.event.reason)

    def test_deactivated_account_is_denied(self):
        ids = [r.record_id for r in self.m.records.all()
               if r.department == "Cardiology"][:1]
        res = self.m.access_records("dr.terminated", ids, timestamp=T0)
        self.assertFalse(res.allowed)
        self.assertIn("deactivated", res.event.reason)

    def test_doctor_crossing_wards_is_fine(self):
        wards = [r.record_id for r in self.m.records.all()
                 if r.department == "Psychiatry"][:1]
        res = self.m.access_records("dr.ivanov", wards, timestamp=T0)
        self.assertTrue(res.allowed)
        self.assertEqual(res.alerts, [])

    def test_requesting_a_section_the_lacks_is_denied(self):
        ids = [r.record_id for r in self.m.records.all()
               if RecordCategory.PSYCH not in r.categories][:3]
        res = self.m.access_records("dr.okafor", ids,
                                    sections=[RecordCategory.PSYCH],
                                    timestamp=T0)
        self.assertFalse(res.allowed)
        self.assertIn("not present", res.event.reason)

    def test_nonexistent_record_is_denied(self):
        res = self.m.access_records("dr.okafor", ["MRN-000000"],
                                    timestamp=T0)
        self.assertFalse(res.allowed)


class TestBusyClinicianIntegration(MonitorTestCase):
    def test_doctor_rounds_produce_no_alert(self):
        ids = self.m.records.ids_for_role(Role.DOCTOR, 70)
        for i, rid in enumerate(ids):
            res = self.m.access_records("dr.okafor", [rid],
                                        timestamp=T0 + timedelta(seconds=i))
            self.assertTrue(res.allowed)
        self.assertEqual(self.rule_ids(), [],
                         "70 legitimate single-chart reads must not alert")
        stats = self.m.stats()
        self.assertEqual(stats["records_read"], 70)
        self.assertEqual(stats["records_exempt"], 70)

    def test_nurse_rounds_produce_no_alert(self):
        """Rounds by a ward nurse, opening only charts she may fully read."""
        ids = self.m.records.ids_readable_by(self.m.staff["nurse.diaz"], 70)
        self.assertGreaterEqual(len(ids), 50, "need enough in-scope charts")
        for i, rid in enumerate(ids):
            res = self.m.access_records("nurse.diaz", [rid],
                                        timestamp=T0 + timedelta(seconds=i * 1.5))
            self.assertTrue(res.allowed, f"denied on {rid}: {res.event.reason}")
        self.assertEqual(self.rule_ids(), [])

    def test_exemption_is_recorded_on_the_audit_event(self):
        rid = self.m.records.ids_for_role(Role.DOCTOR, 1)[0]
        res = self.m.access_records("dr.okafor", [rid], timestamp=T0)
        self.assertTrue(res.exempt)
        self.assertIn("clinical workflow", res.event.exempt_reason)

    def test_scripted_doctor_still_alerts(self):
        """Same account, machine pace: the safety valve must hold."""
        ids = self.m.records.ids_for_role(Role.DOCTOR, 70)
        for i, rid in enumerate(ids):
            self.m.access_records("dr.okafor", [rid],
                                  timestamp=T0 + timedelta(seconds=i * 0.05))
        self.assertIn("EHR-002", self.rule_ids())

    def test_doctor_bulk_request_alerts(self):
        """A clinical role asking for 60 charts in one request is not rounds."""
        ids = self.m.records.ids_for_role(Role.DOCTOR, 60)
        res = self.m.access_records("dr.okafor", ids, timestamp=T0)
        self.assertIn("EHR-002", [a.rule_id for a in res.alerts])

    def test_billing_clerk_never_gets_exemption(self):
        ids = self.m.records.ids_with_section(RecordCategory.BILLING, 30)
        res = self.m.access_records("clerk.bianchi", ids,
                                    sections=[RecordCategory.BILLING],
                                    timestamp=T0)
        self.assertFalse(res.exempt)


class TestAuditIntegrity(MonitorTestCase):
    def test_chain_stays_intact_through_mixed_traffic(self):
        self.m.attempt_login("dr.ivanov", password="x", timestamp=T0)
        self.m.access_records("clerk.bianchi",
                              self.m.records.ids_with_section(
                                  RecordCategory.PSYCH, 2),
                              sections=[RecordCategory.PSYCH], timestamp=T0)
        self.m.access_records("nurse.diaz",
                              self.m.records.ids_for_role(Role.NURSE, 20),
                              timestamp=T0)
        self.assertEqual(self.m.audit.verify_chain(), (True, None))

    def test_every_attempt_is_logged(self):
        """One HTTP request == one audit event, whatever its batch size."""
        before = len(self.m.audit)
        self.m.access_records("dr.okafor",
                              self.m.records.ids_for_role(Role.DOCTOR, 3),
                              timestamp=T0)
        self.assertEqual(len(self.m.audit), before + 1)
        self.assertEqual(self.m.audit.recent(limit=1)[0].batch_size, 3)

    def test_each_separate_request_is_its_own_event(self):
        before = len(self.m.audit)
        for i, rid in enumerate(
                self.m.records.ids_readable_by(self.m.staff["dr.okafor"], 3)):
            self.m.access_records("dr.okafor", [rid],
                                  timestamp=T0 + timedelta(seconds=i))
        self.assertEqual(len(self.m.audit), before + 3)

    def test_denied_attempt_is_logged_too(self):
        before = len(self.m.audit)
        self.m.access_records("clerk.bianchi",
                              self.m.records.ids_with_section(
                                  RecordCategory.PSYCH, 1),
                              sections=[RecordCategory.PSYCH], timestamp=T0)
        self.assertEqual(len(self.m.audit), before + 1)

    def test_stats_agree_with_the_log(self):
        self.m.access_records("dr.okafor",
                              self.m.records.ids_for_role(Role.DOCTOR, 5),
                              timestamp=T0)
        stats = self.m.stats()
        self.assertEqual(stats["total_events"], len(self.m.audit))
        self.assertEqual(stats["outcomes"]["success"], 1)
        self.assertEqual(stats["records_read"], 5)
        self.assertTrue(stats["chain_ok"])


class TestAlertDeduplicationEndToEnd(MonitorTestCase):
    def test_many_reads_produce_one_alert(self):
        ids = self.m.records.ids_with_section(RecordCategory.BILLING, 120)
        for i, rid in enumerate(ids):
            self.m.access_records("clerk.bianchi", [rid],
                                  sections=[RecordCategory.BILLING],
                                  timestamp=T0 + timedelta(seconds=i))
        bulk = [a for a in self.m.board.open_alerts if a.rule_id == "EHR-002"]
        self.assertEqual(len(bulk), 1, "one incident, one card")
        self.assertGreater(bulk[0].occurrences, 1)

    def test_acknowledge_moves_alert_out_of_the_open_list(self):
        ids = self.m.records.ids_with_section(RecordCategory.BILLING, 60)
        self.m.access_records("clerk.bianchi", ids,
                              sections=[RecordCategory.BILLING], timestamp=T0)
        alert = self.m.board.open_alerts[0]
        self.m.board.acknowledge(alert.alert_id)
        self.assertEqual(self.m.board.open_alerts, [])
        self.assertEqual(len(self.m.board.acknowledged_alerts), 1)

    def test_reset_clears_everything(self):
        ids = self.m.records.ids_with_section(RecordCategory.BILLING, 60)
        self.m.access_records("clerk.bianchi", ids,
                              sections=[RecordCategory.BILLING], timestamp=T0)
        self.m.reset()
        self.assertEqual(len(self.m.audit), 0)
        self.assertEqual(self.m.board.open_alerts, [])
        self.assertEqual(self.m.stats()["open_alerts"], 0)


class TestScenarios(unittest.TestCase):
    """Every scenario must produce exactly the alerts it advertises."""

    def test_all_scenarios_are_registered(self):
        self.assertEqual(len(SCENARIOS), 7)

    def test_catalogue_matches_registry(self):
        self.assertEqual({c["key"] for c in catalogue()}, set(SCENARIOS))

    def test_each_scenario_behaves_as_advertised(self):
        for key, runner in SCENARIOS.items():
            with self.subTest(scenario=key):
                monitor = EHRMonitor()
                result = runner(monitor)
                self.assertTrue(
                    result.behaved_as_expected,
                    f"{key}: expected alert={result.should_alert}, "
                    f"got {result.rule_ids_fired}",
                )
                self.assertEqual(result.to_dict()["key"], key)

    def test_quiet_scenarios_generate_no_alerts(self):
        for key in ("normal_operations", "busy_clinician"):
            with self.subTest(scenario=key):
                monitor = EHRMonitor()
                SCENARIOS[key](monitor)
                self.assertEqual(monitor.board.open_alerts, [])

    def test_noisy_scenarios_generate_alerts(self):
        for key in ("brute_force", "bulk_exfiltration",
                    "role_scope_violation", "scripted_account",
                    "terminated_account"):
            with self.subTest(scenario=key):
                monitor = EHRMonitor()
                result = SCENARIOS[key](monitor)
                self.assertTrue(result.rule_ids_fired)

    def test_busy_clinician_and_scripted_account_differ(self):
        """The headline claim: same volume, same role, opposite verdicts."""
        quiet = EHRMonitor()
        SCENARIOS["busy_clinician"](quiet)
        loud = EHRMonitor()
        SCENARIOS["scripted_account"](loud)

        self.assertEqual(quiet.board.open_alerts, [])
        self.assertTrue(loud.board.open_alerts)
        self.assertGreater(quiet.stats()["records_read"],
                           loud.stats()["records_read"] - 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
