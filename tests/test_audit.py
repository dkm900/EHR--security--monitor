"""Tests for the audit log, especially tamper-evidence."""

import json
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ehr.audit import GENESIS_HASH, AuditLog  # noqa: E402
from ehr.models import Action, Outcome, RecordCategory  # noqa: E402


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        self.log = AuditLog()

    def _write(self, n=3, **kw):
        out = []
        for i in range(n):
            out.append(self.log.record(
                user_id="dr.x", role="Doctor", action=Action.VIEW,
                outcome=Outcome.SUCCESS, record_ids=[f"MRN-{i}"], **kw,
            ))
        return out

    def test_empty_log_verifies(self):
        self.assertEqual(self.log.verify_chain(), (True, None))
        self.assertEqual(len(self.log), 0)

    def test_records_are_chained(self):
        a, b, c = self._write(3)
        self.assertEqual(a.prev_hash, GENESIS_HASH)
        self.assertEqual(b.prev_hash, a.entry_hash)
        self.assertEqual(c.prev_hash, b.entry_hash)
        self.assertEqual(self.log.last_hash, c.entry_hash)

    def test_chain_verifies_after_writes(self):
        self._write(10)
        self.assertEqual(self.log.verify_chain(), (True, None))

    def test_recent_is_newest_first(self):
        self._write(3)
        recent = self.log.recent(limit=3)
        self.assertEqual(recent[0].record_ids[0], "MRN-2")
        self.assertEqual(recent[-1].record_ids[0], "MRN-0")

    def test_recent_respects_limit(self):
        self._write(10)
        self.assertEqual(len(self.log.recent(limit=4)), 4)

    def test_for_user_filters(self):
        self.log.record(user_id="a", role="Doctor", action=Action.VIEW,
                        outcome=Outcome.SUCCESS)
        self.log.record(user_id="b", role="Nurse", action=Action.VIEW,
                        outcome=Outcome.SUCCESS)
        self.assertEqual(len(self.log.for_user("a")), 1)
        self.assertEqual(len(self.log.for_user("zzz")), 0)

    def test_since_filters_by_time(self):
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.log.record(user_id="a", role="Doctor", action=Action.VIEW,
                        outcome=Outcome.SUCCESS, timestamp=t0)
        self.log.record(user_id="a", role="Doctor", action=Action.VIEW,
                        outcome=Outcome.SUCCESS,
                        timestamp=t0 + timedelta(hours=1))
        self.assertEqual(len(self.log.since(t0 + timedelta(minutes=30))), 1)

    def test_batch_size_defaults_to_record_count(self):
        e = self.log.record(user_id="a", role="Doctor", action=Action.VIEW,
                            outcome=Outcome.SUCCESS,
                            record_ids=["a", "b", "c"])
        self.assertEqual(e.batch_size, 3)

    def test_explicit_batch_size_is_kept(self):
        e = self.log.record(user_id="a", role="Doctor", action=Action.EXPORT,
                            outcome=Outcome.SUCCESS, batch_size=5000)
        self.assertEqual(e.batch_size, 5000)

    def test_tampering_with_a_record_is_detected(self):
        self._write(5)
        # Simulate someone editing history in place.
        self.log._events[2] = replace(
            self.log._events[2], record_ids=("MRN-evil",)
        )
        ok, bad_id = self.log.verify_chain()
        self.assertFalse(ok)
        self.assertIsNotNone(bad_id)

    def test_deleting_a_record_is_detected(self):
        self._write(5)
        del self.log._events[2]
        ok, bad_id = self.log.verify_chain()
        self.assertFalse(ok)
        self.assertIsNotNone(bad_id)

    def test_outcome_tally(self):
        self.log.record(user_id="a", role="Doctor", action=Action.LOGIN,
                        outcome=Outcome.FAILED)
        self.log.record(user_id="a", role="Doctor", action=Action.VIEW,
                        outcome=Outcome.SUCCESS)
        tally = self.log.counts_by_outcome()
        self.assertEqual(tally["failed"], 1)
        self.assertEqual(tally["success"], 1)
        self.assertEqual(tally["denied"], 0)

    def test_memory_cap_drops_oldest(self):
        log = AuditLog(max_memory=5)
        for i in range(20):
            log.record(user_id="a", role="Doctor", action=Action.VIEW,
                       outcome=Outcome.SUCCESS, record_ids=[str(i)])
        self.assertEqual(len(log), 5)
        self.assertEqual(log.recent(limit=1)[0].record_ids[0], "19")

    def test_to_dict_is_json_serialisable(self):
        e = self.log.record(
            user_id="a", role="Billing", action=Action.VIEW,
            outcome=Outcome.DENIED, reason="nope",
            record_ids=["x"], categories=[RecordCategory.BILLING],
            department=("Cardiology",),
        )
        blob = json.dumps(e.to_dict())
        self.assertIn("billing", blob)
        self.assertEqual(e.department_label, "Cardiology")

    def test_writes_jsonl_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "audit.jsonl"
            log = AuditLog(path=path)
            log.record(user_id="a", role="Doctor", action=Action.VIEW,
                       outcome=Outcome.SUCCESS, record_ids=["r1"])
            self.assertTrue(path.exists())
            lines = path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["record_ids"], ["r1"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
