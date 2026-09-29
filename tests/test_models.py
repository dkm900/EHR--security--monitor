"""Tests for the access-control model: roles, permissions, data scope.

Run:  python -m unittest discover -s tests -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ehr.models import (  # noqa: E402
    Action,
    Outcome,
    RecordCategory,
    Role,
    Staff,
    check_access,
)


def doctor(**kw) -> Staff:
    base = dict(user_id="dr.x", name="Dr X", role=Role.DOCTOR,
                departments=frozenset({"Cardiology"}))
    return Staff(**{**base, **kw})


def nurse(**kw) -> Staff:
    base = dict(user_id="nurse.x", name="Nurse X", role=Role.NURSE,
                departments=frozenset({"Cardiology"}))
    return Staff(**{**base, **kw})


def clerk(**kw) -> Staff:
    base = dict(user_id="clerk.x", name="Clerk X", role=Role.BILLING,
                departments=frozenset({"Cardiology", "Oncology"}))
    return Staff(**{**base, **kw})


class TestRolePermissions(unittest.TestCase):
    def test_doctor_may_prescribe(self):
        self.assertTrue(doctor().may_perform(Action.PRESCRIBE))

    def test_nurse_may_not_prescribe(self):
        self.assertFalse(nurse().may_perform(Action.PRESCRIBE))

    def test_billing_may_not_export(self):
        self.assertFalse(clerk().may_perform(Action.EXPORT))

    def test_admin_may_export_but_not_write(self):
        admin = Staff(user_id="it", name="IT", role=Role.ADMIN)
        self.assertTrue(admin.may_perform(Action.EXPORT))
        self.assertFalse(admin.may_perform(Action.WRITE))

    def test_every_role_can_log_in(self):
        for role in Role:
            staff = Staff(user_id="u", name="U", role=role)
            self.assertTrue(staff.may_perform(Action.LOGIN))


class TestDataScope(unittest.TestCase):
    def test_doctor_reads_every_category(self):
        d = doctor()
        for cat in RecordCategory:
            self.assertTrue(d.may_read(cat), f"doctor should read {cat}")

    def test_nurse_cannot_read_billing(self):
        self.assertFalse(nurse().may_read(RecordCategory.BILLING))

    def test_billing_cannot_read_clinical_or_psych(self):
        c = clerk()
        self.assertFalse(c.may_read(RecordCategory.CLINICAL))
        self.assertFalse(c.may_read(RecordCategory.PSYCH))
        self.assertTrue(c.may_read(RecordCategory.BILLING))
        self.assertTrue(c.may_read(RecordCategory.DEMOGRAPHIC))

    def test_admin_has_no_write_scope(self):
        admin = Staff(user_id="it", name="IT", role=Role.ADMIN)
        self.assertFalse(admin.may_write(RecordCategory.CLINICAL))


class TestCheckAccess(unittest.TestCase):
    def test_in_scope_read_allowed(self):
        d = check_access(
            nurse(),
            Action.VIEW,
            {RecordCategory.CLINICAL, RecordCategory.LAB},
            "Cardiology",
        )
        self.assertTrue(d)
        self.assertEqual(d.reason, "")

    def test_billing_reading_clinical_is_denied(self):
        d = check_access(
            clerk(), Action.VIEW, {RecordCategory.CLINICAL}, "Cardiology"
        )
        self.assertFalse(d)
        self.assertIn("may not read", d.reason)
        self.assertIn("clinical", d.reason)

    def test_billing_reading_billing_section_is_allowed(self):
        d = check_access(
            clerk(), Action.VIEW, {RecordCategory.BILLING}, "Oncology"
        )
        self.assertTrue(d)

    def test_nurse_prescribing_is_denied(self):
        d = check_access(
            nurse(), Action.PRESCRIBE, {RecordCategory.CLINICAL}, "Cardiology"
        )
        self.assertFalse(d)
        self.assertIn("may not perform", d.reason)

    def test_nurse_in_wrong_ward_is_denied(self):
        d = check_access(
            nurse(), Action.VIEW, {RecordCategory.CLINICAL}, "Psychiatry"
        )
        self.assertFalse(d)
        self.assertIn("not assigned", d.reason)

    def test_doctor_covers_whole_hospital(self):
        d = check_access(
            doctor(), Action.VIEW, {RecordCategory.CLINICAL}, "Psychiatry"
        )
        self.assertTrue(d)

    def test_multi_ward_request_needs_all_wards(self):
        ok = check_access(
            nurse(), Action.VIEW, {RecordCategory.CLINICAL},
            frozenset({"Cardiology", "Oncology"}),
        )
        self.assertFalse(ok, "nurse is only assigned to Cardiology")
        self.assertIn("Oncology", ok.reason)

        ok2 = check_access(
            nurse(), Action.VIEW, {RecordCategory.CLINICAL},
            frozenset({"Cardiology"}),
        )
        self.assertTrue(ok2)

    def test_deactivated_account_denied_first(self):
        d = check_access(
            Staff(user_id="gone", name="Gone", role=Role.DOCTOR, active=False),
            Action.VIEW, {RecordCategory.CLINICAL}, "Cardiology",
        )
        self.assertFalse(d)
        self.assertIn("deactivated", d.reason)

    def test_login_bypasses_record_checks(self):
        d = check_access(nurse(), Action.LOGIN, set(), "")
        self.assertTrue(d)

    def test_decision_is_truthy(self):
        """A Decision reads as its boolean, so callers can write `if check(...)`."""
        self.assertTrue(check_access(
            nurse(), Action.VIEW, {RecordCategory.CLINICAL}, "Cardiology"
        ))
        self.assertFalse(check_access(
            nurse(), Action.VIEW, {RecordCategory.BILLING}, "Cardiology"
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)
