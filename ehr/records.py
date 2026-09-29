"""In-memory patient record store.

Stands in for a real EHR database. Exists so the security layer and the web
portal have something concrete to read, authorise and display.

All data here is synthetic.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Iterable, Optional, Sequence

from .models import ROLE_READ_SCOPE, RecordCategory, Role, Staff

DEPARTMENTS = ("Cardiology", "Oncology", "Pediatrics", "Psychiatry", "Emergency")


@dataclass(frozen=True)
class PatientRecord:
    """A single chart."""

    record_id: str
    patient_name: str
    date_of_birth: date
    department: str
    categories: frozenset[RecordCategory]
    attending: str
    summary: str = ""
    vitals: dict[str, str] = field(default_factory=dict)

    @property
    def age(self) -> int:
        today = date.today()
        dob = self.date_of_birth
        return (
            today.year
            - dob.year
            - ((today.month, today.day) < (dob.month, dob.day))
        )

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "patient_name": self.patient_name,
            "date_of_birth": self.date_of_birth.isoformat(),
            "age": self.age,
            "department": self.department,
            "categories": sorted(c.value for c in self.categories),
            "attending": self.attending,
            "summary": self.summary,
            "vitals": dict(self.vitals),
        }


_FIRST = (
    "Amara Osei", "Bruno Kovac", "Chen Wei", "Dalia Haddad", "Elias Moreau",
    "Fatima Zahra", "Gustav Lindqvist", "Hana Sato", "Idris Bello", "Jana Novak",
    "Kwame Mensah", "Lucia Ferreira", "Mateo Rojas", "Nadia Petrov", "Omar Farouk",
    "Priya Raman", "Quentin Dubois", "Rosa Delgado", "Sanjay Iyer", "Tomas Novak",
)
_LAST_DIAG = (
    "atrial fibrillation", "type 2 diabetes", "community-acquired pneumonia",
    "major depressive disorder", "fractured tibia", "hypertensive urgency",
    "pancreatitis", "iron-deficiency anaemia", "cellulitis", "asthma exacerbation",
)


class RecordStore:
    """Deterministic-ish generator + lookup for patient charts."""

    def __init__(self, seed: int = 7, count: int = 400):
        self._rng = random.Random(seed)
        self._records: dict[str, PatientRecord] = {}
        self._build(count)

    def _build(self, count: int) -> None:
        rng = self._rng
        for i in range(1, count + 1):
            department = DEPARTMENTS[(i - 1) % len(DEPARTMENTS)]
            categories = {RecordCategory.DEMOGRAPHIC, RecordCategory.CLINICAL}
            categories.add(rng.choice([RecordCategory.LAB, RecordCategory.BILLING]))
            if department == "Psychiatry":
                categories.add(RecordCategory.PSYCH)
            if department == "Pediatrics":
                categories.add(RecordCategory.PEDIATRIC)
            dob = date.today() - timedelta(days=rng.randint(1, 80) * 365)
            self._records[f"MRN-{1000 + i}"] = PatientRecord(
                record_id=f"MRN-{1000 + i}",
                patient_name=f"{rng.choice(_FIRST)}",
                date_of_birth=dob,
                department=department,
                categories=frozenset(categories),
                attending=f"dr_{(i % 7) + 1}",
                summary=f"Presentation: {rng.choice(_LAST_DIAG)}. Plan under review.",
                vitals={
                    "hr": str(rng.randint(55, 110)),
                    "bp": f"{rng.randint(105, 145)}/{rng.randint(65, 95)}",
                    "spo2": f"{rng.randint(90, 99)}%",
                },
            )

    # -- reads ----------------------------------------------------------
    def __len__(self) -> int:
        return len(self._records)

    def all(self) -> list[PatientRecord]:
        return list(self._records.values())

    def get(self, record_id: str) -> Optional[PatientRecord]:
        return self._records.get(record_id)

    def many(self, record_ids: Iterable[str]) -> list[PatientRecord]:
        return [self._records[r] for r in record_ids if r in self._records]

    def search(
        self,
        *,
        query: str = "",
        department: str = "",
        category: str = "",
        limit: int = 200,
    ) -> list[PatientRecord]:
        """Filter the catalogue. Used by the portal's record browser."""
        out = []
        for rec in self._records.values():
            if query and query.lower() not in rec.patient_name.lower():
                continue
            if department and rec.department != department:
                continue
            if category and category not in {c.value for c in rec.categories}:
                continue
            out.append(rec)
            if len(out) >= limit:
                break
        return out

    def sample_ids(self, n: int) -> list[str]:
        """First `n` record IDs -- handy for demos and bulk-read scenarios."""
        return list(self._records)[:n]

    def ids_for_role(self, role: Role, n: int) -> list[str]:
        """Record IDs containing at least one section this role may read.

        Used to build honest demo scenarios: a Billing clerk harvesting 60
        charts is opening their *billing* sections, which is in scope but
        still a bulk read.
        """
        allowed = ROLE_READ_SCOPE[role]
        return [
            r.record_id
            for r in self._records.values()
            if r.categories & allowed
        ][:n]

    def ids_readable_by(self, staff: Staff, n: int) -> list[str]:
        """Record IDs this *specific* person may open whole, with no denial.

        Applies both halves of the access model -- the role's data scope and
        the person's ward assignment. This is what "normal work" looks like
        for one individual, so scenarios built on it produce no EHR-003 noise.
        """
        return [
            r.record_id
            for r in self._records.values()
            if r.categories <= ROLE_READ_SCOPE[staff.role]
            and staff.covers_department(r.department)
        ][:n]

    def ids_with_section(self, category: RecordCategory, n: int) -> list[str]:
        """Record IDs that actually contain `category`."""
        return [
            r.record_id for r in self._records.values() if category in r.categories
        ][:n]


# ---------------------------------------------------------------------------
# Seed staff directory
# ---------------------------------------------------------------------------
def seed_staff() -> dict[str, Staff]:
    """The demo user directory shown in the portal's role switcher."""
    return {
        "dr.okafor": Staff(
            user_id="dr.okafor",
            name="Dr. Adaeze Okafor",
            role=Role.DOCTOR,
            departments=frozenset({"Cardiology", "Emergency"}),
        ),
        "dr.ivanov": Staff(
            user_id="dr.ivanov",
            name="Dr. Pavel Ivanov",
            role=Role.DOCTOR,
            departments=frozenset({"Oncology"}),
        ),
        "nurse.diaz": Staff(
            user_id="nurse.diaz",
            name="Nurse Maria Diaz",
            role=Role.NURSE,
            departments=frozenset({"Cardiology", "Emergency"}),
        ),
        "nurse.chen": Staff(
            user_id="nurse.chen",
            name="Nurse Chen Wei",
            role=Role.NURSE,
            departments=frozenset({"Pediatrics"}),
        ),
        "clerk.bianchi": Staff(
            user_id="clerk.bianchi",
            name="Giulia Bianchi",
            role=Role.BILLING,
            departments=frozenset({"Cardiology", "Oncology", "Pediatrics",
                                  "Psychiatry", "Emergency"}),
        ),
        "it.admin": Staff(
            user_id="it.admin",
            name="Sam Rivera (IT)",
            role=Role.ADMIN,
            departments=frozenset(DEPARTMENTS),
        ),
        "dr.terminated": Staff(
            user_id="dr.terminated",
            name="Dr. Former Employee",
            role=Role.DOCTOR,
            active=False,
        ),
    }
