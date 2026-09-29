"""Core domain model: staff, roles, permissions and data-scope rules.

This module is deliberately dependency-free so it can be unit tested without
spinning up a web server or touching the filesystem.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import FrozenSet


# ---------------------------------------------------------------------------
# Record categories
# ---------------------------------------------------------------------------
# Every patient record is tagged with one or more categories. Categories are
# the *granular* half of the access-control model: a role may be allowed to
# "read" in general, but still be forbidden from reading PSYCH notes.
class RecordCategory(str, enum.Enum):
    DEMOGRAPHIC = "demographic"   # name, DOB, address, insurance
    CLINICAL = "clinical"         # notes, diagnoses, care plans
    LAB = "lab"                   # lab results, imaging reports
    BILLING = "billing"           # codes, charges, claims, remittances
    PSYCH = "psych"               # psychiatric / substance-abuse notes
    PEDIATRIC = "pediatric"       # minor-patient records


class Action(str, enum.Enum):
    LOGIN = "login"
    VIEW = "view"
    WRITE = "write"
    PRESCRIBE = "prescribe"
    EXPORT = "export"


class Outcome(str, enum.Enum):
    SUCCESS = "success"
    DENIED = "denied"       # blocked by the access-control layer
    FAILED = "failed"       # e.g. bad password -> not a policy denial


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------
class Role(str, enum.Enum):
    DOCTOR = "Doctor"
    NURSE = "Nurse"
    BILLING = "Billing"
    ADMIN = "Admin"         # IT/admin staff: broad read, no clinical write


#: Actions each role is permitted to perform at all.
ROLE_ACTIONS: dict[Role, FrozenSet[Action]] = {
    Role.DOCTOR:  frozenset({Action.LOGIN, Action.VIEW, Action.WRITE, Action.PRESCRIBE}),
    Role.NURSE:   frozenset({Action.LOGIN, Action.VIEW, Action.WRITE}),
    Role.BILLING: frozenset({Action.LOGIN, Action.VIEW, Action.WRITE}),
    Role.ADMIN:   frozenset({Action.LOGIN, Action.VIEW, Action.EXPORT}),
}

#: Record categories each role may read. Anything outside this set is a
#: "role-out-of-scope" read even if the action itself is allowed.
ROLE_READ_SCOPE: dict[Role, FrozenSet[RecordCategory]] = {
    Role.DOCTOR:  frozenset({
        RecordCategory.DEMOGRAPHIC, RecordCategory.CLINICAL,
        RecordCategory.LAB, RecordCategory.BILLING,
        RecordCategory.PSYCH, RecordCategory.PEDIATRIC,
    }),
    Role.NURSE:   frozenset({
        RecordCategory.DEMOGRAPHIC, RecordCategory.CLINICAL, RecordCategory.LAB,
    }),
    Role.BILLING: frozenset({
        RecordCategory.DEMOGRAPHIC, RecordCategory.BILLING,
    }),
    # Admins get metadata/operational visibility but deliberately NOT clinical
    # content -- a realistic least-privilege posture.
    Role.ADMIN:   frozenset({RecordCategory.DEMOGRAPHIC, RecordCategory.BILLING}),
}

#: Record categories each role may modify.
ROLE_WRITE_SCOPE: dict[Role, FrozenSet[RecordCategory]] = {
    Role.DOCTOR:  frozenset({
        RecordCategory.CLINICAL, RecordCategory.LAB, RecordCategory.PSYCH,
    }),
    Role.NURSE:   frozenset({RecordCategory.CLINICAL, RecordCategory.LAB}),
    Role.BILLING: frozenset({RecordCategory.BILLING}),
    Role.ADMIN:   frozenset(),
}

#: Roles that legitimately perform high-volume *single-record* chart review
#: during normal ward rounds. Used by the busy-clinician heuristic.
CLINICAL_ROLES: FrozenSet[Role] = frozenset({Role.DOCTOR, Role.NURSE})


# ---------------------------------------------------------------------------
# Staff
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Staff:
    """An individual member of staff.

    Attributes:
        user_id:   stable login identifier.
        name:      display name (UI only).
        role:      which Role this person holds.
        departments: wards/departments they are *assigned* to. Reading a record
            whose department is outside this set is a scope violation for
            floor staff (nurses), but not for doctors who cover the hospital.
    """

    user_id: str
    name: str
    role: Role
    departments: FrozenSet[str] = field(default_factory=frozenset)
    active: bool = True

    def may_perform(self, action: Action) -> bool:
        """Is this action permitted for the role, ignoring the target record?"""
        return action in ROLE_ACTIONS[self.role]

    def may_read(self, category: RecordCategory) -> bool:
        return category in ROLE_READ_SCOPE[self.role]

    def may_write(self, category: RecordCategory) -> bool:
        return category in ROLE_WRITE_SCOPE[self.role]

    def covers_department(self, department: "str | frozenset[str] | set[str]") -> bool:
        """Is the staff member assigned to every given ward?

        Doctors and admins float -- they cover the hospital, so they always
        return True. Floor staff are pinned to their assigned wards.

        Accepts a single name or a collection, because one access attempt can
        span several charts in several wards. Every department must be covered;
        covering 2 of 3 is still a violation.
        """
        if self.role in (Role.ADMIN, Role.DOCTOR):
            return True
        if isinstance(department, str):
            wanted = {department}
        else:
            wanted = set(department)
        return wanted <= set(self.departments)


# ---------------------------------------------------------------------------
# Authorization decision
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Decision:
    """Result of an authorization check."""

    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:  # lets callers write `if decision:`
        return self.allowed


def check_access(
    staff: Staff,
    action: Action,
    categories: set[RecordCategory],
    department: "str | frozenset[str] | set[str]",
) -> Decision:
    """Decide whether `staff` may perform `action` on a record.

    Checks run cheapest-and-broadest first so the returned `reason` names the
    most fundamental thing that went wrong:

    1. staff account active?
    2. role permits the action at all?            -> role/action violation
    3. role's data scope covers every category?    -> role/category violation
    4. staff assigned to every target ward?       -> department violation

    Args:
        staff:      the acting user.
        action:     what they are trying to do.
        categories: categories of the target record (empty for LOGIN).
        department: owning ward(s) of the target record(s).

    Returns:
        A Decision; `Decision.allowed` is False when access must be refused.
    """
    if not staff.active:
        return Decision(False, "account is deactivated")

    if not staff.may_perform(action):
        return Decision(
            False,
            f"role {staff.role.value} may not perform '{action.value}'",
        )

    if action is Action.LOGIN:
        return Decision(True)

    is_write = action in (Action.WRITE, Action.PRESCRIBE)
    scope = ROLE_WRITE_SCOPE[staff.role] if is_write else ROLE_READ_SCOPE[staff.role]

    for category in sorted(categories, key=lambda c: c.value):
        if category not in scope:
            verb = "write" if is_write else "read"
            return Decision(
                False,
                f"role {staff.role.value} may not {verb} "
                f"'{category.value}' records",
            )

    if not staff.covers_department(department):
        names = department if isinstance(department, str) else ", ".join(sorted(department))
        unassigned = (
            {department} if isinstance(department, str) else set(department)
        ) - set(staff.departments)
        return Decision(
            False,
            f"{staff.user_id} is not assigned to department(s) "
            f"{', '.join(sorted(unassigned))}",
        )

    return Decision(True)
