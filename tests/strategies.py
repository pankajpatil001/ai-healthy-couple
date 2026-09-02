"""Domain Hypothesis strategies for the Foundation slice.

STUB (task 1.3). This module provides reusable Hypothesis strategies that
generate arbitrary-but-valid domain values — users, couples, memberships, and
lifecycle states — for the property-based tests introduced in later tasks
(each of the 22 correctness properties is validated by a single property test).

The lifecycle-state strategies mirror the Foundation-constrained enum value sets
from the design (design.md "Enumerations"):

    Account_Status    : ACTIVE | SUSPENDED | DELETED
    Couple_Status     : PENDING | ACTIVE | DISCONNECTED
    Member_Role       : PARTNER_A | PARTNER_B
    Member_Status     : ACTIVE | DISCONNECTED
    Invitation_Status : PENDING | ACCEPTED | DECLINED | EXPIRED | REVOKED
    Visibility_Scope  : PRIVATE_PARTNER | SHARED_COUPLE | PROFESSIONAL_SHARED | SYSTEM_ONLY

These are string-based today so the harness is exercisable before the enum
types land in task 2.1. Once the real enums exist, swap the sampled values for
``st.sampled_from(list(TheEnum))`` and enrich the entity strategies to build ORM
instances / DTOs. Generators should stay "smart": constrain to the valid input
space and deliberately include edge cases (self, non-member, former partner,
suspended/deleted actors) as the design's PBT configuration requires.
"""

from __future__ import annotations

import uuid

from hypothesis import strategies as st

# --- Foundation enum value sets (string stand-ins until task 2.1) -------------

ACCOUNT_STATUSES = ["ACTIVE", "SUSPENDED", "DELETED"]
COUPLE_STATUSES = ["PENDING", "ACTIVE", "DISCONNECTED"]
MEMBER_ROLES = ["PARTNER_A", "PARTNER_B"]
MEMBER_STATUSES = ["ACTIVE", "DISCONNECTED"]
INVITATION_STATUSES = ["PENDING", "ACCEPTED", "DECLINED", "EXPIRED", "REVOKED"]
VISIBILITY_SCOPES = [
    "PRIVATE_PARTNER",
    "SHARED_COUPLE",
    "PROFESSIONAL_SHARED",
    "SYSTEM_ONLY",
]


# --- Lifecycle-state strategies -----------------------------------------------

def account_statuses() -> st.SearchStrategy[str]:
    """Any Foundation Account_Status value."""
    return st.sampled_from(ACCOUNT_STATUSES)


def couple_statuses() -> st.SearchStrategy[str]:
    """Any Foundation Couple_Status value."""
    return st.sampled_from(COUPLE_STATUSES)


def member_roles() -> st.SearchStrategy[str]:
    """Any Member_Role value."""
    return st.sampled_from(MEMBER_ROLES)


def member_statuses() -> st.SearchStrategy[str]:
    """Any Foundation Member_Status value."""
    return st.sampled_from(MEMBER_STATUSES)


def invitation_statuses() -> st.SearchStrategy[str]:
    """Any Invitation_Status value."""
    return st.sampled_from(INVITATION_STATUSES)


def visibility_scopes() -> st.SearchStrategy[str]:
    """Any Visibility_Scope value."""
    return st.sampled_from(VISIBILITY_SCOPES)


# --- Identifier / primitive strategies ----------------------------------------

def uuids() -> st.SearchStrategy[uuid.UUID]:
    """Random UUIDs, suitable as untrusted client-supplied identifiers."""
    return st.uuids(version=4)


def auth_identifiers() -> st.SearchStrategy[str]:
    """Plausible authentication identifiers (email-shaped stand-in)."""
    local = st.text(
        alphabet=st.characters(min_codepoint=97, max_codepoint=122),
        min_size=1,
        max_size=16,
    )
    return st.builds(lambda name: f"{name}@example.test", local)


# --- Entity strategies (stubs) ------------------------------------------------
#
# These return plain dicts today so tests can be written against a stable shape
# before ORM models exist. Task 2.x should evolve them to build real domain
# objects while keeping the same generated-field contract.

def users() -> st.SearchStrategy[dict]:
    """A user record: id, auth_identifier, and a lifecycle status."""
    return st.fixed_dictionaries(
        {
            "id": uuids(),
            "auth_identifier": auth_identifiers(),
            "status": account_statuses(),
        }
    )


def couples() -> st.SearchStrategy[dict]:
    """A couple record: id and a lifecycle status."""
    return st.fixed_dictionaries({"id": uuids(), "status": couple_statuses()})


def memberships() -> st.SearchStrategy[dict]:
    """A couple-membership record linking a user to a couple with role/status."""
    return st.fixed_dictionaries(
        {
            "couple_id": uuids(),
            "user_id": uuids(),
            "role": member_roles(),
            "status": member_statuses(),
        }
    )


__all__ = [
    "ACCOUNT_STATUSES",
    "COUPLE_STATUSES",
    "MEMBER_ROLES",
    "MEMBER_STATUSES",
    "INVITATION_STATUSES",
    "VISIBILITY_SCOPES",
    "account_statuses",
    "couple_statuses",
    "member_roles",
    "member_statuses",
    "invitation_statuses",
    "visibility_scopes",
    "uuids",
    "auth_identifiers",
    "users",
    "couples",
    "memberships",
]
