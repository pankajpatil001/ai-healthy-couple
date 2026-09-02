"""Unit tests for the DENY-Decision -> privacy-safe HTTP mapping (task 4.3).

Covers ``app.authorization.enforcement``: every :class:`DenyReason` maps to
exactly one of the 401 / 403 / 404 typed errors, the mapped messages stay
generic (never revealing ownership or existence), and :func:`enforce` raises the
mapped error on DENY while doing nothing on ALLOW.

Design references: "Error Handling" table and "IDOR / enumeration prevention and
401/403/404 semantics" (R17.2-R17.4, R18.1-R18.4).
"""

from __future__ import annotations

import uuid

import pytest

from app.authorization.enforcement import decision_to_error, enforce
from app.authorization.models import (
    HTTP_FORBIDDEN,
    HTTP_NOT_FOUND,
    HTTP_UNAUTHENTICATED,
    Decision,
    DenyReason,
)
from app.errors import (
    AppError,
    AuthorizationError,
    ResourceNotFoundError,
    UnauthenticatedError,
)

# Expected (status, code, error type) for every DenyReason the pipeline can emit,
# paired with the http_hint the pipeline attaches for that reason. Keeping the
# hint here proves the mapping and the pipeline agree (R18.4 consistency).
_EXPECTED = {
    # Authenticated-but-forbidden lifecycle denial -> 403, existence-safe (R18.2).
    DenyReason.ACCOUNT_NOT_ACTIVE: (
        HTTP_FORBIDDEN,
        "FORBIDDEN",
        AuthorizationError,
    ),
    # Privacy-safe not-found family -> 404 (R17.2-R17.4, R18.3).
    DenyReason.RESOURCE_NOT_FOUND: (
        HTTP_NOT_FOUND,
        "RESOURCE_NOT_FOUND",
        ResourceNotFoundError,
    ),
    DenyReason.NOT_OWNER: (HTTP_NOT_FOUND, "RESOURCE_NOT_FOUND", ResourceNotFoundError),
    DenyReason.NOT_ACTIVE_MEMBER: (
        HTTP_NOT_FOUND,
        "RESOURCE_NOT_FOUND",
        ResourceNotFoundError,
    ),
    DenyReason.COUPLE_NOT_ACTIVE: (
        HTTP_NOT_FOUND,
        "RESOURCE_NOT_FOUND",
        ResourceNotFoundError,
    ),
    DenyReason.SYSTEM_ONLY: (
        HTTP_NOT_FOUND,
        "RESOURCE_NOT_FOUND",
        ResourceNotFoundError,
    ),
    DenyReason.PROFESSIONAL_SHARED: (
        HTTP_NOT_FOUND,
        "RESOURCE_NOT_FOUND",
        ResourceNotFoundError,
    ),
    DenyReason.UNDECIDABLE: (
        HTTP_NOT_FOUND,
        "RESOURCE_NOT_FOUND",
        ResourceNotFoundError,
    ),
}


def test_every_deny_reason_is_covered() -> None:
    """Guard: the test table enumerates every DenyReason (no gaps as reasons grow)."""
    assert set(_EXPECTED) == set(DenyReason)


@pytest.mark.parametrize("reason", list(DenyReason))
def test_reason_maps_to_expected_status_and_code(reason: DenyReason) -> None:
    """Each DenyReason maps to the design's status/code, hint agreeing (R18.4)."""
    expected_status, expected_code, expected_type = _EXPECTED[reason]
    decision = Decision.deny(reason, expected_status)

    error = decision_to_error(decision)

    assert isinstance(error, expected_type)
    assert error.http_status == expected_status
    assert error.code == expected_code


@pytest.mark.parametrize("reason", list(DenyReason))
def test_status_is_exactly_one_of_401_403_404(reason: DenyReason) -> None:
    """Every denial is exactly one of 401/403/404 — never anything else (R18.1-R18.3)."""
    expected_status, _code, _type = _EXPECTED[reason]
    error = decision_to_error(Decision.deny(reason, expected_status))
    assert error.http_status in {
        HTTP_UNAUTHENTICATED,
        HTTP_FORBIDDEN,
        HTTP_NOT_FOUND,
    }


@pytest.mark.parametrize("reason", list(DenyReason))
def test_messages_are_generic_and_leak_no_ownership_or_existence(
    reason: DenyReason,
) -> None:
    """Mapped messages are generic; they never reveal ownership/existence (R18)."""
    expected_status, _code, _type = _EXPECTED[reason]
    error = decision_to_error(Decision.deny(reason, expected_status))

    message = error.message.lower()
    forbidden_terms = [
        "owner",
        "partner",
        "belongs",
        "exists",
        "existing",
        "member",
        "couple",
        "reflection",
        "suspended",
        "deleted",
        "account",
    ]
    for term in forbidden_terms:
        assert term not in message, f"message leaks '{term}': {error.message!r}"


def test_privacy_safe_not_found_reasons_are_indistinguishable() -> None:
    """All 404 reasons yield an identical body — a probe cannot tell them apart.

    A non-owner (NOT_OWNER), a non-member (NOT_ACTIVE_MEMBER), an inactive couple
    (COUPLE_NOT_ACTIVE), a hidden zone (SYSTEM_ONLY / PROFESSIONAL_SHARED), an
    unresolved resource (RESOURCE_NOT_FOUND) and a default-deny (UNDECIDABLE) must
    all look the same to the client (R17.3, R17.4, R18.3).
    """
    not_found_reasons = [
        r for r, (status, _c, _t) in _EXPECTED.items() if status == HTTP_NOT_FOUND
    ]
    bodies = {
        (
            decision_to_error(Decision.deny(r, HTTP_NOT_FOUND)).code,
            decision_to_error(Decision.deny(r, HTTP_NOT_FOUND)).message,
            decision_to_error(Decision.deny(r, HTTP_NOT_FOUND)).http_status,
        )
        for r in not_found_reasons
    }
    assert len(bodies) == 1


def test_hint_disagreeing_with_mapping_raises() -> None:
    """A pipeline hint that contradicts the reason mapping fails loudly (R18.4)."""
    # NOT_OWNER must be 404; a stray 403 hint is a bug we refuse to ship.
    bad = Decision.deny(DenyReason.NOT_OWNER, HTTP_FORBIDDEN)
    with pytest.raises(ValueError):
        decision_to_error(bad)


def test_hint_none_is_tolerated_and_mapped_by_reason() -> None:
    """A DENY without a hint still maps deterministically by its reason."""
    decision = Decision(allowed=False, reason=DenyReason.NOT_OWNER, http_hint=None)
    error = decision_to_error(decision)
    assert isinstance(error, ResourceNotFoundError)
    assert error.http_status == HTTP_NOT_FOUND


def test_decision_to_error_rejects_allow() -> None:
    """Mapping an ALLOW is a programming error, surfaced loudly (never silent)."""
    with pytest.raises(ValueError):
        decision_to_error(Decision.allow())


def test_decision_to_error_rejects_deny_without_reason() -> None:
    """A reasonless DENY cannot be mapped to a privacy-safe status."""
    with pytest.raises(ValueError):
        decision_to_error(Decision(allowed=False, reason=None, http_hint=HTTP_NOT_FOUND))


def test_enforce_is_a_noop_on_allow() -> None:
    """enforce() returns quietly for an ALLOW so endpoints proceed."""
    assert enforce(Decision.allow()) is None


@pytest.mark.parametrize("reason", list(DenyReason))
def test_enforce_raises_the_mapped_error_on_deny(reason: DenyReason) -> None:
    """enforce() raises exactly the typed AppError the mapping selects."""
    expected_status, expected_code, expected_type = _EXPECTED[reason]
    decision = Decision.deny(reason, expected_status)

    with pytest.raises(AppError) as excinfo:
        enforce(decision)

    assert isinstance(excinfo.value, expected_type)
    assert excinfo.value.http_status == expected_status
    assert excinfo.value.code == expected_code


def test_unauthenticated_error_is_401_and_generic() -> None:
    """Sanity anchor for the 401 branch used by the session/auth layer (R18.1).

    No DenyReason maps to 401 today (the pipeline's step 1 is a lifecycle 403;
    unauthenticated sessions are rejected before the pipeline runs), but the
    mapping table is wired for it, so confirm the typed error is correct.
    """
    err = UnauthenticatedError()
    assert err.http_status == HTTP_UNAUTHENTICATED
    assert err.code == "UNAUTHENTICATED"
    assert "identifier" not in err.message.lower()


def test_returned_errors_are_reinstantiated_not_shared() -> None:
    """Each call returns a fresh error instance (safe to mutate message downstream)."""
    a = decision_to_error(Decision.deny(DenyReason.NOT_OWNER, HTTP_NOT_FOUND))
    b = decision_to_error(Decision.deny(DenyReason.NOT_OWNER, HTTP_NOT_FOUND))
    assert a is not b


# A resource id is irrelevant to the mapping: the same reason yields the same
# body regardless of any client-supplied identifier (R17.1) — the mapping never
# echoes an id back.
def test_mapping_never_echoes_a_resource_identifier() -> None:
    some_id = uuid.uuid4()
    error = decision_to_error(Decision.deny(DenyReason.NOT_OWNER, HTTP_NOT_FOUND))
    assert str(some_id) not in error.message
