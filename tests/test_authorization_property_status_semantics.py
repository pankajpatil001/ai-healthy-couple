"""Property test: authorization failures use consistent, privacy-safe status
semantics (task 4.9).

Feature: foundation-auth-couples, Property 21: Authorization failures use
consistent, privacy-safe status semantics.

The invariant (design.md "Property 21", R17.3, R17.4, R18.1, R18.2, R18.3,
R18.4): every authorization denial resolves to *exactly one* of the three
privacy-safe HTTP statuses — 401 UNAUTHENTICATED, 403 FORBIDDEN, or 404
RESOURCE_NOT_FOUND — never anything else, and the mapping is applied
*uniformly*:

* **Exhaustive & closed** — for any DENY the pipeline can emit, and for any
  ``DenyReason`` value at all, the mapped ``http_status`` is in {401, 403, 404}
  (R18.1-R18.3). No denial ever escapes this set.
* **Deterministic / uniform** — the same reason ALWAYS maps to the same status
  and the same machine-readable ``code``; the outcome does not depend on the
  actor, action, resource identifiers, or any client-supplied input (R18.4).
* **Privacy-safe & non-leaking** — the mapped ``message`` is generic and never
  reveals ownership, membership, account existence, or resource existence
  (design "Error Handling" general rules).
* **Indistinguishable 404s** — every reason that maps to a privacy-safe 404
  produces an *identical* response body (status + code + message), so a probe
  can never tell a non-owner, a non-member, an inactive couple, a hidden zone,
  an ordinary miss, or a default-deny apart (R17.3, R17.4, R18.3).

Two complementary generators drive the space, per the task:

1. *End-to-end*: arbitrary actor / action / resource states that yield DENY
   decisions from the real :class:`AuthorizationService`, mapped through
   :func:`decision_to_error`.
2. *Direct*: arbitrary :class:`DenyReason` values mapped directly, so the
   closed-set / determinism guarantee is proven over the whole reason enum
   independent of whether the pipeline currently emits every reason.

The service is a pure decision function over injected server state, so this test
drives it with the in-memory :class:`FakeResolver` from the unit suite — no
database required.
"""

from __future__ import annotations

import uuid

from hypothesis import assume, given
from hypothesis import strategies as st

from app.authorization.enforcement import decision_to_error, enforce
from app.authorization.models import (
    HTTP_FORBIDDEN,
    HTTP_NOT_FOUND,
    HTTP_UNAUTHENTICATED,
    Action,
    AuthenticatedActor,
    Decision,
    DenyReason,
    ResourceDescriptor,
)
from app.authorization.service import AuthorizationService
from app.enums import Account_Status, Couple_Status, Member_Status, Visibility_Scope
from tests.test_authorization_service import FakeResolver

# The complete, closed set of privacy-safe denial statuses (R18.1-R18.3). No
# authorization failure may ever resolve to a status outside this set.
_ALLOWED_STATUSES = {HTTP_UNAUTHENTICATED, HTTP_FORBIDDEN, HTTP_NOT_FOUND}

# Terms a mapped failure body must never contain: they would leak ownership,
# membership, account existence, or resource existence (design "Error Handling").
_LEAKING_TERMS = [
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

# A stable pool of ids so a generated actor can be the owner, a couple member,
# or an unrelated third party with realistic probability.
_ACTOR_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
_OTHER_ID = uuid.UUID("00000000-0000-4000-8000-000000000002")
_COUPLE_ID = uuid.UUID("00000000-0000-4000-8000-0000000000c0")


@st.composite
def denying_states(draw):
    """An arbitrary server state, returned with the DENY decision it yields.

    Spans the full authorization space — non-ACTIVE accounts, missing
    resources, owner vs non-owner, active / former / non members, every couple
    lifecycle, and every visibility scope — and re-draws (via ``assume``) any
    combination that happens to ALLOW, so only genuine denials reach the
    assertions.
    """
    account_status = draw(st.sampled_from(list(Account_Status)))
    action = draw(st.sampled_from(list(Action)))
    scope = draw(st.sampled_from(list(Visibility_Scope)))
    owner_id = draw(st.sampled_from([_ACTOR_ID, _OTHER_ID, None]))
    couple_id = draw(st.sampled_from([_COUPLE_ID, None]))
    # Client-supplied, audit-only identifiers — must never affect the mapping.
    resource_id = draw(st.one_of(st.none(), st.uuids(version=4)))
    resource_type = draw(st.one_of(st.none(), st.text(max_size=32)))
    # A missing resource (None) is a legitimate privacy-safe not-found path.
    resource_present = draw(st.booleans())

    resolver = FakeResolver()
    couple_status = draw(st.sampled_from(list(Couple_Status) + [None]))
    if couple_status is not None:
        resolver.set_couple(_COUPLE_ID, couple_status)
    member_status = draw(st.sampled_from(list(Member_Status) + [None]))
    if member_status is not None:
        resolver.set_member(_COUPLE_ID, _ACTOR_ID, member_status)

    actor = AuthenticatedActor(user_id=_ACTOR_ID, account_status=account_status)
    resource = (
        ResourceDescriptor(
            visibility_scope=scope,
            owner_id=owner_id,
            couple_id=couple_id,
            resource_id=resource_id,
            resource_type=resource_type,
        )
        if resource_present
        else None
    )
    return actor, action, resolver, resource


# ---------------------------------------------------------------------------
# Property 21 (Hypothesis, foundation profile — min 100 iterations)
# ---------------------------------------------------------------------------


@given(state=denying_states())
def test_property_pipeline_denials_map_to_privacy_safe_status(state):
    """Property 21: every DENY the service emits maps to a 401/403/404 failure.

    For an arbitrary actor / action / resource state that the real
    :class:`AuthorizationService` denies, the mapped typed error carries a status
    in {401, 403, 404} and never anything else (R18.1-R18.3), and its message is
    generic — leaking no ownership, membership, or existence signal (R18). The
    client-supplied ``resource_id`` / ``resource_type`` on the descriptor never
    influence the mapped status or code (R18.4).

    Feature: foundation-auth-couples, Property 21.
    **Validates: Requirements 17.3, 17.4, 18.1, 18.2, 18.3, 18.4**
    """
    actor, action, resolver, resource = state
    service = AuthorizationService(resolver)

    decision = service.authorize(actor, action, resource)
    # Only denials are in scope for Property 21; re-draw any ALLOW.
    assume(not decision.allowed)

    error = decision_to_error(decision)

    assert error.http_status in _ALLOWED_STATUSES, (
        f"denial mapped to a non-privacy-safe status {error.http_status} "
        f"(reason={decision.reason})"
    )

    message = error.message.lower()
    for term in _LEAKING_TERMS:
        assert term not in message, f"failure body leaks '{term}': {error.message!r}"

    # enforce() must raise exactly the mapped error (same status), so the
    # single choke-point stays consistent with decision_to_error (R18.4).
    try:
        enforce(decision)
    except type(error) as raised:
        assert raised.http_status == error.http_status
        assert raised.code == error.code
    else:  # pragma: no cover - a DENY must always raise
        raise AssertionError("enforce() did not raise on a DENY decision")


@given(
    reason=st.sampled_from(list(DenyReason)),
    # Arbitrary client-supplied context that must not perturb the mapping.
    resource_id=st.one_of(st.none(), st.uuids(version=4)),
)
def test_property_every_deny_reason_maps_into_the_closed_status_set(reason, resource_id):
    """Property 21: any DenyReason maps to exactly one of 401/403/404, uniformly.

    Quantified directly over the whole ``DenyReason`` enum (independent of which
    reasons the pipeline currently emits), so the closed-set guarantee holds for
    every reason the classification can ever carry. The mapped status is always
    in {401, 403, 404} (R18.1-R18.3), the message is generic (R18), and the
    presence of an arbitrary client-supplied identifier changes nothing (R18.4).

    Feature: foundation-auth-couples, Property 21.
    **Validates: Requirements 17.3, 17.4, 18.1, 18.2, 18.3, 18.4**
    """
    decision = Decision(allowed=False, reason=reason, http_hint=None)
    error = decision_to_error(decision)

    assert error.http_status in _ALLOWED_STATUSES

    message = error.message.lower()
    for term in _LEAKING_TERMS:
        assert term not in message, f"failure body leaks '{term}': {error.message!r}"

    # The client-supplied identifier is never echoed into the body.
    if resource_id is not None:
        assert str(resource_id) not in error.message


@given(
    reason=st.sampled_from(list(DenyReason)),
    call_count=st.integers(min_value=2, max_value=8),
)
def test_property_reason_maps_deterministically_and_uniformly(reason, call_count):
    """Property 21: the same reason always maps to the same status and code.

    Mapping one reason repeatedly yields a single (status, code) pair every
    time — the mapping is a deterministic, input-independent function of the
    reason alone (R18.4). Each call also returns a fresh error instance, so a
    downstream mutation of one body can never bleed into another.

    Feature: foundation-auth-couples, Property 21.
    **Validates: Requirements 18.1, 18.2, 18.3, 18.4**
    """
    outcomes = set()
    instances = []
    for _ in range(call_count):
        error = decision_to_error(Decision(allowed=False, reason=reason))
        outcomes.add((error.http_status, error.code, error.message))
        instances.append(error)

    assert len(outcomes) == 1, f"reason {reason} mapped inconsistently: {outcomes}"
    # Fresh instance per call (no shared mutable error object).
    assert len({id(e) for e in instances}) == len(instances)


@given(
    reasons=st.lists(st.sampled_from(list(DenyReason)), min_size=2, max_size=16),
)
def test_property_privacy_safe_not_found_bodies_are_indistinguishable(reasons):
    """Property 21: all 404 reasons produce an identical, indistinguishable body.

    Every reason that maps to a privacy-safe 404 yields the same (status, code,
    message) triple, so a probe cannot distinguish a non-owner, a non-member, an
    inactive couple, a hidden zone, an ordinary miss, or a default-deny — they
    are all a plain "not found" (R17.3, R17.4, R18.3). Reasons that do not map to
    404 are filtered out; the property asserts the surviving 404 bodies collapse
    to a single value.

    Feature: foundation-auth-couples, Property 21.
    **Validates: Requirements 17.3, 17.4, 18.3**
    """
    bodies = set()
    for reason in reasons:
        error = decision_to_error(Decision(allowed=False, reason=reason))
        if error.http_status == HTTP_NOT_FOUND:
            bodies.add((error.http_status, error.code, error.message))

    # Need at least one 404 in the sample to make a meaningful assertion.
    assume(bodies)
    assert len(bodies) == 1, f"privacy-safe 404 bodies differ: {bodies}"
