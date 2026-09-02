"""Property test for Property 10 — a non-ACTIVE account has no authorization path
(task 7.4).

Property 10 (design.md "Property 10: A non-ACTIVE account has no authorization
path"):

    For any account whose Account_Status is SUSPENDED or DELETED, the System
    SHALL reject presented session tokens and deny authenticated requests to
    sensitive resources, leaving no active authorization path.

Two independent fail-closed layers must close for a non-ACTIVE account, and this
property quantifies over the whole input space rather than a single fixed case:

  * Authentication layer (app/auth/service.py, R3.6). ``SessionService.authenticate``
    re-reads the authoritative Account_Status server-side on every call. Even a
    *live* (unexpired, unrevoked) session token returns ``None`` the moment the
    account is (or becomes) SUSPENDED/DELETED — so no non-ACTIVE actor is ever
    minted from a token.

  * Authorization layer (app/authorization/service.py, R7.2/R7.3). Pipeline step
    1 denies a non-ACTIVE actor with ``ACCOUNT_NOT_ACTIVE`` *before* any resource
    is resolved. This holds for ANY resource — any visibility_scope, any
    owner/couple state — and ANY action, including a resource the actor would own
    or a couple the actor actively belongs to.

Together these prove the closed guarantee: a SUSPENDED/DELETED account cannot
authenticate, and even if an actor object were obtained by any other means, the
authorization pipeline denies every request it could make. The existing example
tests (``test_authenticate_fails_closed_for_non_active_account`` and
``test_non_active_account_denied_before_resource_resolution``) assert this for
single fixed inputs; here we cover the space.

Both services are exercised through the same in-memory doubles the unit tests
use (``_InMemorySessionStore``/``_FakeStatusLookup`` and ``FakeResolver``).

Feature: foundation-auth-couples, Property 10

**Validates: Requirements 3.6, 7.2, 7.3, 8.3**
"""

from __future__ import annotations

import uuid

from hypothesis import given
from hypothesis import strategies as st

from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.authorization.models import (
    HTTP_FORBIDDEN,
    Action,
    AuthenticatedActor,
    DenyReason,
    ResourceDescriptor,
)
from app.authorization.service import AuthorizationService
from app.auth.service import SessionService
from app.enums import (
    Account_Status,
    Couple_Status,
    Member_Status,
    Visibility_Scope,
)

# Reuse the in-memory doubles the unit tests already exercise, rather than
# maintaining a parallel copy.
from tests.test_session_service import (
    _FakeStatusLookup,
    _InMemorySessionStore,
    _RecordingSession,
)
from tests.test_authorization_service import FakeResolver


# ---------------------------------------------------------------------------
# Strategies — arbitrary non-ACTIVE status, resource, action, couple state.
# ---------------------------------------------------------------------------

# The non-ACTIVE statuses that must have no authorization path (R7.1 subset).
_non_active_statuses = st.sampled_from(
    [Account_Status.SUSPENDED, Account_Status.DELETED]
)
_actions = st.sampled_from(list(Action))
_scopes = st.sampled_from(list(Visibility_Scope))
_couple_statuses = st.sampled_from(list(Couple_Status))
_member_statuses = st.sampled_from(list(Member_Status))
# Sometimes carry an owner/couple id (with server rows), sometimes not — the
# account gate must deny either way.
_optional_uuid = st.one_of(st.none(), st.uuids(version=4))


def _audit_service() -> AuditService:
    return AuditService(AuditRepository(_RecordingSession()))


# ---------------------------------------------------------------------------
# Layer 1 — authentication fails closed for a non-ACTIVE account (R3.6).
# ---------------------------------------------------------------------------

@given(
    status=_non_active_statuses,
    # Whether the account was non-ACTIVE from the start or transitioned after a
    # live token was issued — both must fail closed.
    non_active_at_creation=st.booleans(),
)
def test_property_non_active_account_never_authenticates(
    status,
    non_active_at_creation,
):
    """Property 10: a live token for a SUSPENDED/DELETED account never authenticates.

    For any non-ACTIVE status, and whether the account was non-ACTIVE when the
    session was created or only became so afterwards, ``SessionService.authenticate``
    resolves the presented token to ``None`` — the server re-reads the
    authoritative status and fails closed regardless of the live session (R3.6).
    No non-ACTIVE ``AuthenticatedActor`` is ever produced.

    Feature: foundation-auth-couples, Property 10

    **Validates: Requirements 3.6, 8.3**
    """
    uid = uuid.uuid4()
    statuses = _FakeStatusLookup()
    store = _InMemorySessionStore()
    svc = SessionService(
        store=store,
        audit_service=_audit_service(),
        user_status_lookup=statuses,
    )

    if non_active_at_creation:
        # Account already non-ACTIVE before the token is minted.
        statuses.set(uid, status)
        token = svc.create_session(uid)
    else:
        # A genuinely live session issued while ACTIVE, then the account flips.
        statuses.set(uid, Account_Status.ACTIVE)
        token = svc.create_session(uid)
        assert svc.authenticate(token) is not None  # sanity: live while ACTIVE
        statuses.set(uid, status)

    # The token record itself is still live (unexpired, unrevoked): the only
    # thing closing the path is the account-status re-read.
    record = store.get(token.session_id)
    assert record is not None and record.is_active()

    assert svc.authenticate(token) is None


# ---------------------------------------------------------------------------
# Layer 2 — authorization denies every request for a non-ACTIVE actor (R7.2/7.3).
# ---------------------------------------------------------------------------

@given(
    status=_non_active_statuses,
    action=_actions,
    scope=_scopes,
    # Sometimes make the actor the owner and/or an ACTIVE member of an ACTIVE
    # couple — the most permissive possible relationship state. The account gate
    # must still deny before any of that is consulted.
    actor_is_owner=st.booleans(),
    couple_id=_optional_uuid,
    couple_status=_couple_statuses,
    member_status=_member_statuses,
)
def test_property_non_active_actor_denied_for_every_resource(
    status,
    action,
    scope,
    actor_is_owner,
    couple_id,
    couple_status,
    member_status,
):
    """Property 10: a non-ACTIVE actor is denied for ANY resource and action.

    For any non-ACTIVE actor, any action, and any resource — any visibility_scope,
    with or without an owner/couple, and even when the actor owns the resource or
    is an ACTIVE member of an ACTIVE couple — the authorization pipeline denies at
    step 1 with ``ACCOUNT_NOT_ACTIVE`` (HTTP 403), before the resource is resolved
    (R7.2, R7.3). There is no resource for which a non-ACTIVE actor is allowed.

    Feature: foundation-auth-couples, Property 10

    **Validates: Requirements 7.2, 7.3, 8.3**
    """
    actor = AuthenticatedActor(user_id=uuid.uuid4(), account_status=status)

    # Seed the resolver with the most permissive relationship rows possible so
    # that, but for the account gate, a SHARED_COUPLE resource *would* be granted.
    resolver = FakeResolver()
    if couple_id is not None:
        resolver.set_couple(couple_id, couple_status)
        resolver.set_member(couple_id, actor.user_id, member_status)
    service = AuthorizationService(resolver)

    resource = ResourceDescriptor(
        visibility_scope=scope,
        owner_id=actor.user_id if actor_is_owner else (
            None if couple_id is None else uuid.uuid4()
        ),
        couple_id=couple_id,
    )

    decision = service.authorize(actor, action, resource)

    assert decision.allowed is False
    assert decision.reason == DenyReason.ACCOUNT_NOT_ACTIVE
    assert decision.http_hint == HTTP_FORBIDDEN


# ---------------------------------------------------------------------------
# Combined — the two layers together leave no active authorization path.
# ---------------------------------------------------------------------------

@given(
    status=_non_active_statuses,
    action=_actions,
    scope=_scopes,
    owner_id=_optional_uuid,
    couple_id=_optional_uuid,
    couple_status=_couple_statuses,
    member_status=_member_statuses,
)
def test_property_no_active_authorization_path_remains(
    status,
    action,
    scope,
    owner_id,
    couple_id,
    couple_status,
    member_status,
):
    """Property 10: end-to-end, a non-ACTIVE account has no authorization path.

    A session issued while the account was ACTIVE goes non-ACTIVE. From that point:
      (a) the live token no longer authenticates (``authenticate`` -> ``None``,
          R3.6) — so no actor is minted through the front door; and
      (b) even given a non-ACTIVE actor, ``authorize`` denies every request
          (ACCOUNT_NOT_ACTIVE, R7.2/R7.3) for any resource/action.
    Both hold together for arbitrary status/resource/action/couple state, proving
    no active path survives.

    Feature: foundation-auth-couples, Property 10

    **Validates: Requirements 3.6, 7.2, 7.3, 8.3**
    """
    uid = uuid.uuid4()
    statuses = _FakeStatusLookup({uid: Account_Status.ACTIVE})
    store = _InMemorySessionStore()
    session_svc = SessionService(
        store=store,
        audit_service=_audit_service(),
        user_status_lookup=statuses,
    )

    token = session_svc.create_session(uid)
    statuses.set(uid, status)  # account transitions to SUSPENDED/DELETED

    # (a) Authentication layer closes: the live token yields no actor.
    assert session_svc.authenticate(token) is None

    # (b) Authorization layer closes: even holding a non-ACTIVE actor for this
    # same user, every request is denied regardless of the resource.
    actor = AuthenticatedActor(user_id=uid, account_status=status)
    resolver = FakeResolver()
    if couple_id is not None:
        resolver.set_couple(couple_id, couple_status)
        resolver.set_member(couple_id, uid, member_status)
    resource = ResourceDescriptor(
        visibility_scope=scope,
        owner_id=owner_id,
        couple_id=couple_id,
    )

    decision = AuthorizationService(resolver).authorize(actor, action, resource)
    assert decision.allowed is False
    assert decision.reason == DenyReason.ACCOUNT_NOT_ACTIVE
