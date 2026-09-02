"""Property-based test for Property 18 (sensitive operations gated by re-auth).

Feature: foundation-auth-couples, Property 18: Sensitive operations are gated by
re-authentication.

This module implements the single property-based test that validates
correctness Property 18 from the design ("Correctness Properties"):

    *For any* ``Sensitive_Operation`` (account deletion request, couple
    disconnection, account/security setting change), absence or failure of
    Re_Authentication SHALL cause the operation to be denied.

The gate has two enforcement sides in the design's "Auth module":

  * :meth:`AuthenticationService.require_reauthentication` opens the gate — it
    verifies a *fresh* credential proof and, on success, mints a short-lived,
    single-operation :class:`ReauthToken`. A missing or failing proof raises
    :class:`ReauthRequiredError` (403) and mints nothing (R5.1/R5.2).
  * :meth:`AuthenticationService.consume_reauthentication` enforces the gate at
    the point of the operation — it returns ``True`` only for a grant that
    exists, matches the presented token, belongs to the acting actor, and was
    minted for exactly that operation; consuming it makes it single-use.

The property quantifies over all three Sensitive_Operations (R5.3) and asserts
the operation is DENIED whenever Re_Authentication is absent or fails, and only
proceeds on a valid, fresh, correctly-scoped grant:

  1. **Missing / failed proof denies (R5.2).** An empty proof and a wrong-
     credential proof both raise ``ReauthRequiredError`` (403) and mint no
     grant.
  2. **A valid fresh proof authorises exactly one operation for one actor
     (R5.1).** The minted grant validates once for its own actor+operation; a
     grant minted for operation X never authorises operation Y, and never
     authorises a different actor.
  3. **A consumed grant cannot be reused (R5.1).** After a single successful
     consume, replaying the same grant is denied.
  4. **End-to-end at a real Sensitive_Operation.**
     :meth:`AccountService.request_account_deletion` (a Sensitive_Operation,
     R5.3) denies with ``ReauthRequiredError`` unless a valid
     ACCOUNT_DELETION_REQUEST grant is presented, and creates nothing when it
     denies.

Runs under the "foundation" Hypothesis profile (min 100 iterations) registered
in ``conftest.py``. Reuses the in-memory fakes from the auth- and
account-service example suites so the property drives the exact same wiring.

**Validates: Requirements 5.1, 5.2, 5.3**
"""

from __future__ import annotations

import uuid

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.authorization.models import AuthenticatedActor
from app.enums import Account_Status
from app.errors import ReauthRequiredError
from app.auth.service import (
    AuthenticationService,
    InMemoryIdentityProvider,
    ReauthToken,
    SessionService,
    Sensitive_Operation,
)
from app.users.service import AccountService

# Reuse the in-memory fakes the example suites already exercise so the property
# drives the exact same wiring as the unit tests.
from tests.test_authentication_service import (
    _FakeUserRepository,
    _InMemoryReauthStore,
    _InMemoryRecoveryStore,
    _InMemorySessionStore,
    _RecordingSession,
)
from tests.test_account_service import (
    _FakeDeletionRepository,
    _FakeUserRepository as _AccountUserRepository,
    _make_user,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# All three Sensitive_Operations (R5.3): the property must hold for each.
_operations = st.sampled_from(list(Sensitive_Operation))

# A well-formed ``local@domain.tld`` identifier (passes the service shape check
# so the branch under test is re-auth, not identifier validation).
_local = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
    min_size=1,
    max_size=16,
)
_domain_label = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
    min_size=1,
    max_size=12,
)
_tld = st.sampled_from(["test", "example", "invalid", "local"])


@st.composite
def _identifiers(draw) -> str:
    return f"{draw(_local)}@{draw(_domain_label)}.{draw(_tld)}"


# A non-empty credential (the account's real password).
_credentials = st.text(min_size=1, max_size=24)
# An arbitrary "bad proof": empty string or an arbitrary (likely-wrong) value.
_bad_proofs = st.one_of(st.just(""), st.text(max_size=24))


# ---------------------------------------------------------------------------
# Builders (mirror the example suites' _build_service wiring)
# ---------------------------------------------------------------------------


def _build_auth_service():
    """Wire an AuthenticationService over in-memory fakes; return (svc, users)."""
    users = _FakeUserRepository()
    idp = InMemoryIdentityProvider()
    audit = AuditService(AuditRepository(_RecordingSession()))
    sessions = SessionService(
        store=_InMemorySessionStore(),
        audit_service=audit,
        user_status_lookup=users,
    )
    svc = AuthenticationService(
        user_repository=users,
        identity_provider=idp,
        session_service=sessions,
        audit_service=audit,
        recovery_store=_InMemoryRecoveryStore(),
        reauth_store=_InMemoryReauthStore(),
    )
    return svc, users


def _actor_for(user) -> AuthenticatedActor:
    return AuthenticatedActor(user_id=user.id, account_status=Account_Status.ACTIVE)


# ---------------------------------------------------------------------------
# Property 18 (Hypothesis, foundation profile — min 100 iterations)
# ---------------------------------------------------------------------------


@given(
    identifier=_identifiers(),
    credential=_credentials,
    bad_proof=_bad_proofs,
    operation=_operations,
    other_operation=_operations,
)
def test_property_sensitive_operations_gated_by_reauthentication(
    identifier,
    credential,
    bad_proof,
    operation,
    other_operation,
):
    """Property 18: a Sensitive_Operation is denied without a valid Re_Authentication.

    For an arbitrary Sensitive_Operation and an ACTIVE account:

    1. A missing (empty) or failing (wrong-credential) proof raises
       ``ReauthRequiredError`` (403) and mints no grant (R5.2).
    2. A valid fresh proof mints a grant that authorises exactly one operation
       for one actor: it validates once for its own actor+operation, but a grant
       minted for ``operation`` never authorises a *different* operation, and
       never authorises a *different* actor (R5.1).
    3. A consumed grant cannot be replayed (single-use, R5.1).

    Feature: foundation-auth-couples, Property 18.
    **Validates: Requirements 5.1, 5.2, 5.3**
    """
    svc, _users = _build_auth_service()
    user = svc.register(identifier, credential)
    actor = _actor_for(user)

    # -- (1) missing / failed proof denies (R5.2) ------------------------
    # Empty proof is always a "missing" proof.
    with pytest.raises(ReauthRequiredError) as empty_exc:
        svc.require_reauthentication(actor, "", operation)
    assert empty_exc.value.http_status == 403

    # A wrong-credential proof must fail too. Guard against the rare draw that
    # equals the real credential by mutating it so it is guaranteed wrong.
    wrong_proof = bad_proof
    if wrong_proof == credential:
        wrong_proof = credential + "x"
    if wrong_proof != "":  # empty already covered above
        with pytest.raises(ReauthRequiredError) as wrong_exc:
            svc.require_reauthentication(actor, wrong_proof, operation)
        assert wrong_exc.value.http_status == 403

    # -- (2) a valid fresh proof authorises exactly one operation (R5.1) -
    grant = svc.require_reauthentication(actor, credential, operation)
    assert grant.operation_type == operation

    # A grant minted for ``operation`` does not authorise a *different*
    # operation. Probe a freshly-minted grant so ``grant`` itself stays intact
    # for the single-use assertion below (a consume attempt burns whatever grant
    # id it targets, pass or fail).
    if other_operation != operation:
        grant_wrong_op = svc.require_reauthentication(actor, credential, operation)
        assert (
            svc.consume_reauthentication(grant_wrong_op, actor, other_operation)
            is False
        )

    # A grant is bound to its actor: a *different* actor cannot use it. Uses a
    # freshly-minted grant so it does not disturb ``grant`` (any consume attempt
    # burns the grant id it targets — the single-use semantic).
    other_actor = AuthenticatedActor(
        user_id=uuid.uuid4(), account_status=Account_Status.ACTIVE
    )
    grant_other_actor = svc.require_reauthentication(actor, credential, operation)
    assert (
        svc.consume_reauthentication(grant_other_actor, other_actor, operation)
        is False
    )

    # A forged token (right grant id, wrong secret) never validates. This probes
    # a fresh grant's id — not ``grant`` — because a consume attempt against a
    # grant id consumes (pops) it regardless of the outcome (single-use).
    forgeable = svc.require_reauthentication(actor, credential, operation)
    forged = ReauthToken(
        grant_id=forgeable.grant_id, token="forged", operation_type=operation
    )
    assert svc.consume_reauthentication(forged, actor, operation) is False

    # The genuine ``grant`` validates exactly once for its own actor + operation...
    assert svc.consume_reauthentication(grant, actor, operation) is True
    # -- (3) ...and cannot be reused (single-use, R5.1) ------------------
    assert svc.consume_reauthentication(grant, actor, operation) is False


# ---------------------------------------------------------------------------
# Property 18 — end-to-end at a real Sensitive_Operation (account deletion)
# ---------------------------------------------------------------------------


def _build_account_service():
    """Wire a real AuthenticationService + AccountService over in-memory fakes.

    The AccountService's deletion gate delegates to the *real*
    ``AuthenticationService.consume_reauthentication`` (not a stub), so the
    end-to-end denial is exercised through the same grant machinery as the
    unit property above.
    """
    users = _AccountUserRepository()
    idp = InMemoryIdentityProvider()
    audit = AuditService(AuditRepository(_RecordingSession()))
    sessions = SessionService(
        store=_InMemorySessionStore(),
        audit_service=audit,
        user_status_lookup=users,
    )
    reauth = _InMemoryReauthStore()
    auth = AuthenticationService(
        user_repository=users,
        identity_provider=idp,
        session_service=sessions,
        audit_service=audit,
        recovery_store=_InMemoryRecoveryStore(),
        reauth_store=reauth,
    )
    deletions = _FakeDeletionRepository()
    account = AccountService(
        user_repository=users,
        deletion_repository=deletions,
        session_service=sessions,
        authentication_service=auth,
        audit_service=audit,
    )
    return account, auth, users, idp, deletions


@given(
    identifier=_identifiers(),
    credential=_credentials,
    wrong_operation=st.sampled_from(
        [
            Sensitive_Operation.COUPLE_DISCONNECTION,
            Sensitive_Operation.ACCOUNT_SECURITY_SETTING_CHANGE,
        ]
    ),
)
def test_property_account_deletion_denied_without_valid_reauth(
    identifier,
    credential,
    wrong_operation,
):
    """Property 18 end-to-end: account deletion denies without a valid grant (R5.3).

    ``AccountService.request_account_deletion`` is a Sensitive_Operation. It must
    deny with ``ReauthRequiredError`` — creating nothing — when:

      * no grant is presented (a forged/never-minted grant), or
      * the presented grant was minted for a *different* Sensitive_Operation.

    It proceeds only when a fresh ACCOUNT_DELETION_REQUEST grant is presented,
    and that grant is then single-use.

    Feature: foundation-auth-couples, Property 18.
    **Validates: Requirements 5.1, 5.2, 5.3**
    """
    account, auth, users, idp, deletions = _build_account_service()

    # Register the user directly against the account fakes and give the IdP the
    # matching credential so re-auth can succeed.
    user = users.add_user(_make_user(auth_identifier=identifier.strip().lower()))
    idp.register_credentials(identifier.strip().lower(), credential)
    actor = AuthenticatedActor(user_id=user.id, account_status=Account_Status.ACTIVE)

    # (a) A forged / never-minted grant denies, and creates nothing (R5.2).
    forged = ReauthToken(
        grant_id="never-minted-" + uuid.uuid4().hex,
        token="nope",
        operation_type=Sensitive_Operation.ACCOUNT_DELETION_REQUEST,
    )
    with pytest.raises(ReauthRequiredError):
        account.request_account_deletion(actor, forged)
    assert deletions.created == []

    # (b) A grant minted for a *different* operation denies (wrong scope, R5.1).
    mismatched = auth.require_reauthentication(
        actor, credential, wrong_operation, auth_identifier=identifier.strip().lower()
    )
    with pytest.raises(ReauthRequiredError):
        account.request_account_deletion(actor, mismatched)
    assert deletions.created == []

    # (c) A valid, correctly-scoped grant proceeds and creates exactly one
    #     REQUESTED record.
    valid = auth.require_reauthentication(
        actor,
        credential,
        Sensitive_Operation.ACCOUNT_DELETION_REQUEST,
        auth_identifier=identifier.strip().lower(),
    )
    request = account.request_account_deletion(actor, valid)
    assert request is not None
    assert len(deletions.created) == 1

    # (d) The consumed grant cannot be replayed (single-use, R5.1) — a replay
    #     denies and creates nothing further.
    with pytest.raises(ReauthRequiredError):
        account.request_account_deletion(actor, valid)
    assert len(deletions.created) == 1
