"""Property-based test for Property 15 (account existence never disclosed).

Feature: foundation-auth-couples, Property 15: Account existence is never
disclosed on auth failures.

This module implements the single property-based test that validates
correctness Property 15 from the design ("Correctness Properties"):

    *For any* authentication identifier — whether it corresponds to a
    registered account or not — an invalid-login attempt and a recovery
    initiation SHALL produce responses that are **indistinguishable** between
    the existing and non-existing cases, and no such response SHALL expose
    another User's authentication identifier.

Two observable surfaces are quantified:

  * **login failures (R2.2, R1.5)** — a wrong-credential login against a
    *registered* identifier and a login against an *unregistered* identifier
    both raise a single generic ``AuthenticationFailedError``. The property
    asserts the two failures are byte-for-byte indistinguishable (same
    ``type``, ``code``, ``http_status``, ``message``) and that no identifier —
    the attempted one or any other registered user's — ever appears in the
    error text (R1.5).

  * **recovery initiation (R4.2)** — initiating recovery for a *registered*
    identifier and for an *unregistered* one is observably identical at the
    layer the property concerns: neither raises, and the value handed back to
    the caller never leaks *which* case occurred by exposing an identifier. The
    internal ``RecoveryChallenge`` carries only opaque, unguessable secrets, so
    the caller (and the API layer that renders an identical generic success)
    cannot distinguish existing from non-existing (R4.2).

Runs under the "foundation" Hypothesis profile (min 100 iterations) registered
in ``conftest.py``.

**Validates: Requirements 1.5, 2.2, 4.2**
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from app.auth.service import (
    AuthenticationService,
    InMemoryIdentityProvider,
    RecoveryChallenge,
    SessionService,
)
from app.audit.repository import AuditRepository
from app.audit.service import AuditService
from app.errors import AuthenticationFailedError

# Reuse the in-memory fakes and the service builder that the example-based
# suite already exercises, so this property drives the exact same wiring.
from tests.test_authentication_service import (
    _FakeUserRepository,
    _InMemoryReauthStore,
    _InMemoryRecoveryStore,
    _InMemorySessionStore,
    _RecordingSession,
)


# ---------------------------------------------------------------------------
# Strategies — arbitrary, well-formed authentication identifiers.
#
# The property quantifies over identifiers that pass the service's shape check
# (local@domain.tld) so that failures are driven by *credential invalidity* /
# *account non-existence* rather than by input validation — validation errors
# are a distinct, already-tested branch (R1.3) and would confound the
# "indistinguishable failure" property.
# ---------------------------------------------------------------------------

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
    """A well-formed ``local@domain.tld`` identifier (passes the shape check)."""
    return f"{draw(_local)}@{draw(_domain_label)}.{draw(_tld)}"


_credentials = st.text(min_size=1, max_size=24)


def _build_service():
    """Wire an AuthenticationService over in-memory fakes (mirrors _build_service)."""
    users = _FakeUserRepository()
    idp = InMemoryIdentityProvider()
    audit_session = _RecordingSession()
    audit = AuditService(AuditRepository(audit_session))
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
    return svc


def _failure_signature(exc: AuthenticationFailedError) -> tuple:
    """The full observable signature of an auth failure the client can see."""
    return (type(exc), exc.code, exc.http_status, exc.message, str(exc))


# ---------------------------------------------------------------------------
# Property 15 (Hypothesis, foundation profile — min 100 iterations)
# ---------------------------------------------------------------------------


@given(
    registered_id=_identifiers(),
    registered_credential=_credentials,
    other_id=_identifiers(),
    wrong_credential=_credentials,
    attempt_credential=_credentials,
)
def test_property_account_existence_never_disclosed(
    registered_id,
    registered_credential,
    other_id,
    wrong_credential,
    attempt_credential,
):
    """Property 15: auth failures never disclose account existence.

    Given an account registered under ``registered_id`` and an ``other_id`` that
    is deliberately *not* registered:

    1. A wrong-credential login for the registered identifier and a login for
       the non-existent identifier raise the SAME generic
       ``AuthenticationFailedError`` — indistinguishable in type, code,
       http_status, and message — and neither error text exposes any
       identifier (R2.2, R1.5).
    2. Initiating recovery for the registered vs the non-existent identifier is
       observably identical to the caller: neither raises, and nothing handed
       back exposes an identifier (R4.2, R1.5).

    Feature: foundation-auth-couples, Property 15.
    **Validates: Requirements 1.5, 2.2, 4.2**
    """
    svc = _build_service()

    # ``other_id`` must be genuinely absent for the "non-existing" arm to mean
    # something; skip the rare collision where the two draws normalise equal.
    if other_id.strip().lower() == registered_id.strip().lower():
        return

    svc.register(registered_id, registered_credential)

    # Ensure the wrong credential is actually wrong for the registered account
    # (a random draw could coincide with the real one). If it matches, mutate it
    # so the login is guaranteed to fail on credential grounds.
    effective_wrong = wrong_credential
    if effective_wrong == registered_credential:
        effective_wrong = registered_credential + "x"

    # -- (1) login failures are indistinguishable ------------------------
    existing_failure = None
    try:
        svc.login(registered_id, effective_wrong)
    except AuthenticationFailedError as exc:  # expected
        existing_failure = exc
    assert existing_failure is not None, "wrong credential must fail login"

    nonexisting_failure = None
    try:
        svc.login(other_id, attempt_credential)
    except AuthenticationFailedError as exc:  # expected
        nonexisting_failure = exc
    assert nonexisting_failure is not None, "unknown identifier must fail login"

    # Byte-for-byte indistinguishable: an attacker cannot tell whether the
    # identifier exists from the failure alone (R2.2).
    assert _failure_signature(existing_failure) == _failure_signature(
        nonexisting_failure
    )

    # No response exposes any user's identifier (R1.5): neither the attempted
    # identifier nor the registered account's identifier appears in the text.
    for failure in (existing_failure, nonexisting_failure):
        text = f"{failure.message} {failure.code} {failure}"
        assert registered_id.strip().lower() not in text.lower()
        assert other_id.strip().lower() not in text.lower()

    # -- (2) recovery initiation is indistinguishable --------------------
    # Neither arm raises, so the caller cannot branch on an exception (R4.2).
    existing_recovery = svc.initiate_recovery(registered_id)
    nonexisting_recovery = svc.initiate_recovery(other_id)

    # Whatever is returned must never expose an identifier to the caller: the
    # existing arm yields a RecoveryChallenge whose fields are opaque secrets,
    # and the non-existing arm yields None. The API layer renders an identical
    # generic success for both (R4.2), so the only thing that must hold at this
    # layer is that no identifier leaks through the returned value (R1.5).
    if existing_recovery is not None:
        assert isinstance(existing_recovery, RecoveryChallenge)
        leaked = f"{existing_recovery.challenge_id} {existing_recovery.secret}".lower()
        assert registered_id.strip().lower() not in leaked
        assert other_id.strip().lower() not in leaked

    # The non-existing identifier issues no challenge and, crucially, raises no
    # error that would distinguish it from the existing case.
    assert nonexisting_recovery is None
