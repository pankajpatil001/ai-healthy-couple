"""Property-based test for Property 19 (lifecycle status is server-controlled).

Feature: foundation-auth-couples, Property 19: Lifecycle status is
server-controlled — a client-supplied ``Account_Status`` / ``Couple_Status``
value is rejected, and the authoritative status is only ever changed through a
server-side lifecycle operation.

The property has two halves:

* **Account_Status (R7.4) — fully covered here.** For *arbitrary* settings
  payloads that smuggle an ``account_status`` / ``status`` field set to ANY
  value (any ``Account_Status`` member or an arbitrary string), possibly mixed
  with arbitrary benign profile fields, ``AccountService.update_own_settings``
  rejects the payload with :class:`~app.errors.ValidationError` and the user's
  authoritative status is left UNCHANGED. Complementarily, there is no
  client-writable path to ``Account_Status``: the :class:`SettingsUpdate` schema
  neither declares a status field nor accepts extras (``extra="forbid"``), the
  lifecycle levers are enumerated in ``_FORBIDDEN_SETTINGS_FIELDS``, and
  :meth:`AccountService.transition_status` — the *only* server-side write path —
  still constrains its input to the ``Account_Status`` value set.

* **Couple_Status (R13.7) — covered at the layer that exists.** The couple
  lifecycle write paths live in ``CoupleService`` (task 9), which is not yet
  implemented (``app/couples/service.py`` is a stub). The invariant is therefore
  asserted at the layer that exists today: no **client-writable request/input**
  schema in ``app/couples/schemas.py`` accepts a ``Couple_Status`` — there is no
  request DTO through which a client could *set* one. A read-only *response*
  projection that merely exposes the server-controlled status for rendering
  (e.g. ``CoupleView``, built from an ORM row via ``from_attributes``) is an
  output, not an input, and so is expected — not a violation. The ``Couple``
  model's ``status`` is server-controlled
  (defaults to ``PENDING``; there is no client-facing setter). The disconnect /
  create-flow rejection assertions (that ``CoupleService`` ignores a
  client-supplied ``Couple_Status`` when creating PENDING / disconnecting) are
  **deferred until task 9.x lands** and should be added to this file once
  ``CoupleService`` implements those flows.

Runs under the "foundation" Hypothesis profile (min 100 iterations) registered
in ``conftest.py``. Reuses the in-memory fakes and builders from
``tests/test_account_service.py`` so the property is exercised against the same
service wiring as the example-based unit tests.

**Validates: Requirements 7.4, 13.7**
"""

from __future__ import annotations

import inspect

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.couples import schemas as couple_schemas
from app.couples.models import Couple
from app.enums import Account_Status, Couple_Status
from app.errors import ValidationError
from app.users.schemas import _FORBIDDEN_SETTINGS_FIELDS, SettingsUpdate

# Reuse the exact fakes/builders the example-based AccountService tests use, so
# the property is proven against the same in-memory wiring (no new doubles).
from tests.test_account_service import (
    _FakeUserRepository,
    _actor,
    _make_user,
    _service,
)

# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

#: The field names a client might use to try to smuggle a lifecycle change in
#: through the settings door. Both are lifecycle levers guarded by R7.4.
_STATUS_FIELD_NAMES = ["account_status", "status"]

#: Values a client might supply for the smuggled status field: every valid
#: Account_Status member value plus arbitrary strings (including near-misses and
#: empty). The property must hold for ALL of them — a *valid* status value is
#: just as forbidden through settings as an invalid one (R7.4).
_status_values = st.one_of(
    st.sampled_from([s.value for s in Account_Status]),
    st.sampled_from(["deleted", "Active", "PENDING", "", "ADMIN", "0", "true"]),
    st.text(max_size=24),
)

#: Arbitrary benign profile fields that a real settings update might carry. These
#: are mixed alongside the smuggled status field to prove the whole payload is
#: rejected atomically (the benign fields never take effect either).
_benign_fields = st.dictionaries(
    keys=st.sampled_from(["display_name", "locale", "timezone"]),
    values=st.text(min_size=1, max_size=16),
    max_size=3,
)


# ---------------------------------------------------------------------------
# Property 19 — Account_Status half (Hypothesis, foundation profile: 100+)
# ---------------------------------------------------------------------------


@given(
    field=st.sampled_from(_STATUS_FIELD_NAMES),
    status_value=_status_values,
    benign=_benign_fields,
    initial=st.sampled_from(list(Account_Status)),
)
def test_property_client_supplied_account_status_is_rejected(
    field, status_value, benign, initial
):
    """Property 19 (Account_Status, R7.4): a smuggled status is always rejected.

    For any status field name, any status value (valid member or arbitrary
    string), any accompanying benign fields, and any initial account status:

    1. ``update_own_settings`` raises :class:`ValidationError` — the payload is
       rejected, not partially applied; and
    2. the user's authoritative ``status`` is UNCHANGED — neither the smuggled
       status nor the benign fields took effect.

    Feature: foundation-auth-couples, Property 19.
    **Validates: Requirements 7.4, 13.7**
    """
    users = _FakeUserRepository()
    user = users.add_user(_make_user(status=initial))
    svc, *_ = _service(users=users)

    original_status = user.status
    original_display = user.display_name
    original_locale = user.locale
    original_timezone = user.timezone

    payload = dict(benign)
    payload[field] = status_value  # the smuggled lifecycle lever

    with pytest.raises(ValidationError):
        svc.update_own_settings(_actor(user), payload)

    # Nothing took effect — status is unchanged and no benign field leaked in
    # (the whole payload is rejected atomically, R7.4).
    assert user.status == original_status
    assert user.display_name == original_display
    assert user.locale == original_locale
    assert user.timezone == original_timezone


@given(status_value=_status_values)
def test_property_settings_schema_has_no_client_status_path(status_value):
    """Property 19 (Account_Status, R7.4): the schema exposes no status field.

    The only client-facing settings payload is :class:`SettingsUpdate`. It
    declares no ``account_status`` / ``status`` field and forbids extras, so
    validating a payload that carries a status field always fails — there is no
    client-writable path to ``Account_Status`` other than the server-side
    :meth:`AccountService.transition_status`.

    Feature: foundation-auth-couples, Property 19.
    **Validates: Requirements 7.4**
    """
    # The schema does not model a status field at all.
    assert "account_status" not in SettingsUpdate.model_fields
    assert "status" not in SettingsUpdate.model_fields
    # And the lifecycle levers are enumerated as forbidden.
    assert {"account_status", "status"} <= _FORBIDDEN_SETTINGS_FIELDS

    for field in _STATUS_FIELD_NAMES:
        with pytest.raises(Exception):
            SettingsUpdate.model_validate({field: status_value})


@given(status_value=st.text(max_size=24))
def test_property_transition_status_is_only_write_and_constrained(status_value):
    """Property 19 (Account_Status, R7.1/R7.4): the sole write path is constrained.

    ``transition_status`` is the only server-side ``Account_Status`` write. It
    accepts exactly the ``Account_Status`` value set: a valid member is applied,
    and any string outside the set is rejected with :class:`ValidationError`,
    leaving the authoritative status unchanged.

    Feature: foundation-auth-couples, Property 19.
    **Validates: Requirements 7.4**
    """
    users = _FakeUserRepository()
    user = users.add_user(_make_user(status=Account_Status.ACTIVE))
    svc, *_ = _service(users=users)

    valid_values = {s.value for s in Account_Status}
    if status_value in valid_values:
        svc.transition_status(user.id, status_value, reason="server_op")  # type: ignore[arg-type]
        assert user.status == Account_Status(status_value)
    else:
        with pytest.raises(ValidationError):
            svc.transition_status(user.id, status_value, reason="bad")  # type: ignore[arg-type]
        assert user.status == Account_Status.ACTIVE


# ---------------------------------------------------------------------------
# Property 19 — Couple_Status half (R13.7)
#
# CoupleService (task 9) is not yet implemented, so the disconnect/create-flow
# rejection of a client-supplied Couple_Status is DEFERRED until 9.x lands (add
# it to this file then). What exists today is asserted: there is no
# client-writable DTO/field that accepts a Couple_Status, and the Couple model's
# status is server-controlled (defaults to PENDING).
# ---------------------------------------------------------------------------


def test_couple_status_has_no_client_writable_schema_field():
    """Property 19 (Couple_Status, R13.7): no client-writable DTO accepts a status.

    Couple lifecycle is server-controlled. R13.7 requires that a client cannot
    *set* ``Couple_Status``: there must be no client-writable **request/input**
    schema that accepts a client-supplied ``Couple_Status``. A read-only
    **response projection** that merely *exposes* the server-controlled status so
    a caller can render it (e.g. :class:`~app.couples.schemas.CoupleView`, built
    from an ORM row via ``from_attributes``) is expected and is **not** a
    violation — it is an output, never an input the client fills in.

    This test therefore distinguishes the two:

    * **Request/input schemas** (``model_config`` without ``from_attributes``):
      these are what a client constructs and sends, so a ``status`` /
      ``couple_status`` field here would be a genuine R13.7 violation. Assert
      none exists.
    * **Response projections** (``model_config`` with ``from_attributes=True``):
      exempt from the "no status field" rule because they are outputs. But we
      still assert they are read-only projections — validated from a server-side
      ORM row, not driven by a client-supplied ``status`` value — so a response
      view can never be repurposed as a lever to override server state.

    NOTE: the disconnect/create-flow assertions (CoupleService ignoring a
    client-supplied Couple_Status) are deferred until task 9.x implements
    ``CoupleService``.

    Feature: foundation-auth-couples, Property 19.
    **Validates: Requirements 13.7**
    """
    from pydantic import BaseModel

    status_field_names = {"status", "couple_status"}

    def _is_response_projection(model: type[BaseModel]) -> bool:
        # A response/output projection is populated from a server-side ORM row
        # (from_attributes=True) rather than from a client-supplied payload.
        return bool(getattr(model, "model_config", {}).get("from_attributes"))

    models = [
        obj
        for _name, obj in inspect.getmembers(couple_schemas, inspect.isclass)
        if issubclass(obj, BaseModel) and obj is not BaseModel
    ]

    # --- Request/input schemas must never declare a settable status field. ---
    # If a future task adds a create/update request DTO with a `status` /
    # `couple_status` field (i.e. a schema WITHOUT from_attributes), this catches
    # it — the property still fails on a genuine client-writable status lever.
    offending: list[str] = []
    for model in models:
        if _is_response_projection(model):
            continue  # outputs are exempt; asserted separately below
        for field_name in getattr(model, "model_fields", {}):
            if field_name in status_field_names:
                offending.append(f"{model.__name__}.{field_name}")

    assert offending == [], (
        "A couples request/input schema exposes a client-writable Couple_Status "
        f"field: {offending}. Couple_Status is server-controlled (R13.7) and must "
        "not be settable through a client-supplied request payload."
    )

    # --- Response projections that expose status must be read-only outputs. ---
    # Exposing the server-controlled status for rendering is fine; what R13.7
    # forbids is a client *setting* it. Assert every projection carrying a status
    # field is built from an ORM row (from_attributes) — i.e. it is an output
    # view, not a request the client fills in.
    for model in models:
        exposes_status = any(
            field_name in status_field_names
            for field_name in getattr(model, "model_fields", {})
        )
        if not exposes_status:
            continue
        assert _is_response_projection(model), (
            f"{model.__name__} exposes a Couple_Status field but is not a "
            "read-only response projection (from_attributes=True). A schema that "
            "exposes status must be a server-built output, never a client input "
            "(R13.7)."
        )


def test_couple_status_is_server_controlled_default_pending():
    """Property 19 (Couple_Status, R13.7): a new Couple starts PENDING server-side.

    The ``Couple`` model's ``status`` is server-controlled: with no client input,
    a freshly constructed couple takes the server-side default ``PENDING``. Only
    server-side lifecycle operations (CoupleService, task 9) move it onward.

    Feature: foundation-auth-couples, Property 19.
    **Validates: Requirements 13.7**
    """
    couple = Couple()
    # SQLAlchemy applies the column default on flush; the mapped default is the
    # server-controlled PENDING starting state.
    default = Couple.__table__.c.status.default
    assert default is not None
    assert default.arg == Couple_Status.PENDING
    # No client ever supplies status: the attribute is unset until the server
    # default is applied (i.e. it is not driven by a client-provided value).
    assert getattr(couple, "status", None) in (None, Couple_Status.PENDING)
