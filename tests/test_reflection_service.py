"""Unit tests for ReflectionService (no PostgreSQL/Redis required).

These prove the service's orchestration contract with in-memory fakes:

* authorize-FIRST: an unauthorized caller never causes decryption;
* owner-only read/update/delete map non-owner/missing to a privacy-safe 404;
* create validates an optional couple_id as context only;
* deletion is soft (ciphertext cleared) and non-resurrecting;
* audit events are recorded and content-free.

End-to-end encryption-in-DB and the real authorization pipeline are covered by
the API/integration tests (test_api_reflections.py).
"""

from __future__ import annotations

import base64
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest

from app.authorization.models import Action, AuthenticatedActor
from app.crypto.encryption import ContentCipher, _secret_name_for_key_id
from app.enums import Account_Status, Visibility_Scope
from app.errors import ResourceNotFoundError
from app.reflections.repository import ReflectionRepository
from app.reflections.schemas import ReflectionCreate, ReflectionUpdate
from app.reflections.service import (
    REFLECTION_CREATED_EVENT,
    REFLECTION_DELETED_EVENT,
    REFLECTION_READ_EVENT,
    REFLECTION_UPDATED_EVENT,
    ReflectionService,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


def _now():
    return datetime.now(timezone.utc)


class _DictSecrets:
    def __init__(self, secrets):
        self._secrets = secrets

    def get_secret(self, name):
        from app.config import SecretNotFoundError

        try:
            return self._secrets[name]
        except KeyError as exc:
            raise SecretNotFoundError(name) from exc

    def try_get_secret(self, name):
        return self._secrets.get(name)


def _cipher(key_id="reflection-v1"):
    key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    return ContentCipher(
        active_key_id=key_id,
        secrets_provider=_DictSecrets({_secret_name_for_key_id(key_id): key}),
    )


@dataclass
class _FakeRow:
    """Stand-in for a PrivateReflection ORM row."""

    id: uuid.UUID
    user_id: uuid.UUID
    couple_id: uuid.UUID | None
    visibility_scope: Visibility_Scope
    content_ciphertext: str | None
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)
    deleted_at: datetime | None = None


class FakeReflectionRepository:
    """In-memory reflection repo using a real cipher for encrypt/decrypt."""

    def __init__(self, cipher: ContentCipher) -> None:
        self._cipher = cipher
        self.rows: dict[uuid.UUID, _FakeRow] = {}
        self.decrypt_calls: list[uuid.UUID] = []

    def create(self, *, owner_id, plaintext, couple_id=None):
        row = _FakeRow(
            id=uuid.uuid4(),
            user_id=owner_id,
            couple_id=couple_id,
            visibility_scope=Visibility_Scope.PRIVATE_PARTNER,
            content_ciphertext=self._cipher.encrypt(plaintext),
        )
        self.rows[row.id] = row
        return row

    def get_active_row(self, reflection_id):
        row = self.rows.get(reflection_id)
        if row is None or row.deleted_at is not None:
            return None
        return row

    def list_for_owner(self, owner_id):
        # Mirrors the real repo: owner-scoped, non-deleted, newest-first.
        rows = [
            r for r in self.rows.values()
            if r.user_id == owner_id and r.deleted_at is None
        ]
        return sorted(rows, key=lambda r: r.created_at, reverse=True)

    def decrypt_content(self, row):
        self.decrypt_calls.append(row.id)
        if not row.content_ciphertext:
            return ""
        return self._cipher.decrypt(row.content_ciphertext)

    def update_content(self, row, *, plaintext):
        row.content_ciphertext = self._cipher.encrypt(plaintext)
        row.updated_at = _now()
        return row

    def soft_delete(self, row):
        row.deleted_at = _now()
        row.content_ciphertext = None
        return row


class FakeAuthorizedRepository:
    """Owner-only resolver mirroring AuthorizedRepository.get_private_reflection.

    Returns the row only if it exists (not soft-deleted) AND the actor owns it;
    otherwise ``None`` (missing and unauthorized indistinguishable).
    """

    def __init__(self, reflection_repo: FakeReflectionRepository) -> None:
        self._repo = reflection_repo

    def get_private_reflection(self, actor, reflection_id, action=Action.READ):
        # Mirrors the REAL AuthorizedRepository: it resolves by id and applies
        # only the owner-only decision — it is deletion-agnostic (does NOT filter
        # soft-deleted rows). The service is responsible for the deleted-row
        # check, so the fake must surface tombstones too, otherwise the tests
        # would not exercise that logic.
        row = self._repo.rows.get(reflection_id)
        if row is None:
            return None
        if row.user_id != actor.user_id:
            return None
        return row


class FakeCoupleRepository:
    def __init__(self) -> None:
        self.active_memberships: set[tuple[uuid.UUID, uuid.UUID]] = set()

    def get_active_membership(self, couple_id, user_id):
        return (
            object() if (couple_id, user_id) in self.active_memberships else None
        )


@dataclass
class _AuditRecord:
    event_type: str
    actor_id: uuid.UUID | None
    resource_id: uuid.UUID | None
    outcome: str
    metadata: dict | None


class FakeAudit:
    def __init__(self) -> None:
        self.records: list[_AuditRecord] = []

    def record(self, *, actor_type, actor_id, event_type, resource_type,
               resource_id, outcome, request_id=None, metadata=None):
        self.records.append(
            _AuditRecord(event_type, actor_id, resource_id, outcome, metadata)
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def wiring():
    cipher = _cipher()
    refl_repo = FakeReflectionRepository(cipher)
    authz_repo = FakeAuthorizedRepository(refl_repo)
    couples = FakeCoupleRepository()
    audit = FakeAudit()
    service = ReflectionService(
        reflection_repository=refl_repo,
        authorized_repository=authz_repo,
        couple_repository=couples,
        audit_service=audit,
    )
    return service, refl_repo, couples, audit


def _actor(user_id=None):
    return AuthenticatedActor(
        user_id=user_id or uuid.uuid4(), account_status=Account_Status.ACTIVE
    )


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


def test_create_reflection_owner_and_encrypts(wiring):
    service, refl_repo, _, audit = wiring
    actor = _actor()
    view = service.create_reflection(actor, ReflectionCreate(content="hello world"))
    assert view.content == "hello world"
    row = refl_repo.rows[view.id]
    assert row.user_id == actor.user_id
    assert row.visibility_scope == Visibility_Scope.PRIVATE_PARTNER
    # Stored value is ciphertext, not plaintext.
    assert row.content_ciphertext and "hello world" not in row.content_ciphertext
    assert audit.records[-1].event_type == REFLECTION_CREATED_EVENT


def test_create_with_valid_couple_id_is_context_only(wiring):
    service, refl_repo, couples, _ = wiring
    actor = _actor()
    couple_id = uuid.uuid4()
    couples.active_memberships.add((couple_id, actor.user_id))
    view = service.create_reflection(
        actor, ReflectionCreate(content="note", couple_id=couple_id)
    )
    row = refl_repo.rows[view.id]
    assert row.couple_id == couple_id
    # couple_id does NOT change visibility.
    assert row.visibility_scope == Visibility_Scope.PRIVATE_PARTNER


def test_create_with_couple_id_non_member_is_privacy_safe_404(wiring):
    service, _, _, _ = wiring
    actor = _actor()
    with pytest.raises(ResourceNotFoundError):
        service.create_reflection(
            actor, ReflectionCreate(content="note", couple_id=uuid.uuid4())
        )


# ---------------------------------------------------------------------------
# List (owner-only, metadata only)
# ---------------------------------------------------------------------------


def test_list_returns_only_owner_reflections(wiring):
    service, _, _, _ = wiring
    owner = _actor()
    other = _actor()
    service.create_reflection(owner, ReflectionCreate(content="mine 1"))
    service.create_reflection(owner, ReflectionCreate(content="mine 2"))
    service.create_reflection(other, ReflectionCreate(content="theirs"))

    owner_list = service.list_reflections(owner)
    assert len(owner_list) == 2
    other_list = service.list_reflections(other)
    assert len(other_list) == 1
    # No id overlap between the two owners' lists.
    assert {s.id for s in owner_list}.isdisjoint({s.id for s in other_list})


def test_list_excludes_deleted(wiring):
    service, _, _, _ = wiring
    owner = _actor()
    a = service.create_reflection(owner, ReflectionCreate(content="keep"))
    b = service.create_reflection(owner, ReflectionCreate(content="remove"))
    service.delete_reflection(owner, b.id)

    ids = {s.id for s in service.list_reflections(owner)}
    assert a.id in ids
    assert b.id not in ids


def test_list_is_metadata_only_no_decryption(wiring):
    service, refl_repo, _, _ = wiring
    owner = _actor()
    service.create_reflection(owner, ReflectionCreate(content="secret"))
    refl_repo.decrypt_calls.clear()
    summaries = service.list_reflections(owner)
    # Summaries carry no content field and listing never decrypts.
    assert refl_repo.decrypt_calls == []
    assert not hasattr(summaries[0], "content")


def test_list_empty_for_new_user(wiring):
    service, _, _, _ = wiring
    assert service.list_reflections(_actor()) == []


def test_multiple_reflections_created_and_each_retrievable(wiring):
    service, _, _, _ = wiring
    owner = _actor()
    created = [
        service.create_reflection(owner, ReflectionCreate(content=f"note {i}"))
        for i in range(3)
    ]
    listed_ids = {s.id for s in service.list_reflections(owner)}
    assert listed_ids == {c.id for c in created}
    for c in created:
        assert service.get_reflection(owner, c.id).content.startswith("note ")


# ---------------------------------------------------------------------------
# Read / owner-only
# ---------------------------------------------------------------------------


def test_owner_can_read_own(wiring):
    service, _, _, _ = wiring
    actor = _actor()
    created = service.create_reflection(actor, ReflectionCreate(content="secret"))
    got = service.get_reflection(actor, created.id)
    assert got.content == "secret"


def test_partner_cannot_read_and_no_decryption(wiring):
    service, refl_repo, _, _ = wiring
    owner = _actor()
    created = service.create_reflection(owner, ReflectionCreate(content="secret"))
    refl_repo.decrypt_calls.clear()
    partner = _actor()
    with pytest.raises(ResourceNotFoundError):
        service.get_reflection(partner, created.id)
    # CRITICAL: unauthorized caller must NOT cause decryption.
    assert refl_repo.decrypt_calls == []


def test_read_missing_is_404(wiring):
    service, _, _, _ = wiring
    with pytest.raises(ResourceNotFoundError):
        service.get_reflection(_actor(), uuid.uuid4())


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


def test_owner_can_update(wiring):
    service, refl_repo, _, _ = wiring
    actor = _actor()
    created = service.create_reflection(actor, ReflectionCreate(content="v1"))
    updated = service.update_reflection(
        actor, created.id, ReflectionUpdate(content="v2")
    )
    assert updated.content == "v2"
    assert service.get_reflection(actor, created.id).content == "v2"


def test_partner_cannot_update(wiring):
    service, _, _, _ = wiring
    owner = _actor()
    created = service.create_reflection(owner, ReflectionCreate(content="v1"))
    with pytest.raises(ResourceNotFoundError):
        service.update_reflection(
            _actor(), created.id, ReflectionUpdate(content="hacked")
        )
    # Owner's content unchanged.
    assert service.get_reflection(owner, created.id).content == "v1"


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


def test_delete_clears_ciphertext_and_prevents_retrieval(wiring):
    service, refl_repo, _, audit = wiring
    actor = _actor()
    created = service.create_reflection(actor, ReflectionCreate(content="secret"))
    service.delete_reflection(actor, created.id)
    row = refl_repo.rows[created.id]
    assert row.deleted_at is not None
    assert row.content_ciphertext is None  # ciphertext cleared
    # GET after delete -> 404.
    with pytest.raises(ResourceNotFoundError):
        service.get_reflection(actor, created.id)
    assert audit.records[-1].event_type == REFLECTION_DELETED_EVENT


def test_repeated_delete_is_safe(wiring):
    service, _, _, _ = wiring
    actor = _actor()
    created = service.create_reflection(actor, ReflectionCreate(content="x"))
    service.delete_reflection(actor, created.id)
    with pytest.raises(ResourceNotFoundError):
        service.delete_reflection(actor, created.id)


def test_update_cannot_resurrect_deleted(wiring):
    service, _, _, _ = wiring
    actor = _actor()
    created = service.create_reflection(actor, ReflectionCreate(content="x"))
    service.delete_reflection(actor, created.id)
    with pytest.raises(ResourceNotFoundError):
        service.update_reflection(actor, created.id, ReflectionUpdate(content="back"))


def test_partner_cannot_delete(wiring):
    service, _, _, _ = wiring
    owner = _actor()
    created = service.create_reflection(owner, ReflectionCreate(content="x"))
    with pytest.raises(ResourceNotFoundError):
        service.delete_reflection(_actor(), created.id)
    # Still readable by owner.
    assert service.get_reflection(owner, created.id).content == "x"


# ---------------------------------------------------------------------------
# Audit is content-free
# ---------------------------------------------------------------------------


def test_audit_never_contains_plaintext(wiring):
    service, _, _, audit = wiring
    actor = _actor()
    plaintext = "VERY-PRIVATE-REFLECTION-TEXT"
    created = service.create_reflection(actor, ReflectionCreate(content=plaintext))
    service.get_reflection(actor, created.id)
    service.update_reflection(actor, created.id, ReflectionUpdate(content=plaintext))
    service.delete_reflection(actor, created.id)
    for rec in audit.records:
        assert plaintext not in str(rec.metadata)
        assert rec.resource_id is not None  # id is a UUID, not content
