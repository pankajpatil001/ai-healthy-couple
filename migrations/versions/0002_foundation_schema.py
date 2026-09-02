"""foundation schema — tables, constraints, and indexes

Creates the full Foundation schema on top of the empty ``0001_base`` baseline:
the seven tables (``users``, ``data_deletion_requests``, ``couples``,
``couple_members``, ``couple_invitations``, ``private_reflections``,
``audit_events``) together with the constraints and indexes that enforce the
core invariants (design.md "Constraints and immutability", 02-database-schema.md
§35–§37):

- **Unique auth identifier** on ``users.auth_identifier`` — rejects duplicate
  registration (R1.2).
- **``UNIQUE(couple_id, user_id)``** on ``couple_members`` — one membership row
  per user per couple.
- **Partial unique index** on ``couple_members(user_id) WHERE status = 'ACTIVE'``
  — at most one ACTIVE couple per user; also blocks the accept-side race
  (R9.2/R9.3/R11.2).
- **Unique ``token_hash``** on ``couple_invitations`` — one invitation per token;
  the raw token is never stored (R10.1, R10.3).

Immutability of ``private_reflections.user_id`` (the owner / Pattern A key) and
``couple_members.role`` is a **behavioral** invariant enforced by the service
layer and review, not by a column constraint (roles/ownership are simply never
updated in this slice; 06-authorization-matrix.md §8, §20). It is documented
here so the guarantee is discoverable from the schema history; no DDL enforces
it because there is no product path that mutates these columns.

Revision ID: 0002_foundation_schema
Revises: 0001_base
Create Date: 2026-08-30 19:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "0002_foundation_schema"
down_revision: Union[str, None] = "0001_base"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ---------------------------------------------------------------------------
# Enum types (app.enums). Declared once with create_type=False so we control
# CREATE TYPE / DROP TYPE explicitly and never emit them twice when reused
# across columns.
# ---------------------------------------------------------------------------
account_status = postgresql.ENUM(
    "ACTIVE", "SUSPENDED", "DELETED", name="account_status", create_type=False
)
deletion_status = postgresql.ENUM(
    "REQUESTED",
    "PROCESSING",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
    name="deletion_status",
    create_type=False,
)
couple_status = postgresql.ENUM(
    "PENDING", "ACTIVE", "DISCONNECTED", name="couple_status", create_type=False
)
member_role = postgresql.ENUM(
    "PARTNER_A", "PARTNER_B", name="member_role", create_type=False
)
member_status = postgresql.ENUM(
    "ACTIVE", "DISCONNECTED", name="member_status", create_type=False
)
invitation_status = postgresql.ENUM(
    "PENDING",
    "ACCEPTED",
    "DECLINED",
    "EXPIRED",
    "REVOKED",
    name="invitation_status",
    create_type=False,
)
visibility_scope = postgresql.ENUM(
    "PRIVATE_PARTNER",
    "SHARED_COUPLE",
    "PROFESSIONAL_SHARED",
    "SYSTEM_ONLY",
    name="visibility_scope",
    create_type=False,
)

_ENUMS = (
    account_status,
    deletion_status,
    couple_status,
    member_role,
    member_status,
    invitation_status,
    visibility_scope,
)


def upgrade() -> None:
    bind = op.get_bind()

    # Create enum types up front so every table can reference them by name.
    for enum in _ENUMS:
        enum.create(bind, checkfirst=True)

    # --- users -------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("auth_identifier", sa.String(length=320), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("locale", sa.String(length=35), nullable=True),
        sa.Column("timezone", sa.String(length=64), nullable=True),
        sa.Column("status", account_status, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        # R1.2: unique auth identifier rejects duplicate registration.
        sa.UniqueConstraint("auth_identifier", name="uq_users_auth_identifier"),
    )

    # --- data_deletion_requests -------------------------------------------
    op.create_table(
        "data_deletion_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope", sa.String(length=64), nullable=False),
        sa.Column("status", deletion_status, nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.String(length=512), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_data_deletion_requests"),
    )
    op.create_index(
        "ix_data_deletion_requests_user_id",
        "data_deletion_requests",
        ["user_id"],
    )

    # --- couples -----------------------------------------------------------
    op.create_table(
        "couples",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", couple_status, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disconnected_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_couples"),
    )

    # --- couple_members ----------------------------------------------------
    # role is IMMUTABLE once assigned (behavioral invariant; no product path
    # updates it — 06-authorization-matrix.md §8, §20).
    op.create_table(
        "couple_members",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("couple_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", member_role, nullable=False),
        sa.Column("status", member_status, nullable=False),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("left_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_couple_members"),
        # One membership row per user per couple.
        sa.UniqueConstraint(
            "couple_id", "user_id", name="uq_couple_members_couple_id_user_id"
        ),
    )
    op.create_index(
        "ix_couple_members_couple_id", "couple_members", ["couple_id"]
    )
    op.create_index("ix_couple_members_user_id", "couple_members", ["user_id"])
    # At-most-one-ACTIVE-couple per user (R9.2/R9.3) and DB-level guard against
    # the accept-side race (R11.2): unique on user_id filtered to ACTIVE rows.
    op.create_index(
        "uq_couple_members_active_user",
        "couple_members",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("status = 'ACTIVE'"),
    )

    # --- couple_invitations ------------------------------------------------
    op.create_table(
        "couple_invitations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("couple_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("inviter_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("invitee_identifier", sa.String(length=320), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("status", invitation_status, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("declined_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_couple_invitations"),
    )
    op.create_index(
        "ix_couple_invitations_couple_id", "couple_invitations", ["couple_id"]
    )
    # One invitation per token; only the secure hash is ever stored (R10.1, R10.3).
    op.create_index(
        "uq_couple_invitations_token_hash",
        "couple_invitations",
        ["token_hash"],
        unique=True,
    )

    # --- private_reflections ----------------------------------------------
    # user_id is the IMMUTABLE owner (Pattern A authorization key). Ownership is
    # never reassigned in this slice (behavioral invariant;
    # 06-authorization-matrix.md §8, §20). couple_id is context only and never
    # makes content shared (R16.4).
    op.create_table(
        "private_reflections",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("couple_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("visibility_scope", visibility_scope, nullable=False),
        sa.Column("content_ciphertext", sa.Text(), nullable=True),
        sa.Column("content_metadata", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_private_reflections"),
    )
    op.create_index(
        "ix_private_reflections_user_id", "private_reflections", ["user_id"]
    )
    op.create_index(
        "ix_private_reflections_couple_id", "private_reflections", ["couple_id"]
    )

    # --- audit_events ------------------------------------------------------
    # The ORM attribute is event_metadata; the column is "metadata".
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=True),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
    )


def downgrade() -> None:
    bind = op.get_bind()

    op.drop_table("audit_events")

    op.drop_index("ix_private_reflections_couple_id", table_name="private_reflections")
    op.drop_index("ix_private_reflections_user_id", table_name="private_reflections")
    op.drop_table("private_reflections")

    op.drop_index(
        "uq_couple_invitations_token_hash", table_name="couple_invitations"
    )
    op.drop_index(
        "ix_couple_invitations_couple_id", table_name="couple_invitations"
    )
    op.drop_table("couple_invitations")

    op.drop_index("uq_couple_members_active_user", table_name="couple_members")
    op.drop_index("ix_couple_members_user_id", table_name="couple_members")
    op.drop_index("ix_couple_members_couple_id", table_name="couple_members")
    op.drop_table("couple_members")

    op.drop_table("couples")

    op.drop_index(
        "ix_data_deletion_requests_user_id", table_name="data_deletion_requests"
    )
    op.drop_table("data_deletion_requests")

    op.drop_table("users")

    # Drop enum types last, after all dependent columns are gone.
    for enum in reversed(_ENUMS):
        enum.drop(bind, checkfirst=True)
