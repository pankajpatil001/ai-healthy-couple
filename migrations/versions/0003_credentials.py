"""credentials table — production application-managed Argon2id auth (Phase 2)

Additive, backward-compatible migration on top of the Foundation schema. Adds a
single ``credentials`` table that stores only the Argon2id **hash** for each
``auth_identifier`` (the plaintext is never persisted). Credential material is
kept isolated from the ``users`` account/profile row, preserving the
"credentials live with the identity provider, not the User row" boundary while
the provider becomes application-managed (08-technology-stack.md §9).

No existing table is altered; no data is migrated. Development accounts created
under the previous in-memory provider have no row here and must re-register
(documented in the migration/rollback strategy) — production is greenfield.

Revision ID: 0003_credentials
Revises: 0002_foundation_schema
Create Date: 2026-09-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0003_credentials"
down_revision: Union[str, None] = "0002_foundation_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "credentials",
        # One credential per identifier; the identifier is the shared coordinate
        # with the users table and the sole key the identity provider addresses.
        sa.Column("auth_identifier", sa.String(length=320), nullable=False),
        # Full Argon2id encoded hash (embeds version, params, and salt). Never
        # the plaintext.
        sa.Column("password_hash", sa.String(length=512), nullable=False),
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
        sa.PrimaryKeyConstraint("auth_identifier", name="pk_credentials"),
    )


def downgrade() -> None:
    op.drop_table("credentials")
