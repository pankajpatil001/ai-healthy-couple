"""base

Empty base revision establishing the migration baseline. Table definitions for
User, Couple, CoupleMember, CoupleInvitation, PrivateReflection, AuditEvent, and
DataDeletionRequest are authored in task 2.x on top of this revision.

Revision ID: 0001_base
Revises:
Create Date: 2026-08-30 19:04:21.659589

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001_base'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
