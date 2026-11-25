"""Add documents.size_bytes, counted against each user's quota (O3 fix).

Existing rows get 0: the init container that runs migrations does not mount
the documents volume, so it cannot measure files uploaded before this change.

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "documents",
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("documents", "size_bytes")
