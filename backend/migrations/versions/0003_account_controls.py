"""Account controls and a richer audit log.

- users.disabled: an administrator can disable an account.
- users.session_version: raising it revokes one user's sessions.
- audit_logs.ip and audit_logs.request_id: where a request came from, and
  the ID shared with the security events and the X-Request-ID header.

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users", sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    op.add_column(
        "users", sa.Column("session_version", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column("audit_logs", sa.Column("ip", sa.String(64), nullable=True))
    op.add_column("audit_logs", sa.Column("request_id", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_logs", "request_id")
    op.drop_column("audit_logs", "ip")
    op.drop_column("users", "session_version")
    op.drop_column("users", "disabled")
