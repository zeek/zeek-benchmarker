"""add task name

Revision ID: 1c1d18482b62
Revises: 34f3f58772c9
Create Date: 2023-09-25 13:14:46.588072

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "1c1d18482b62"
down_revision: str | None = "34f3f58772c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("cirrus_task_name", sa.Text))


def downgrade() -> None:
    op.drop_column("jobs", "cirrus_task_name")
