"""create initial tables

Revision ID: 34f3f58772c9
Revises:
Create Date: 2023-09-19 15:57:50.204309

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "34f3f58772c9"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "zeek_tests",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("ts", sa.DateTime, server_default=sa.text("(STRFTIME('%s'))")),
        sa.Column("job_id", sa.Text, nullable=False, index=True),
        sa.Column("test_id", sa.Text, nullable=False),
        sa.Column("test_run", sa.Integer, nullable=False),
        sa.Column("elapsed_time", sa.Float, nullable=True),
        sa.Column("user_time", sa.Float, nullable=True),
        sa.Column("system_time", sa.Float, nullable=True),
        sa.Column("max_rss", sa.Float, nullable=True),
        sa.Column("sha", sa.Text, nullable=True),
        sa.Column("branch", sa.Text, nullable=True),
        sa.Column("success", sa.Boolean, nullable=False),
        sa.Column("error", sa.Text, nullable=True),
    )

    op.create_table(
        "jobs",
        sa.Column("id", sa.Text, primary_key=True, nullable=False),
        sa.Column("ts", sa.DateTime, server_default=sa.text("(STRFTIME('%s'))")),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("build_url", sa.Text, nullable=False),
        sa.Column("build_hash", sa.Text, nullable=False),
        sa.Column("sha", sa.Text, nullable=False),
        sa.Column("branch", sa.Text, nullable=False),  # sanitized version
        sa.Column("original_branch", sa.Text, nullable=False),
        sa.Column("cirrus_repo_owner", sa.Text),
        sa.Column("cirrus_repo_name", sa.Text),
        sa.Column("cirrus_task_id", sa.Integer),
        sa.Column("cirrus_build_id", sa.Integer),
        sa.Column("cirrus_pr", sa.Integer),
        sa.Column("cirrus_pr_labels", sa.Text),
        sa.Column("github_check_suite_id", sa.Integer),
        sa.Column("repo_version", sa.Text),
    )


def downgrade() -> None:
    op.drop_table("zeek_tests")
    op.drop_table("jobs")
