"""add machine table

Revision ID: 311be9937d3e
Revises: 1c1d18482b62
Create Date: 2023-09-28 12:04:49.205816

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "311be9937d3e"
down_revision: str | None = "1c1d18482b62"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "machines",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "created_at", sa.DateTime, server_default=sa.text("(STRFTIME('%s'))")
        ),
        sa.Column("dmi_sys_vendor", sa.Text),
        sa.Column("dmi_product_uuid", sa.Text),
        sa.Column("dmi_product_serial", sa.Text),
        sa.Column("dmi_board_asset_tag", sa.Text),
        sa.Column("os", sa.Text),
        sa.Column("architecture", sa.Text),
        sa.Column("cpu_model", sa.Text),
        sa.Column("mem_total_bytes", sa.Integer),
    )

    op.add_column("jobs", sa.Column("machine_id", sa.Integer))


def downgrade() -> None:
    op.drop_column("jobs", "machine_id")
    op.drop_table("machines")
