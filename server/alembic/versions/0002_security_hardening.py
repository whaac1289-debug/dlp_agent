"""security hardening updates

Revision ID: 0002_security_hardening
Revises: 0001_initial
Create Date: 2024-10-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
import uuid

revision = "0002_security_hardening"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("events", sa.Column("event_id", sa.String(length=64), nullable=True))
    connection = op.get_bind()
    events = connection.execute(sa.text("SELECT id FROM events")).fetchall()
    for row in events:
        connection.execute(
            sa.text("UPDATE events SET event_id = :event_id WHERE id = :id"),
            {"event_id": str(uuid.uuid4()), "id": row[0]},
        )
    op.alter_column("events", "event_id", nullable=False)
    op.create_unique_constraint("uq_events_event_id", "events", ["event_id"])
    op.create_index("ix_events_event_id", "events", ["event_id"])

    op.add_column("policy_rules", sa.Column("keywords", sa.JSON(), nullable=True))
    op.add_column("policy_rules", sa.Column("hashes", sa.JSON(), nullable=True))
    op.add_column("policy_rules", sa.Column("severity_score", sa.Integer(), nullable=True))
    op.add_column("policy_rules", sa.Column("tags", sa.JSON(), nullable=True))
    op.add_column("policy_rules", sa.Column("is_whitelist", sa.Boolean(), nullable=True))

    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("agent_uuid", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
    )
    op.create_index("ix_enrollment_tokens_token_hash", "enrollment_tokens", ["token_hash"], unique=True)


def downgrade():
    op.drop_index("ix_enrollment_tokens_token_hash", table_name="enrollment_tokens")
    op.drop_table("enrollment_tokens")
    op.drop_column("policy_rules", "is_whitelist")
    op.drop_column("policy_rules", "tags")
    op.drop_column("policy_rules", "severity_score")
    op.drop_column("policy_rules", "hashes")
    op.drop_column("policy_rules", "keywords")
    op.drop_index("ix_events_event_id", table_name="events")
    op.drop_constraint("uq_events_event_id", "events", type_="unique")
    op.drop_column("events", "event_id")
