"""automatic discovery, profile states, outcomes

* switches: identity read from the device (vendor, model, AOS version, system name /
  description / object id, discovery status, category, profile, time) and administrator
  metadata that is only compared with discovery (expected model / AOS version / host-key
  fingerprint); environment production | lab.
  DATA: model / AOS version entered by hand before this release become *expected* metadata;
  the switch is NOT_DISCOVERED until discovery reads the real values (fail closed: no
  state-changing operation before that).
* command_verifications: profile state LAB_VERIFIED | PRODUCTION_VERIFIED | BLOCKED |
  DEPRECATED (existing records → LAB_VERIFIED).
* port_actions / audit_logs: outcome, safe error category, profile version (+ site in audit).
* import_jobs: mode atomic | per_row, linked discovery job.
* discovery_jobs: background discovery.

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-26 21:11:22.147287
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
import app.db.base
from app.db.audit_guard import create_statements, drop_statements


revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def _recreate_switch_expression_indexes() -> None:
    """SQLite table rebuilds (batch mode) do not carry expression indexes over."""
    if op.get_bind().dialect.name != "sqlite":
        return
    op.execute("DROP INDEX IF EXISTS uq_switches_host_port")
    op.execute("DROP INDEX IF EXISTS uq_switches_name_lower")
    op.create_index('uq_switches_host_port', 'switches', [sa.text('lower(host)'), 'ssh_port'], unique=True)
    op.create_index('uq_switches_name_lower', 'switches', [sa.text('lower(name)')], unique=True)


def upgrade() -> None:
    op.create_table('discovery_jobs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_by_id', sa.Integer(), nullable=True),
    sa.Column('created_by', sa.String(length=64), nullable=False),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('switch_ids', sa.JSON(), nullable=False),
    sa.Column('total', sa.Integer(), nullable=False),
    sa.Column('processed', sa.Integer(), nullable=False),
    sa.Column('discovered', sa.Integer(), nullable=False),
    sa.Column('failed', sa.Integer(), nullable=False),
    sa.Column('mismatched', sa.Integer(), nullable=False),
    sa.Column('cancel_requested', sa.Boolean(), nullable=False),
    sa.Column('results', sa.JSON(), nullable=False),
    sa.Column('error', sa.Text(), nullable=False),
    sa.Column('created_at', app.db.base.UTCDateTime(timezone=True), nullable=False),
    sa.Column('started_at', app.db.base.UTCDateTime(timezone=True), nullable=True),
    sa.Column('completed_at', app.db.base.UTCDateTime(timezone=True), nullable=True),
    sa.Column('failed_at', app.db.base.UTCDateTime(timezone=True), nullable=True),
    sa.CheckConstraint("status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted')", name=op.f('ck_discovery_jobs_status_valid')),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_discovery_jobs_created_by_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_discovery_jobs'))
    )
    with op.batch_alter_table('discovery_jobs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_discovery_jobs_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_discovery_jobs_status'), ['status'], unique=False)

    # Only ADD COLUMN on the audit table (no rebuild): its append-only triggers stay in place.
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('site', sa.String(length=128), server_default='', nullable=False))
        batch_op.add_column(sa.Column('profile_version', sa.String(length=16), server_default='', nullable=False))
        batch_op.add_column(sa.Column('error_category', sa.String(length=32), server_default='', nullable=False))
        batch_op.add_column(sa.Column('outcome', sa.String(length=24), server_default='', nullable=False))

    with op.batch_alter_table('command_verifications', schema=None) as batch_op:
        batch_op.add_column(sa.Column('status', sa.String(length=20), server_default='LAB_VERIFIED', nullable=False))
        batch_op.add_column(sa.Column('status_changed_by', sa.String(length=64), server_default='', nullable=False))
        batch_op.add_column(sa.Column('status_changed_at', app.db.base.UTCDateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('status_reason', sa.Text(), server_default='', nullable=False))
        batch_op.create_check_constraint(op.f('ck_command_verifications_status_valid'), "status IN ('LAB_VERIFIED', 'PRODUCTION_VERIFIED', 'BLOCKED', 'DEPRECATED')")

    with op.batch_alter_table('import_jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('mode', sa.String(length=8), server_default='atomic', nullable=False))
        batch_op.add_column(sa.Column('discovery_job_id', sa.String(length=36), server_default='', nullable=False))
        batch_op.create_check_constraint(op.f('ck_import_jobs_mode_valid'), "mode IN ('atomic', 'per_row')")

    with op.batch_alter_table('mac_search_results', schema=None) as batch_op:
        batch_op.add_column(sa.Column('error_category', sa.String(length=32), server_default='', nullable=False))

    with op.batch_alter_table('port_actions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('outcome', sa.String(length=24), server_default='', nullable=False))
        batch_op.add_column(sa.Column('error_category', sa.String(length=32), server_default='', nullable=False))
        batch_op.add_column(sa.Column('profile_version', sa.String(length=16), server_default='', nullable=False))

    with op.batch_alter_table('switches', schema=None) as batch_op:
        batch_op.add_column(sa.Column('vendor', sa.String(length=16), server_default='', nullable=False))
        batch_op.add_column(sa.Column('discovery_status', sa.String(length=20), server_default='not_discovered', nullable=False))
        batch_op.add_column(sa.Column('discovery_error', sa.String(length=255), server_default='', nullable=False))
        batch_op.add_column(sa.Column('discovery_category', sa.String(length=32), server_default='', nullable=False))
        batch_op.add_column(sa.Column('discovery_profile', sa.String(length=32), server_default='', nullable=False))
        batch_op.add_column(sa.Column('discovered_at', app.db.base.UTCDateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('system_name', sa.String(length=128), server_default='', nullable=False))
        batch_op.add_column(sa.Column('system_description', sa.String(length=255), server_default='', nullable=False))
        batch_op.add_column(sa.Column('system_object_id', sa.String(length=64), server_default='', nullable=False))
        batch_op.add_column(sa.Column('expected_model', sa.String(length=64), server_default='', nullable=False))
        batch_op.add_column(sa.Column('expected_aos_version', sa.String(length=64), server_default='', nullable=False))
        batch_op.add_column(sa.Column('expected_host_key_fingerprint', sa.String(length=128), server_default='', nullable=False))
        batch_op.add_column(sa.Column('environment', sa.String(length=12), server_default='production', nullable=False))
        batch_op.create_check_constraint(op.f('ck_switches_discovery_status_valid'), "discovery_status IN ('not_discovered', 'discovered', 'discovery_failed', 'mismatch')")
        batch_op.create_check_constraint(op.f('ck_switches_environment_valid'), "environment IN ('production', 'lab')")
    _recreate_switch_expression_indexes()

    # Hand-entered identity becomes expected metadata; discovery must read the real values.
    op.execute("UPDATE switches SET expected_model = model, expected_aos_version = aos_version, "
               "model = '', aos_version = '', discovery_status = 'not_discovered'")


def downgrade() -> None:
    # Keep the last known identity usable by the previous version (it trusted these columns).
    op.execute("UPDATE switches SET model = expected_model WHERE model = ''")
    op.execute("UPDATE switches SET aos_version = expected_aos_version WHERE aos_version = ''")
    with op.batch_alter_table('switches', schema=None) as batch_op:
        batch_op.drop_constraint(op.f('ck_switches_environment_valid'), type_='check')
        batch_op.drop_constraint(op.f('ck_switches_discovery_status_valid'), type_='check')
        batch_op.drop_column('environment')
        batch_op.drop_column('expected_host_key_fingerprint')
        batch_op.drop_column('expected_aos_version')
        batch_op.drop_column('expected_model')
        batch_op.drop_column('system_object_id')
        batch_op.drop_column('system_description')
        batch_op.drop_column('system_name')
        batch_op.drop_column('discovered_at')
        batch_op.drop_column('discovery_profile')
        batch_op.drop_column('discovery_category')
        batch_op.drop_column('discovery_error')
        batch_op.drop_column('discovery_status')
        batch_op.drop_column('vendor')
    _recreate_switch_expression_indexes()

    with op.batch_alter_table('mac_search_results', schema=None) as batch_op:
        batch_op.drop_column('error_category')

    with op.batch_alter_table('port_actions', schema=None) as batch_op:
        batch_op.drop_column('profile_version')
        batch_op.drop_column('error_category')
        batch_op.drop_column('outcome')

    with op.batch_alter_table('import_jobs', schema=None) as batch_op:
        batch_op.drop_constraint(op.f('ck_import_jobs_mode_valid'), type_='check')
        batch_op.drop_column('discovery_job_id')
        batch_op.drop_column('mode')

    with op.batch_alter_table('command_verifications', schema=None) as batch_op:
        batch_op.drop_constraint(op.f('ck_command_verifications_status_valid'), type_='check')
        batch_op.drop_column('status_reason')
        batch_op.drop_column('status_changed_at')
        batch_op.drop_column('status_changed_by')
        batch_op.drop_column('status')

    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.drop_column('outcome')
        batch_op.drop_column('error_category')
        batch_op.drop_column('profile_version')
        batch_op.drop_column('site')
    # A SQLite rebuild of audit_logs drops its triggers: put the append-only guard back.
    if op.get_bind().dialect.name == "sqlite":
        for statement in drop_statements("sqlite") + create_statements("sqlite"):
            op.execute(statement)

    with op.batch_alter_table('discovery_jobs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_discovery_jobs_status'))
        batch_op.drop_index(batch_op.f('ix_discovery_jobs_created_at'))

    op.drop_table('discovery_jobs')
