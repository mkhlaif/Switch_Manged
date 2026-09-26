"""switch import and inventory constraints

* switches: hostname, site, port_locations (per-port human location shown to MAC_OPERATOR);
  UNIQUE (lower(host), ssh_port) and UNIQUE lower(name) (case-insensitive expression indexes);
  UNIQUE hostname when set; CHECK ssh_port range, role, transport.
* import_jobs: bulk switch import (validated preview → confirmation → background batches).
* mac_search_results: indexes on switch_id and (status, created_at).

Existing inventory data is never changed by this migration. If it violates a new constraint
(two entries for the same management address, an invalid role, ...), the upgrade stops with a
list of the rows to fix — nothing is renamed, merged or deleted automatically.

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-26 15:31:50.251945
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
import app.db.base


revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def _preflight() -> None:
    bind = op.get_bind()
    problems: list[str] = []
    for host, port, names in bind.execute(sa.text(
            "SELECT lower(host), ssh_port, COUNT(*) FROM switches GROUP BY lower(host), ssh_port "
            "HAVING COUNT(*) > 1")).all():
        problems.append(f"{names} switches share the management address {host}:{port}")
    for name, count in bind.execute(sa.text(
            "SELECT lower(name), COUNT(*) FROM switches GROUP BY lower(name) "
            "HAVING COUNT(*) > 1")).all():
        problems.append(f"{count} switches are named {name!r} (names must differ in more than "
                        "upper/lower case)")
    for name, port in bind.execute(sa.text(
            "SELECT name, ssh_port FROM switches WHERE ssh_port < 1 OR ssh_port > 65535")).all():
        problems.append(f"switch {name!r} has an invalid SSH port {port}")
    for name, role in bind.execute(sa.text(
            "SELECT name, role FROM switches WHERE role NOT IN "
            "('access', 'distribution', 'core', 'unknown')")).all():
        problems.append(f"switch {name!r} has an invalid role {role!r}")
    for name, transport in bind.execute(sa.text(
            "SELECT name, transport FROM switches WHERE transport NOT IN ('ssh', 'simulator')")).all():
        problems.append(f"switch {name!r} has an invalid transport {transport!r}")
    if problems:
        raise RuntimeError(
            "Migration 0004 stopped: the switch inventory violates the new integrity rules. "
            "Fix these switches (Switches page or an administrator SQL session), then start the "
            "application again. Nothing was changed. Problems: " + "; ".join(problems))


def upgrade() -> None:
    _preflight()
    op.create_table('import_jobs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('created_by_id', sa.Integer(), nullable=True),
    sa.Column('created_by', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('file_format', sa.String(length=8), nullable=False),
    sa.Column('filename', sa.String(length=255), nullable=False),
    sa.Column('file_sha256', sa.String(length=64), nullable=False),
    sa.Column('on_existing', sa.String(length=8), nullable=False),
    sa.Column('skip_invalid', sa.Boolean(), nullable=False),
    sa.Column('cancel_requested', sa.Boolean(), nullable=False),
    sa.Column('total', sa.Integer(), nullable=False),
    sa.Column('valid', sa.Integer(), nullable=False),
    sa.Column('invalid', sa.Integer(), nullable=False),
    sa.Column('duplicates', sa.Integer(), nullable=False),
    sa.Column('warnings', sa.Integer(), nullable=False),
    sa.Column('processed', sa.Integer(), nullable=False),
    sa.Column('imported', sa.Integer(), nullable=False),
    sa.Column('updated', sa.Integer(), nullable=False),
    sa.Column('unchanged', sa.Integer(), nullable=False),
    sa.Column('skipped', sa.Integer(), nullable=False),
    sa.Column('failed', sa.Integer(), nullable=False),
    sa.Column('file_errors', sa.JSON(), nullable=False),
    sa.Column('rows', sa.JSON(), nullable=False),
    sa.Column('error', sa.Text(), nullable=False),
    sa.Column('created_at', app.db.base.UTCDateTime(timezone=True), nullable=False),
    sa.Column('expires_at', app.db.base.UTCDateTime(timezone=True), nullable=True),
    sa.Column('confirmed_at', app.db.base.UTCDateTime(timezone=True), nullable=True),
    sa.Column('started_at', app.db.base.UTCDateTime(timezone=True), nullable=True),
    sa.Column('completed_at', app.db.base.UTCDateTime(timezone=True), nullable=True),
    sa.Column('failed_at', app.db.base.UTCDateTime(timezone=True), nullable=True),
    sa.CheckConstraint("file_format IN ('csv', 'json')", name=op.f('ck_import_jobs_format_valid')),
    sa.CheckConstraint("on_existing IN ('skip', 'update')", name=op.f('ck_import_jobs_on_existing_valid')),
    sa.CheckConstraint("status IN ('validated', 'queued', 'running', 'completed', 'failed', 'cancelled', 'expired', 'interrupted')", name=op.f('ck_import_jobs_status_valid')),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_import_jobs_created_by_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_import_jobs'))
    )
    with op.batch_alter_table('import_jobs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_import_jobs_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_import_jobs_status'), ['status'], unique=False)

    with op.batch_alter_table('switches', schema=None) as batch_op:
        batch_op.add_column(sa.Column('hostname', sa.String(length=255), server_default='', nullable=False))
        batch_op.add_column(sa.Column('site', sa.String(length=128), server_default='', nullable=False))
        batch_op.add_column(sa.Column('port_locations', sa.JSON(), server_default=sa.text("'{}'"), nullable=False))
        batch_op.create_index('uq_switches_hostname', ['hostname'], unique=True, postgresql_where=sa.text("hostname <> ''"), sqlite_where=sa.text("hostname <> ''"))
        batch_op.create_check_constraint(op.f('ck_switches_ssh_port_range'), "ssh_port BETWEEN 1 AND 65535")
        batch_op.create_check_constraint(op.f('ck_switches_role_valid'), "role IN ('access', 'distribution', 'core', 'unknown')")
        batch_op.create_check_constraint(op.f('ck_switches_transport_valid'), "transport IN ('ssh', 'simulator')")
    # Case-insensitive unique expression indexes, created AFTER the SQLite table rebuild above
    # (reflection-based batch rebuilds do not carry expression indexes over). A future batch
    # migration of this table must re-create them; tests/test_db_schema.py checks they exist.
    op.create_index('uq_switches_host_port', 'switches', [sa.text('lower(host)'), 'ssh_port'], unique=True)
    op.create_index('uq_switches_name_lower', 'switches', [sa.text('lower(name)')], unique=True)
    # mac_search_results grows by one row per switch per search (measured with 1M rows:
    # topology 76 ms, dashboard 123 ms, deleting one switch 180 ms without these indexes).
    op.create_index(op.f('ix_mac_search_results_switch_id'), 'mac_search_results', ['switch_id'], unique=False)
    op.create_index('ix_mac_search_results_status_created', 'mac_search_results', ['status', 'created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_mac_search_results_status_created', table_name='mac_search_results')
    op.drop_index(op.f('ix_mac_search_results_switch_id'), table_name='mac_search_results')
    op.drop_index('uq_switches_name_lower', table_name='switches')
    op.drop_index('uq_switches_host_port', table_name='switches')
    with op.batch_alter_table('switches', schema=None) as batch_op:
        batch_op.drop_constraint(op.f('ck_switches_transport_valid'), type_='check')
        batch_op.drop_constraint(op.f('ck_switches_role_valid'), type_='check')
        batch_op.drop_constraint(op.f('ck_switches_ssh_port_range'), type_='check')
        batch_op.drop_index('uq_switches_hostname', postgresql_where=sa.text("hostname <> ''"), sqlite_where=sa.text("hostname <> ''"))
        batch_op.drop_column('port_locations')
        batch_op.drop_column('site')
        batch_op.drop_column('hostname')

    with op.batch_alter_table('import_jobs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_import_jobs_status'))
        batch_op.drop_index(batch_op.f('ix_import_jobs_created_at'))

    op.drop_table('import_jobs')
