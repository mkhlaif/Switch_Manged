"""Append-only audit log (§37), enforced by the database itself.

UPDATE, DELETE (and on PostgreSQL TRUNCATE) of ``audit_logs`` rows are rejected by triggers, so
not even a bug or a compromised application code path can rewrite history. The same statements
are used by the Alembic migration (production) and by ``metadata.create_all`` (tests).

Note: the database owner can still drop the triggers; run the application with a database role
that does not own the schema if that threat matters (see docs/SECURITY.md).
"""

from __future__ import annotations

_PG_FUNCTION = """
CREATE OR REPLACE FUNCTION audit_logs_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only';
END;
$$ LANGUAGE plpgsql
"""

_CREATE = {
    "postgresql": [
        _PG_FUNCTION,
        "CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only()",
        "CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only()",
    ],
    "sqlite": [
        "CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs "
        "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END",
        "CREATE TRIGGER audit_logs_no_delete BEFORE DELETE ON audit_logs "
        "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END",
    ],
}

_DROP = {
    "postgresql": [
        "DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs",
        "DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs",
        "DROP FUNCTION IF EXISTS audit_logs_append_only()",
    ],
    "sqlite": [
        "DROP TRIGGER IF EXISTS audit_logs_no_update",
        "DROP TRIGGER IF EXISTS audit_logs_no_delete",
    ],
}


def create_statements(dialect: str) -> list[str]:
    return list(_CREATE.get(dialect, []))


def drop_statements(dialect: str) -> list[str]:
    return list(_DROP.get(dialect, []))


def attach(table) -> None:
    """Create the triggers whenever the table is created through SQLAlchemy metadata."""
    from sqlalchemy import DDL, event

    for dialect, statements in _CREATE.items():
        for stmt in statements:
            event.listen(table, "after_create", DDL(stmt).execute_if(dialect=dialect))
