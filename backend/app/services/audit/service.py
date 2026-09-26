"""Audit trail: every administrative action is written to ``audit_logs`` and the AUDIT log level.

Details are passed through :func:`scrub` so secrets can never be persisted, even by mistake.
The table is append-only: the database rejects UPDATE and DELETE (migration 0003 triggers), and
the application never issues either.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger, log_audit, log_security
from app.models import AuditLog

log = get_logger("audit")

_SECRET_KEYS = {"password", "new_password", "current_password", "secret", "token",
                "host_key_private", "private_key", "api_token", "netbox_token", "zabbix_token"}


MAX_JSON_BYTES = 64_000


def _bounded(value: dict | None) -> dict | None:
    """Oversized details/state (e.g. a huge crafted value) are cut, never rejected: the audit
    entry itself must always be written."""
    if value is None:
        return None
    text = json.dumps(value, default=str)
    if len(text) <= MAX_JSON_BYTES:
        return value
    return {"truncated": True, "original_bytes": len(text), "preview": text[:MAX_JSON_BYTES // 2]}


def scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("***" if k.lower() in _SECRET_KEYS or "password" in k.lower() else scrub(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


async def record(
    db: AsyncSession,
    *,
    action: str,
    result: str,
    user: Any = None,
    username: str | None = None,
    message: str = "",
    target_type: str = "",
    target_id: str | int | None = None,
    target_label: str = "",
    mac: str = "",
    switch_name: str = "",
    port: str = "",
    details: dict | None = None,
    ip: str = "",
    severity: str = "INFO",
    commit: bool = True,
    role: str | None = None,
    operation: str = "",
    vlan: int | None = None,
    profile: str = "",
    fingerprint: str = "",
    risk_level: str = "",
    approval: str = "",
    error: str = "",
    before_state: dict | None = None,
    after_state: dict | None = None,
    site: str = "",
    profile_version: str = "",
    error_category: str = "",
    outcome: str = "",
) -> AuditLog:
    entry = AuditLog(
        user_id=getattr(user, "id", None),
        username=(username or getattr(user, "username", "") or "system")[:64],
        action=action[:48],
        result=result[:16],
        target_type=target_type[:32],
        target_id=(str(target_id) if target_id is not None else "")[:64],
        target_label=(target_label or "")[:255],
        mac=(mac or "")[:12],
        switch_name=(switch_name or "")[:128],
        port=(port or "")[:32],
        message=message[:1024],
        details=_bounded(scrub(details or {})),
        ip=(ip or "")[:64],
        severity=severity if severity in {"INFO", "WARNING", "HIGH", "CRITICAL"} else "INFO",
        role=(role if role is not None else str(getattr(user, "role", "") or ""))[:16],
        operation=operation[:32],
        vlan=vlan,
        profile=profile[:32],
        command_fingerprint=fingerprint[:64],
        risk_level=risk_level[:16],
        approval=approval[:128],
        error=error[:1024],
        before_state=_bounded(scrub(before_state)) if before_state is not None else None,
        after_state=_bounded(scrub(after_state)) if after_state is not None else None,
        site=(site or "")[:128],
        profile_version=(profile_version or "")[:16],
        error_category=(error_category or "")[:32],
        outcome=(outcome or "")[:24],
    )
    db.add(entry)
    if commit:
        await db.commit()
    line = "%s %s user=%s%s%s%s %s"
    args = (
        action, result, entry.username,
        f" switch={switch_name}" if switch_name else "",
        f" port={port}" if port else "",
        f" mac={mac}" if mac else "",
        message,
    )
    security = result in {"DENIED", "BLOCKED"} or action.startswith("LOGIN_FAILED")
    if security or entry.severity in {"HIGH", "CRITICAL"}:
        log_security(log, line, *args)
    else:
        log_audit(log, line, *args)
    return entry
