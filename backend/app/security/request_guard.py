"""ASGI guard: requests carrying command-like fields are rejected before routing.

The API is operation-based; no endpoint accepts CLI text. A JSON body containing a key such as
"command", "cli", "exec" or "shell" is therefore an attempted arbitrary command and is blocked
and recorded as a HIGH severity security event. (Request schemas also forbid unknown fields.)

Exempt: the admin-only command-profile editor (/api/profiles), whose templates are validated
against the security allowlist.
"""

from __future__ import annotations

import json

from starlette.responses import JSONResponse

from app.core.logging import get_logger, log_security

log = get_logger("security.request_guard")

FORBIDDEN_KEYS = frozenset({
    "command", "commands", "cmd", "cmds", "cli", "cli_command", "raw", "raw_command",
    "exec", "execute", "shell", "script", "ssh_command", "terminal", "run",
})
EXEMPT_PREFIXES = ("/api/profiles",)
MAX_INSPECT_BYTES = 1_000_000


def find_forbidden_key(data: object, depth: int = 0) -> str | None:
    if depth > 20:
        return None
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(key, str) and key.strip().lower() in FORBIDDEN_KEYS:
                return key
            found = find_forbidden_key(value, depth + 1)
            if found:
                return found
    elif isinstance(data, list):
        for item in data:
            found = find_forbidden_key(item, depth + 1)
            if found:
                return found
    return None


async def _record(scope, key: str) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.core.security import SESSION_COOKIE, hash_token
    from app.db.session import session_factory
    from app.models import AuditLog, UserSession

    headers = {k.decode().lower(): v.decode(errors="replace") for k, v in scope.get("headers", [])}
    token = ""
    for part in headers.get("cookie", "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == SESSION_COOKIE:
            token = value
    ip = (scope.get("client") or ("", 0))[0]
    try:
        async with session_factory()() as db:
            user = None
            if token:
                sess = (await db.execute(select(UserSession).options(
                    selectinload(UserSession.user)).where(
                    UserSession.token_hash == hash_token(token)))).scalar_one_or_none()
                user = sess.user if sess else None
            db.add(AuditLog(
                user_id=user.id if user else None, username=user.username if user else "anonymous",
                action="ARBITRARY_COMMAND_ATTEMPT", result="BLOCKED", severity="HIGH",
                target_type="request", message=f"Request to {scope.get('path')} carried a "
                f"command field {key[:40]!r}",
                details={"path": scope.get("path"), "field": key[:40], "commands_executed": 0},
                ip=ip,
            ))
            await db.commit()
    except Exception:  # noqa: BLE001 - the request is blocked regardless
        log.exception("Could not persist arbitrary-command security event")
    log_security(log, "[HIGH] ARBITRARY_COMMAND_ATTEMPT on %s (field %r) from %s",
                 scope.get("path"), key[:40], ip)


class CommandFieldGuard:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if (scope["type"] != "http" or scope.get("method") in {"GET", "HEAD", "OPTIONS"}
                or not scope.get("path", "").startswith("/api/")
                or scope["path"].startswith(EXEMPT_PREFIXES)):
            await self.app(scope, receive, send)
            return
        body = b""
        messages = []
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":
                break
            body += message.get("body", b"")
            if not message.get("more_body", False) or len(body) > MAX_INSPECT_BYTES:
                break
        key = None
        if body:
            try:
                key = find_forbidden_key(json.loads(body))
            except (ValueError, UnicodeDecodeError):
                key = None  # not JSON: the route's own validation rejects it
        if key:
            await _record(scope, key)
            response = JSONResponse(status_code=400, content={"error": {
                "code": "COMMAND_BLOCKED",
                "title": "COMMAND BLOCKED BY SAFETY POLICY",
                "message": "Requests may not contain command fields. The API only accepts "
                           "predefined operations. No command was executed.",
            }})
            await response(scope, receive, send)
            return

        pending = list(messages)

        async def replay():
            if pending:
                return pending.pop(0)
            return await receive()

        await self.app(scope, replay, send)
