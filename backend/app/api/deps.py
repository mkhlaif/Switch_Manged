"""Request dependencies: authentication, CSRF and role-based authorization."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import AuthenticationError, PermissionDeniedError
from app.core.security import CSRF_HEADER, SESSION_COOKIE, hash_token, tokens_equal
from app.core.timeutil import utcnow
from app.db.session import get_db
from app.core.permissions import Permission
from app.models import Role, User, UserSession

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise AuthenticationError("Please sign in.")
    session = (await db.execute(
        select(UserSession).options(selectinload(UserSession.user))
        .where(UserSession.token_hash == hash_token(token))
    )).scalar_one_or_none()
    now = utcnow()
    if session is None or session.expires_at < now:
        raise AuthenticationError("Your session has expired. Please sign in again.")
    user = session.user
    if not user.is_active:
        raise AuthenticationError("This account is disabled.")
    if request.method not in SAFE_METHODS:
        header = request.headers.get(CSRF_HEADER, "")
        if not header or not tokens_equal(header, session.csrf_token):
            raise PermissionDeniedError("Missing or invalid CSRF token. Reload the page.",
                                        code="CSRF_FAILED")
    if now - session.last_seen_at > timedelta(minutes=1):
        session.last_seen_at = now
        await db.commit()
    request.state.user = user
    request.state.csrf_token = session.csrf_token
    return user


def require(*permissions: Permission) -> Callable:
    """Dependency: the user must hold ALL listed permissions (checked server-side)."""

    async def _dep(request: Request, user: User = Depends(get_current_user),
                   db: AsyncSession = Depends(get_db)) -> User:
        missing = [p for p in permissions if not user.has_permission(p)]
        if missing:
            if user.role == Role.MAC_OPERATOR.value:
                # A simplified-UI account probing technical APIs is a security event.
                from app.services.audit.service import record

                await record(db, action="RBAC_VIOLATION", result="DENIED", severity="HIGH",
                             user=user, ip=client_ip(request),
                             message=f"{user.role} attempted {request.url.path}",
                             details={"path": request.url.path, "method": request.method,
                                      "missing": [p.value for p in missing]})
            raise PermissionDeniedError("You do not have permission for this action.")
        return user

    return _dep
