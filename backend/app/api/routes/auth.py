from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_current_user
from app.core.config import get_settings
from app.core.errors import AuthenticationError, ValidationFailedError
from app.core.ratelimit import limiter
from app.core.security import (
    CSRF_COOKIE,
    DUMMY_PASSWORD_HASH,
    SESSION_COOKIE,
    hash_password,
    hash_token,
    new_token,
    validate_password_strength,
    verify_password,
)
from app.core.timeutil import utcnow
from app.db.session import get_db
from app.models import User, UserSession
from app.schemas.common import ChangePasswordRequest, LoginRequest, UserOut
from app.services.audit.service import record

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _user_payload(user: User) -> dict:
    """The user plus the server-side permission set; the SPA picks its interface from it
    (MAC_OPERATOR → simplified screen). The backend enforces the same permissions per route."""
    from app.core.permissions import permissions_for
    from app.models import Role

    data = UserOut.model_validate(user).model_dump(mode="json")
    data["permissions"] = sorted(p.value for p in permissions_for(user.role))
    data["interface"] = "simple" if user.role == Role.MAC_OPERATOR.value else "full"
    return data

MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15


def _set_cookies(response: Response, token: str, csrf: str) -> None:
    settings = get_settings()
    max_age = settings.session_ttl_minutes * 60
    response.set_cookie(SESSION_COOKIE, token, max_age=max_age, httponly=True,
                        secure=settings.cookie_secure, samesite="strict", path="/")
    # Readable by the SPA (double-submit CSRF pattern); useless to another origin.
    response.set_cookie(CSRF_COOKIE, csrf, max_age=max_age, httponly=False,
                        secure=settings.cookie_secure, samesite="strict", path="/")


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response,
                db: AsyncSession = Depends(get_db)) -> dict:
    ip = client_ip(request)
    username = body.username.strip().lower()
    limiter.hit(f"login-ip:{ip}", limit=30, window_seconds=300)
    limiter.hit(f"login:{ip}:{username}", limit=10, window_seconds=300)

    user = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    now = utcnow()
    if user is None:
        verify_password(DUMMY_PASSWORD_HASH, body.password)  # equalize timing
        await record(db, action="LOGIN_FAILED", result="FAILED", severity="WARNING",
                     username=username, ip=ip,
                     message="Unknown username")
        raise AuthenticationError("Invalid username or password.", code="INVALID_CREDENTIALS")
    if user.locked_until and user.locked_until > now:
        await record(db, action="LOGIN_FAILED", result="DENIED", severity="WARNING",
                     user=user, ip=ip,
                     message="Account temporarily locked")
        raise AuthenticationError("Too many failed attempts. The account is temporarily locked.",
                                  code="ACCOUNT_LOCKED")
    if not verify_password(user.password_hash, body.password) or not user.is_active:
        user.failed_login_count += 1
        if user.failed_login_count >= MAX_FAILED_LOGINS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_count = 0
        await db.commit()
        await record(db, action="LOGIN_FAILED", result="FAILED", severity="WARNING",
                     user=user, ip=ip,
                     message="Wrong password" if user.is_active else "Account disabled")
        raise AuthenticationError("Invalid username or password.", code="INVALID_CREDENTIALS")

    token, csrf = new_token(), new_token()
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    db.add(UserSession(
        user_id=user.id, token_hash=hash_token(token), csrf_token=csrf,
        expires_at=now + timedelta(minutes=get_settings().session_ttl_minutes),
        ip=ip, user_agent=(request.headers.get("user-agent") or "")[:256],
    ))
    await db.execute(delete(UserSession).where(UserSession.expires_at < now))
    await db.commit()
    await record(db, action="LOGIN_SUCCESS", result="SUCCESS", user=user, ip=ip)
    _set_cookies(response, token, csrf)
    return {"user": _user_payload(user), "csrf_token": csrf}


@router.post("/logout")
async def logout(request: Request, response: Response, user: User = Depends(get_current_user),
                 db: AsyncSession = Depends(get_db)) -> dict:
    token = request.cookies.get(SESSION_COOKIE, "")
    await db.execute(delete(UserSession).where(UserSession.token_hash == hash_token(token)))
    await db.commit()
    await record(db, action="LOGOUT", result="SUCCESS", user=user, ip=client_ip(request))
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
async def me(request: Request, user: User = Depends(get_current_user)) -> dict:
    return {"user": _user_payload(user), "csrf_token": request.state.csrf_token}


@router.post("/change-password")
async def change_password(body: ChangePasswordRequest, request: Request,
                          user: User = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)) -> dict:
    limiter.hit(f"pwchange:{user.id}", limit=5, window_seconds=300)
    if not verify_password(user.password_hash, body.current_password):
        await record(db, action="PASSWORD_CHANGE", result="FAILED", user=user,
                     ip=client_ip(request), message="Current password incorrect")
        raise ValidationFailedError("Current password is incorrect.")
    problem = validate_password_strength(body.new_password)
    if problem:
        raise ValidationFailedError(problem)
    db_user = await db.get(User, user.id)
    db_user.password_hash = hash_password(body.new_password)
    token = request.cookies.get(SESSION_COOKIE, "")
    # Invalidate every other session of this user.
    await db.execute(delete(UserSession).where(UserSession.user_id == user.id,
                                               UserSession.token_hash != hash_token(token)))
    await db.commit()
    await record(db, action="PASSWORD_CHANGE", result="SUCCESS", user=user, ip=client_ip(request))
    return {"ok": True}
