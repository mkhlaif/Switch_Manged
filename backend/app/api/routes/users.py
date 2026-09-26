from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import Permission
from app.api.deps import client_ip, require
from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.core.security import hash_password, validate_password_strength
from app.db.session import get_db
from app.models import Role, User, UserSession
from app.schemas.common import UserCreate, UserOut, UserUpdate
from app.services.audit.service import record

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("")
async def list_users(_: User = Depends(require(Permission.MANAGE_USERS)),
                     db: AsyncSession = Depends(get_db)) -> list[dict]:
    from app.core.timeutil import utcnow

    sessions = dict((await db.execute(
        select(UserSession.user_id, func.count()).where(UserSession.expires_at >= utcnow())
        .group_by(UserSession.user_id))).all())
    users = (await db.execute(select(User).order_by(User.username))).scalars().all()
    return [{**UserOut.model_validate(u).model_dump(mode="json"),
             "active_sessions": sessions.get(u.id, 0)} for u in users]


@router.post("/{user_id}/logout")
async def force_logout(user_id: int, request: Request,
                       admin: User = Depends(require(Permission.MANAGE_USERS)),
                       db: AsyncSession = Depends(get_db)) -> dict:
    """Terminate every session of the user immediately (§72 force logout)."""
    user = await db.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found.")
    result = await db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    await db.commit()
    await record(db, action="USER_FORCE_LOGOUT", result="SUCCESS", severity="WARNING",
                 user=admin, ip=client_ip(request), target_type="user", target_id=user.id,
                 target_label=user.username,
                 message=f"{result.rowcount or 0} session(s) terminated")
    return {"ok": True, "sessions_terminated": result.rowcount or 0}


@router.post("", response_model=UserOut, status_code=201)
async def create_user(body: UserCreate, request: Request, admin: User = Depends(require(Permission.MANAGE_USERS)),
                      db: AsyncSession = Depends(get_db)):
    username = body.username.lower()
    if (await db.execute(select(User).where(User.username == username))).scalar_one_or_none():
        raise ConflictError(f"User '{username}' already exists.")
    problem = validate_password_strength(body.password)
    if problem:
        raise ValidationFailedError(problem)
    user = User(username=username, full_name=body.full_name, role=body.role.value,
                password_hash=hash_password(body.password))
    db.add(user)
    await db.commit()
    await record(db, action="USER_CREATE", result="SUCCESS", user=admin, ip=client_ip(request),
                 target_type="user", target_id=user.id, target_label=username,
                 details={"role": user.role})
    return user


async def _admin_count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(User).where(
        User.role == Role.ADMIN.value, User.is_active.is_(True)))).scalar_one()


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(user_id: int, body: UserUpdate, request: Request,
                      admin: User = Depends(require(Permission.MANAGE_USERS)), db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found.")
    changes = body.model_dump(exclude_unset=True)
    demoting = ("role" in changes and changes["role"] != Role.ADMIN) or changes.get("is_active") is False
    if user.role == Role.ADMIN.value and demoting and await _admin_count(db) <= 1:
        raise ValidationFailedError("At least one active administrator must remain.")
    if "password" in changes and changes["password"]:
        problem = validate_password_strength(changes["password"])
        if problem:
            raise ValidationFailedError(problem)
        user.password_hash = hash_password(changes.pop("password"))
        await db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    changes.pop("password", None)
    role_changed = "role" in changes and changes["role"] is not None and         changes["role"].value != user.role
    for key, value in changes.items():
        setattr(user, key, value.value if isinstance(value, Role) else value)
    if changes.get("is_active") is False or role_changed:
        # A role change switches the interface/permission set: start from a fresh login.
        await db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    await db.commit()
    await record(db, action="USER_UPDATE", result="SUCCESS", user=admin, ip=client_ip(request),
                 target_type="user", target_id=user.id, target_label=user.username,
                 details={k: (v.value if isinstance(v, Role) else v) for k, v in changes.items()})
    return user


@router.delete("/{user_id}", status_code=204)
async def delete_user(user_id: int, request: Request, admin: User = Depends(require(Permission.MANAGE_USERS)),
                      db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found.")
    if user.id == admin.id:
        raise ValidationFailedError("You cannot delete your own account.")
    if user.role == Role.ADMIN.value and await _admin_count(db) <= 1:
        raise ValidationFailedError("At least one active administrator must remain.")
    await db.delete(user)
    await db.commit()
    await record(db, action="USER_DELETE", result="SUCCESS", user=admin, ip=client_ip(request),
                 target_type="user", target_id=user_id, target_label=user.username)
