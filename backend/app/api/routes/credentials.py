from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import Permission
from app.api.deps import client_ip, require
from app.core.crypto import encrypt_secret
from app.core.errors import ConflictError, NotFoundError
from app.db.session import get_db
from app.models import Credential, Switch, User
from app.schemas.common import CredentialCreate, CredentialOut, CredentialUpdate
from app.services.audit.service import record

router = APIRouter(prefix="/api/credentials", tags=["credentials"])


async def _out(db: AsyncSession, cred: Credential) -> CredentialOut:
    count = (await db.execute(select(func.count()).select_from(Switch).where(
        Switch.credential_id == cred.id))).scalar_one()
    out = CredentialOut.model_validate(cred)
    out.switch_count = count
    return out


@router.get("", response_model=list[CredentialOut])
async def list_credentials(_: User = Depends(require(Permission.MANAGE_CREDENTIALS)), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Credential).order_by(Credential.name))).scalars().all()
    return [await _out(db, c) for c in rows]


@router.post("", response_model=CredentialOut, status_code=201)
async def create_credential(body: CredentialCreate, request: Request,
                            admin: User = Depends(require(Permission.MANAGE_CREDENTIALS)),
                            db: AsyncSession = Depends(get_db)):
    if (await db.execute(select(Credential).where(Credential.name == body.name))).scalar_one_or_none():
        raise ConflictError(f"Credential '{body.name}' already exists.")
    cred = Credential(name=body.name, username=body.username, description=body.description,
                      password_encrypted=encrypt_secret(body.password))
    db.add(cred)
    await db.commit()
    await record(db, action="CREDENTIAL_CREATE", result="SUCCESS", user=admin,
                 ip=client_ip(request), target_type="credential", target_id=cred.id,
                 target_label=cred.name, details={"username": cred.username})
    return await _out(db, cred)


@router.patch("/{cred_id}", response_model=CredentialOut)
async def update_credential(cred_id: int, body: CredentialUpdate, request: Request,
                            admin: User = Depends(require(Permission.MANAGE_CREDENTIALS)),
                            db: AsyncSession = Depends(get_db)):
    cred = await db.get(Credential, cred_id)
    if cred is None:
        raise NotFoundError("Credential not found.")
    changes = body.model_dump(exclude_unset=True)
    if changes.get("password"):
        cred.password_encrypted = encrypt_secret(changes.pop("password"))
        changes["password_changed"] = True
    changes.pop("password", None)
    for key in ("name", "username", "description"):
        if key in changes:
            setattr(cred, key, changes[key])
    await db.commit()
    await record(db, action="CREDENTIAL_UPDATE", result="SUCCESS", user=admin,
                 ip=client_ip(request), target_type="credential", target_id=cred.id,
                 target_label=cred.name, details=changes)
    return await _out(db, cred)


@router.delete("/{cred_id}", status_code=204)
async def delete_credential(cred_id: int, request: Request, admin: User = Depends(require(Permission.MANAGE_CREDENTIALS)),
                            db: AsyncSession = Depends(get_db)):
    cred = await db.get(Credential, cred_id)
    if cred is None:
        raise NotFoundError("Credential not found.")
    in_use = (await db.execute(select(func.count()).select_from(Switch).where(
        Switch.credential_id == cred.id))).scalar_one()
    if in_use:
        raise ConflictError(f"Credential is used by {in_use} switch(es).")
    await db.delete(cred)
    await db.commit()
    await record(db, action="CREDENTIAL_DELETE", result="SUCCESS", user=admin,
                 ip=client_ip(request), target_type="credential", target_id=cred_id,
                 target_label=cred.name)
