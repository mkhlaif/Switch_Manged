"""Command profiles and administrator lab-verification records.

Built-in profiles are read-only (defined in code, verified against ALE documentation). Admins may
clone one into a custom profile to adapt syntax after lab validation; every template must pass
the same safety linter, and edited commands revert to ``unverified`` until explicitly marked
``lab_verified``. Write strategies can only use the fixed grammar in ``WRITE_GRAMMAR``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import Permission
from app.core.ratelimit import limiter
from app.api.deps import client_ip, require
from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.db.session import get_db
from app.models import CommandProfileRecord, CommandVerification, Switch, User
from app.schemas.common import (
    ProfileCreate,
    ProfileUpdate,
    VerificationCreate,
    VerificationRun,
)
from app.services.alcatel.profiles import (
    BUILTIN_PROFILES,
    CommandProfile,
    PortBounceStrategy,
    ProfileLintError,
    Verification,
    version_matches_prefix,
)
from app.services.alcatel.registry import load_profiles, select_profile
from app.services.audit.service import record

router = APIRouter(prefix="/api/profiles", tags=["profiles"])


async def _verifications(db: AsyncSession) -> list[dict]:
    rows = (await db.execute(select(CommandVerification).order_by(
        CommandVerification.profile_key, CommandVerification.capability,
        CommandVerification.model_family, CommandVerification.version_prefix,
    ))).scalars().all()
    return [{"id": v.id, "profile_key": v.profile_key, "capability": v.capability,
             "model_family": v.model_family, "version_prefix": v.version_prefix,
             "notes": v.notes, "verified_by": v.verified_by,
             "verified_at": v.verified_at.isoformat(), "evidence": v.evidence} for v in rows]


@router.get("")
async def list_profiles(_: User = Depends(require(Permission.VIEW_SAFETY)),
                        db: AsyncSession = Depends(get_db)) -> dict:
    profiles = await load_profiles(db)
    usage: dict[str, int] = {}
    for sw in (await db.execute(select(Switch))).scalars():
        profile, _reason = select_profile(profiles, sw)
        if profile is not None:
            usage[profile.key] = usage.get(profile.key, 0) + 1
    return {
        "profiles": [{**p.to_dict(), "switch_count": usage.get(p.key, 0)}
                     for p in profiles.values()],
        "verifications": await _verifications(db),
        "verification_levels": [v.value for v in Verification],
        "strategies": [s.value for s in PortBounceStrategy],
        "capabilities": ["READ", *[s.value for s in PortBounceStrategy]],
    }


def _validate_verification(profile: CommandProfile, body: VerificationCreate) -> None:
    if body.capability != "READ":
        spec = next((s for s in profile.strategies if s.strategy.value == body.capability), None)
        if spec is None:
            raise ValidationFailedError(f"Profile {profile.key} has no strategy "
                                        f"{body.capability}.")
        if not spec.verification.usable:
            raise ValidationFailedError("An unverified strategy cannot be lab-verified.")
    if body.model_family != "*" and body.model_family not in profile.supported_models:
        raise ValidationFailedError(
            f"{body.model_family} is not a supported model of profile {profile.key} "
            f"({', '.join(profile.supported_models)}).")
    if not any(version_matches_prefix(body.version_prefix, v) or
               body.version_prefix.startswith(v.rstrip(".")) for v in profile.version_prefixes):
        raise ValidationFailedError(
            f"Version prefix {body.version_prefix} does not belong to profile {profile.key} "
            f"({', '.join(profile.version_prefixes)}).")


async def _add_verification(db: AsyncSession, admin: User, ip: str, body: VerificationCreate,
                            evidence: dict) -> None:
    exists = (await db.execute(select(CommandVerification).where(
        CommandVerification.profile_key == body.profile_key,
        CommandVerification.capability == body.capability,
        CommandVerification.model_family == body.model_family,
        CommandVerification.version_prefix == body.version_prefix,
    ))).scalar_one_or_none()
    if exists:
        raise ConflictError("This verification record already exists.")
    db.add(CommandVerification(profile_key=body.profile_key, capability=body.capability,
                               model_family=body.model_family,
                               version_prefix=body.version_prefix, notes=body.notes,
                               verified_by=admin.username, evidence=evidence))
    await db.commit()
    await record(db, action="PROFILE_VERIFICATION_ADD", result="SUCCESS", user=admin, ip=ip,
                 target_type="profile", target_id=body.profile_key, profile=body.profile_key,
                 message=f"{body.capability} lab-verified for {body.model_family} AOS "
                         f"{body.version_prefix}", details=body.model_dump())


@router.post("/verifications", status_code=201)
async def add_verification(body: VerificationCreate, request: Request,
                           admin: User = Depends(require(Permission.MANAGE_PROFILES)),
                           db: AsyncSession = Depends(get_db)) -> dict:
    profile = (await load_profiles(db)).get(body.profile_key)
    if profile is None:
        raise NotFoundError("Profile not found.")
    _validate_verification(profile, body)
    await _add_verification(db, admin, client_ip(request), body,
                            {"method": "manual lab test recorded by administrator"})
    return {"verifications": await _verifications(db)}


@router.delete("/verifications/{verification_id}")
async def revoke_verification(verification_id: int, request: Request,
                              admin: User = Depends(require(Permission.MANAGE_PROFILES)),
                              db: AsyncSession = Depends(get_db)) -> dict:
    row = await db.get(CommandVerification, verification_id)
    if row is None:
        raise NotFoundError("Verification record not found.")
    info = {"profile_key": row.profile_key, "capability": row.capability,
            "model_family": row.model_family, "version_prefix": row.version_prefix}
    await db.delete(row)
    await db.commit()
    await record(db, action="PROFILE_VERIFICATION_REVOKE", result="SUCCESS", user=admin,
                 ip=client_ip(request), target_type="profile", target_id=info["profile_key"],
                 details=info, message=f"{info['capability']} verification for "
                                       f"{info['model_family']} AOS {info['version_prefix']} "
                                       "revoked")
    return {"verifications": await _verifications(db)}


@router.post("/verifications/run")
async def run_verification(body: VerificationRun, request: Request,
                           admin: User = Depends(require(Permission.MANAGE_PROFILES)),
                           db: AsyncSession = Depends(get_db)) -> dict:
    """Execute the profile's READ-ONLY commands once against a lab switch and validate every
    output against its documented contract. Never sends a state-changing command."""
    from app.services.alcatel.verification import run_read_verification

    limiter.hit(f"verification-run:{admin.id}", limit=5, window_seconds=60)
    ip = client_ip(request)
    result = await run_read_verification(db, admin, switch_id=body.switch_id, port=body.port,
                                         mac=body.mac, ip=ip)
    if body.record:
        if not result["passed"]:
            raise ValidationFailedError("Verification did not pass; nothing was recorded.")
        await _add_verification(db, admin, ip, VerificationCreate(
            profile_key=result["profile"], capability="READ",
            model_family=result["model_family"], version_prefix=result["version_prefix"],
            notes=body.notes or f"Automated read-only verification on {result['switch']}"),
            {"method": "automated read-only verification run",
             "switch": result["switch"], "results": result["results"]})
        result["recorded"] = True
    return result


@router.post("", status_code=201)
async def create_custom_profile(body: ProfileCreate, request: Request,
                                admin: User = Depends(require(Permission.MANAGE_PROFILES)),
                                db: AsyncSession = Depends(get_db)) -> dict:
    profiles = await load_profiles(db)
    if body.key in profiles:
        raise ConflictError(f"Profile {body.key} already exists.")
    source = profiles.get(body.clone_from)
    if source is None:
        raise NotFoundError("Source profile not found.")
    definition = source.to_dict()
    definition.update({"key": body.key, "name": body.name, "builtin": False, "enabled": False,
                       "description": body.description or f"Custom copy of {source.key}"})
    CommandProfile.from_dict(definition)  # lint
    db.add(CommandProfileRecord(key=body.key, name=body.name, description=definition["description"],
                                builtin=False, enabled=False, definition=definition))
    await db.commit()
    await record(db, action="PROFILE_CREATE", result="SUCCESS", user=admin, ip=client_ip(request),
                 target_type="profile", target_id=body.key, details={"clone_from": source.key})
    return definition


@router.put("/{key}")
async def update_custom_profile(key: str, body: ProfileUpdate, request: Request,
                                admin: User = Depends(require(Permission.MANAGE_PROFILES)),
                                db: AsyncSession = Depends(get_db)) -> dict:
    if key in BUILTIN_PROFILES:
        raise ValidationFailedError("Built-in profiles are read-only. Clone it to customise.")
    row = (await db.execute(select(CommandProfileRecord).where(
        CommandProfileRecord.key == key))).scalar_one_or_none()
    if row is None:
        raise NotFoundError("Profile not found.")
    definition = dict(row.definition)
    old_commands = definition.get("commands", {})
    if body.commands is not None:
        merged = dict(old_commands)  # only the commands in the request are changed
        for name, cmd in body.commands.items():
            prev = old_commands.get(name, {})
            new = {**prev, **cmd, "name": name, "read_only": True}
            # Any template change resets verification unless explicitly lab-verified now.
            if new.get("template") != prev.get("template") and \
                    cmd.get("verification") != Verification.LAB_VERIFIED.value:
                new["verification"] = Verification.UNVERIFIED.value
            merged[name] = new
        definition["commands"] = merged
    if body.strategies is not None:
        definition["strategies"] = body.strategies
    if body.name is not None:
        definition["name"] = row.name = body.name
    if body.description is not None:
        definition["description"] = row.description = body.description
    if body.enabled is not None:
        definition["enabled"] = row.enabled = body.enabled
    try:
        CommandProfile.from_dict({**definition, "key": key, "builtin": False})
    except (ProfileLintError, KeyError, ValueError) as exc:
        raise ValidationFailedError(f"Profile rejected by the safety linter: {exc}") from exc
    row.definition = definition
    await db.commit()
    await record(db, action="PROFILE_UPDATE", result="SUCCESS", user=admin, ip=client_ip(request),
                 target_type="profile", target_id=key, details=body.model_dump(exclude_none=True))
    return definition


@router.delete("/{key}", status_code=204)
async def delete_custom_profile(key: str, request: Request, admin: User = Depends(require(Permission.MANAGE_PROFILES)),
                                db: AsyncSession = Depends(get_db)):
    if key in BUILTIN_PROFILES:
        raise ValidationFailedError("Built-in profiles cannot be deleted.")
    row = (await db.execute(select(CommandProfileRecord).where(
        CommandProfileRecord.key == key))).scalar_one_or_none()
    if row is None:
        raise NotFoundError("Profile not found.")
    in_use = (await db.execute(select(Switch).where(Switch.profile_key == key))).first()
    if in_use:
        raise ConflictError("Profile is assigned to one or more switches.")
    await db.delete(row)
    await db.commit()
    await record(db, action="PROFILE_DELETE", result="SUCCESS", user=admin, ip=client_ip(request),
                 target_type="profile", target_id=key)
