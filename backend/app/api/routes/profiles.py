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
from app.core.timeutil import utcnow
from app.models import (
    ActionOutcome,
    AuditLog,
    CommandProfileRecord,
    CommandVerification,
    PortAction,
    Switch,
    User,
)
from app.schemas.common import (
    ProfileCreate,
    ProfileUpdate,
    VerificationCreate,
    VerificationRun,
    VerificationStatusChange,
)
from app.services.alcatel.profiles import (
    BUILTIN_PROFILES,
    CommandProfile,
    PortBounceStrategy,
    ProfileLintError,
    Verification,
    model_family,
    version_matches_prefix,
)
from app.services.alcatel.registry import load_profiles, profile_version, select_profile
from app.services.audit.service import record

router = APIRouter(prefix="/api/profiles", tags=["profiles"])


PROFILE_STATES = ("DRAFT", "LAB_VERIFIED", "PRODUCTION_VERIFIED", "BLOCKED", "DEPRECATED")
EVIDENCE_LEVELS = ("SIMULATED", "FIXTURE_TESTED", "LAB_VERIFIED", "PRODUCTION_VERIFIED")
# Allowed transitions of a verification record (no record = DRAFT).
TRANSITIONS = {
    "LAB_VERIFIED": {"PRODUCTION_VERIFIED", "BLOCKED", "DEPRECATED"},
    "PRODUCTION_VERIFIED": {"LAB_VERIFIED", "BLOCKED", "DEPRECATED"},
    "BLOCKED": {"LAB_VERIFIED", "DEPRECATED"},
    "DEPRECATED": {"LAB_VERIFIED"},
}


def _verification_view(v: CommandVerification) -> dict:
    return {"id": v.id, "profile_key": v.profile_key, "capability": v.capability,
            "model_family": v.model_family, "version_prefix": v.version_prefix,
            "notes": v.notes, "verified_by": v.verified_by,
            "verified_at": v.verified_at.isoformat(), "evidence": v.evidence,
            "status": v.status, "status_changed_by": v.status_changed_by,
            "status_changed_at": v.status_changed_at.isoformat() if v.status_changed_at
            else None, "status_reason": v.status_reason,
            # Legacy records for every model ("*") never count as production evidence.
            "all_models": v.model_family == "*",
            "effective_level": ("LAB_VERIFIED" if v.model_family == "*" and
                                v.status == "PRODUCTION_VERIFIED" else v.status)}


async def _verifications(db: AsyncSession) -> list[dict]:
    rows = (await db.execute(select(CommandVerification).order_by(
        CommandVerification.profile_key, CommandVerification.capability,
        CommandVerification.model_family, CommandVerification.version_prefix,
    ))).scalars().all()
    return [_verification_view(v) for v in rows]


@router.get("")
async def list_profiles(_: User = Depends(require(Permission.VIEW_SAFETY)),
                        db: AsyncSession = Depends(get_db)) -> dict:
    from app.services.discovery.registry import DISCOVERY_PROFILES

    profiles = await load_profiles(db)
    usage: dict[str, int] = {}
    for sw in (await db.execute(select(Switch))).scalars():
        profile, _reason = select_profile(profiles, sw)
        if profile is not None:
            usage[profile.key] = usage.get(profile.key, 0) + 1
    return {
        "profiles": [{**p.to_dict(), "switch_count": usage.get(p.key, 0),
                      "version": profile_version(p),
                      # Built-in commands: documented syntax + parser tests against fixtures.
                      # Higher levels come only from verification records (below).
                      "evidence_level": "FIXTURE_TESTED" if p.builtin else "SIMULATED"}
                     for p in profiles.values()],
        "discovery_profiles": [d.to_dict() for d in DISCOVERY_PROFILES],
        "verifications": await _verifications(db),
        "verification_levels": [v.value for v in Verification],
        "profile_states": list(PROFILE_STATES),
        "evidence_levels": list(EVIDENCE_LEVELS),
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
    if body.model_family not in profile.supported_models:
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
    row = (await db.execute(select(CommandVerification).where(
        CommandVerification.profile_key == body.profile_key,
        CommandVerification.capability == body.capability,
        CommandVerification.model_family == body.model_family,
        CommandVerification.version_prefix == body.version_prefix,
    ))).scalar_one_or_none()
    if row is not None and row.status == "BLOCKED":
        raise ConflictError("This capability is BLOCKED for this model family / AOS version. "
                            "An administrator must lift the block explicitly (with a reason) "
                            "before it can be verified again.")
    if row is not None and row.status != "DEPRECATED":
        raise ConflictError("This verification record already exists.")
    if row is None:
        db.add(CommandVerification(profile_key=body.profile_key, capability=body.capability,
                                   model_family=body.model_family,
                                   version_prefix=body.version_prefix, notes=body.notes,
                                   verified_by=admin.username, evidence=evidence,
                                   status="LAB_VERIFIED"))
    else:  # a DEPRECATED record is revived with the new evidence (history stays in the audit)
        row.notes, row.verified_by, row.verified_at = body.notes, admin.username, utcnow()
        row.evidence, row.status = evidence, "LAB_VERIFIED"
        row.status_changed_by, row.status_changed_at = admin.username, utcnow()
        row.status_reason = "re-verified"
    await db.commit()
    await record(db, action="PROFILE_VERIFICATION_ADD", result="SUCCESS", user=admin, ip=ip,
                 target_type="profile", target_id=body.profile_key, profile=body.profile_key,
                 message=f"{body.capability} LAB_VERIFIED for {body.model_family} AOS "
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


async def _production_evidence(db: AsyncSession, row: CommandVerification) -> dict | None:
    """Recorded evidence from a REAL switch (SSH, not the simulator) of this model family and
    AOS version: a passed read-only verification run (READ), or a live restart with this
    strategy whose post-restart verification succeeded (restart strategies)."""
    if row.capability == "READ":
        runs = (await db.execute(select(AuditLog).where(
            AuditLog.action == "PROFILE_VERIFICATION_RUN", AuditLog.result == "SUCCESS",
            AuditLog.profile == row.profile_key,
        ).order_by(AuditLog.id.desc()).limit(500))).scalars().all()
        for run in runs:
            d = run.details or {}
            if d.get("transport") == "ssh" and d.get("model_family") == row.model_family and \
                    version_matches_prefix(str(d.get("aos_version") or ""), row.version_prefix):
                return {"kind": "read_verification_run", "audit_id": run.id,
                        "switch": run.switch_name, "aos_version": d.get("aos_version"),
                        "at": run.ts.isoformat()}
        return None
    actions = (await db.execute(select(PortAction, Switch).join(
        Switch, Switch.id == PortAction.switch_id).where(
        PortAction.profile_key == row.profile_key, PortAction.strategy == row.capability,
        PortAction.dry_run.is_(False), PortAction.outcome == ActionOutcome.SUCCESS.value,
        Switch.transport == "ssh",
    ).order_by(PortAction.id.desc()).limit(500))).all()
    for action, switch in actions:
        if model_family(switch.model) == row.model_family and \
                version_matches_prefix(action.aos_version or "", row.version_prefix):
            return {"kind": "verified_live_restart", "action_id": action.id,
                    "switch": action.switch_name, "port": action.port,
                    "aos_version": action.aos_version,
                    "at": (action.finished_at or action.created_at).isoformat()}
    return None


@router.post("/verifications/{verification_id}/status")
async def change_verification_status(verification_id: int, body: VerificationStatusChange,
                                     request: Request,
                                     admin: User = Depends(require(Permission.MANAGE_PROFILES)),
                                     db: AsyncSession = Depends(get_db)) -> dict:
    """Profile state transition (audited). PRODUCTION_VERIFIED requires recorded evidence from
    a real switch; the application never promotes anything on its own."""
    row = await db.get(CommandVerification, verification_id)
    if row is None:
        raise NotFoundError("Verification record not found.")
    if body.status not in TRANSITIONS.get(row.status, set()):
        raise ConflictError(f"A {row.status} record cannot become {body.status}.")
    evidence = None
    if body.status == "PRODUCTION_VERIFIED":
        if row.model_family == "*":
            raise ValidationFailedError("Records for all models cannot be production-verified. "
                                        "Verify the exact model family.")
        evidence = await _production_evidence(db, row)
        if evidence is None:
            raise ValidationFailedError(
                "No production evidence recorded: PRODUCTION_VERIFIED needs "
                + ("a passed read-only verification run" if row.capability == "READ" else
                   f"a live {row.capability} restart whose post-restart verification "
                   "succeeded")
                + f" on a real (SSH) {row.model_family} switch running AOS "
                  f"{row.version_prefix}. Nothing was changed.")
        row.evidence = {**(row.evidence or {}), "production": evidence}
    previous = row.status
    row.status = body.status
    row.status_changed_by, row.status_changed_at = admin.username, utcnow()
    row.status_reason = body.reason
    await db.commit()
    await record(db, action="PROFILE_STATE_CHANGE", result="SUCCESS", user=admin,
                 ip=client_ip(request), target_type="profile", target_id=row.profile_key,
                 profile=row.profile_key,
                 severity="WARNING" if body.status in {"BLOCKED", "PRODUCTION_VERIFIED"}
                 else "INFO",
                 message=f"{row.capability} of {row.profile_key} on {row.model_family} AOS "
                         f"{row.version_prefix}: {previous} -> {body.status} ({body.reason})",
                 details={"id": row.id, "from": previous, "to": body.status,
                          "reason": body.reason, "evidence": evidence})
    return {"verifications": await _verifications(db)}


@router.delete("/verifications/{verification_id}")
async def revoke_verification(verification_id: int, request: Request,
                              admin: User = Depends(require(Permission.MANAGE_PROFILES)),
                              db: AsyncSession = Depends(get_db)) -> dict:
    """Revoke = DEPRECATED (the record is kept for history; it no longer counts)."""
    row = await db.get(CommandVerification, verification_id)
    if row is None:
        raise NotFoundError("Verification record not found.")
    info = {"profile_key": row.profile_key, "capability": row.capability,
            "model_family": row.model_family, "version_prefix": row.version_prefix,
            "from": row.status}
    if row.status != "DEPRECATED":
        row.status = "DEPRECATED"
        row.status_changed_by, row.status_changed_at = admin.username, utcnow()
        row.status_reason = "revoked"
        await db.commit()
    await record(db, action="PROFILE_VERIFICATION_REVOKE", result="SUCCESS", user=admin,
                 ip=client_ip(request), target_type="profile", target_id=info["profile_key"],
                 details=info, message=f"{info['capability']} verification for "
                                       f"{info['model_family']} AOS {info['version_prefix']} "
                                       "revoked (DEPRECATED)")
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
        if result["transport"] == "simulator":
            raise ValidationFailedError("A simulator run is SIMULATED evidence: it is never "
                                        "recorded as a lab verification. Run it against a real "
                                        "lab switch. Nothing was recorded.")
        await _add_verification(db, admin, ip, VerificationCreate(
            profile_key=result["profile"], capability="READ",
            model_family=result["model_family"], version_prefix=result["version_prefix"],
            notes=body.notes or f"Automated read-only verification on {result['switch']}"),
            {"method": "automated read-only verification run",
             "switch": result["switch"], "transport": result["transport"],
             "aos_version": result["aos_version"], "results": result["results"]})
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
