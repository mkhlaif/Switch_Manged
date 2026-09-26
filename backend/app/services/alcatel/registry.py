"""Profile registry: built-in profiles (code) + custom profiles, applicability and lab verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models import CommandProfileRecord, CommandVerification
from app.services.alcatel.profiles import (
    BUILTIN_PROFILES,
    BounceMethod,
    BounceStrategySpec,
    CommandProfile,
    ProfileLintError,
    is_poe_model,
    model_family,
    model_matches,
    profile_applicability,
    version_matches_prefix,
)

log = get_logger("profiles")

UNAVAILABLE = "Command profile unavailable for this switch model/version"


async def sync_builtin_profiles(db: AsyncSession) -> None:
    """Mirror built-in profiles into the DB so they are visible via the API. Built-in rows are
    always overwritten from code: their commands cannot be edited."""
    existing = {r.key: r for r in (await db.execute(select(CommandProfileRecord))).scalars()}
    for key, profile in BUILTIN_PROFILES.items():
        row = existing.get(key)
        if row is None:
            db.add(CommandProfileRecord(key=key, name=profile.name, description=profile.description,
                                        builtin=True, enabled=profile.enabled,
                                        definition=profile.to_dict()))
        else:
            row.name, row.description = profile.name, profile.description
            row.builtin, row.enabled, row.definition = True, profile.enabled, profile.to_dict()
    await db.commit()


async def load_profiles(db: AsyncSession) -> dict[str, CommandProfile]:
    profiles = dict(BUILTIN_PROFILES)
    rows = (await db.execute(
        select(CommandProfileRecord).where(CommandProfileRecord.builtin.is_(False))
    )).scalars()
    for row in rows:
        try:
            profile = CommandProfile.from_dict({**row.definition, "key": row.key, "name": row.name,
                                                "builtin": False, "enabled": row.enabled})
        except (ProfileLintError, KeyError, ValueError) as exc:
            log.error("Custom profile %s is invalid and ignored: %s", row.key, exc)
            continue
        profiles[row.key] = profile
    return profiles


_IDENTIFIED = frozenset({"discovered", "mismatch"})  # DiscoveryStatus values with an identity


def select_profile(profiles: dict[str, CommandProfile], switch) -> tuple[CommandProfile | None, str]:
    """Return (profile, reason). The profile is None when no verified profile applies to the
    switch's exact model family and AOS version (fail closed).

    Inventory switches carry ``discovery_status``: their model / version are only trusted once
    they come from automatic discovery (never from what someone typed in)."""
    status = getattr(switch, "discovery_status", None)
    if status is not None and status not in _IDENTIFIED:
        return None, (f"{UNAVAILABLE}: the device identity has not been discovered yet "
                      f"({status.replace('_', ' ')}). Run discovery first.")
    if switch.profile_key:
        profile = profiles.get(switch.profile_key)
        if profile is None:
            return None, f"{UNAVAILABLE}: assigned profile '{switch.profile_key}' does not exist."
        if not profile.enabled:
            return None, f"{UNAVAILABLE}: profile '{profile.key}' is disabled (unverified)."
    else:
        if not switch.aos_version:
            return None, f"{UNAVAILABLE}: AOS version unknown."
        candidates = [p for p in profiles.values() if p.builtin and
                      any(switch.aos_version.startswith(v.rstrip(".") + ".")
                          or switch.aos_version.startswith(v) for v in p.version_prefixes)]
        if not candidates:
            return None, f"{UNAVAILABLE}: no command profile exists for AOS {switch.aos_version}."
        profile = candidates[0]
        if not profile.enabled:
            return None, (f"{UNAVAILABLE}: profile {profile.key} is not verified for AOS "
                          f"{switch.aos_version}.")
    ok, why = profile_applicability(profile, switch.model, switch.aos_version)
    if not ok:
        return None, f"{UNAVAILABLE} ({why})."
    return profile, why


def profile_version(profile: CommandProfile) -> str:
    """Short content hash of a profile definition: identifies exactly which commands /
    parsers an action or audit entry used (a changed custom profile gets a new version)."""
    blob = json.dumps(profile.to_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


LEVELS = {"LAB_VERIFIED": 1, "PRODUCTION_VERIFIED": 2}


def required_level(switch) -> str:
    """State changes on production switches need PRODUCTION_VERIFIED; lab switches (and the
    in-process simulator) LAB_VERIFIED."""
    if getattr(switch, "transport", "ssh") == "simulator" or \
            getattr(switch, "environment", "production") == "lab":
        return "LAB_VERIFIED"
    return "PRODUCTION_VERIFIED"


def _specific_prefix(prefix: str) -> bool:
    """A record must name at least major.minor (e.g. 8.10): "8" would claim every 8.x
    release, which nobody has verified."""
    return len(prefix.split(".")) >= 2


@dataclass
class VerificationStatus:
    required: bool
    verified: bool
    detail: str
    record_id: int | None = None
    level: str = ""  # best active state found: LAB_VERIFIED | PRODUCTION_VERIFIED | BLOCKED | ""


async def verification_status(db: AsyncSession, profile_key: str, capability: str,
                              model: str | None, version: str | None,
                              *, required: bool = True,
                              minimum: str = "LAB_VERIFIED") -> VerificationStatus:
    """Profile state of ``capability`` for this exact model family and AOS version.

    No record = DRAFT (not usable). A matching BLOCKED record wins over everything. DEPRECATED
    records are ignored. Records for all models ("*", legacy) never count as
    PRODUCTION_VERIFIED: production needs the exact model family."""
    family = model_family(model)
    if family is None or not version:
        return VerificationStatus(required, False, "model family or AOS version unknown")
    rows = (await db.execute(select(CommandVerification).where(
        CommandVerification.profile_key == profile_key,
        CommandVerification.capability == capability,
    ))).scalars().all()
    matching = [r for r in rows if r.model_family in {family, "*"}
                and _specific_prefix(r.version_prefix)
                and version_matches_prefix(version, r.version_prefix)]
    blocked = next((r for r in matching if r.status == "BLOCKED"), None)
    if blocked is not None:
        return VerificationStatus(required, False,
                                  f"{capability} of profile {profile_key} is BLOCKED for "
                                  f"{blocked.model_family} AOS {blocked.version_prefix} by "
                                  f"{blocked.status_changed_by or blocked.verified_by}",
                                  blocked.id, "BLOCKED")

    def effective(r) -> int:
        level = LEVELS.get(r.status, 0)
        return min(level, LEVELS["LAB_VERIFIED"]) if r.model_family == "*" else level

    active = sorted((r for r in matching if effective(r)), key=effective, reverse=True)
    if not active:
        return VerificationStatus(required, False,
                                  f"{capability} of profile {profile_key} is not verified "
                                  f"(DRAFT) for {family} AOS {version}")
    best = active[0]
    level = "PRODUCTION_VERIFIED" if effective(best) == 2 else "LAB_VERIFIED"
    detail = (f"{capability} {level} for {best.model_family} AOS {best.version_prefix} by "
              f"{best.status_changed_by or best.verified_by}")
    if LEVELS[level] < LEVELS[minimum]:
        return VerificationStatus(required, False,
                                  f"{detail}; production switches need {minimum}", best.id,
                                  level)
    return VerificationStatus(required, True, detail, best.id, level)


@dataclass
class StrategyChoice:
    available: bool                       # verified AND lab-approved: may really be executed
    strategy: BounceStrategySpec | None   # the approved strategy, or the best verified candidate
    reason: str                           # why it is (not) available

    @property
    def dry_run_possible(self) -> bool:
        return self.strategy is not None


async def choose_strategy(
    db: AsyncSession, profile: CommandProfile, switch, method: BounceMethod,
    port_is_poe_capable: bool | None = None,
) -> StrategyChoice:
    """Pick the verified, lab-approved bounce strategy for this switch, or explain why none."""
    specs = profile.strategies_for(method)
    if not specs:
        return StrategyChoice(False, None, f"Profile {profile.key} defines no "
                              f"{method.value.replace('_', ' ')} strategy.")
    reasons: list[str] = []
    candidate: BounceStrategySpec | None = None
    for spec in specs:
        if not spec.verification.usable:
            reasons.append(f"{spec.strategy.value}: command syntax is unverified.")
            continue
        if spec.supported_models and not model_matches(switch.model, spec.supported_models):
            reasons.append(f"{spec.strategy.value}: not supported on {switch.model or 'this model'}.")
            continue
        if spec.unsupported_models and model_matches(switch.model, spec.unsupported_models):
            reasons.append(f"{spec.strategy.value}: not supported on {switch.model}.")
            continue
        if spec.requires_poe_model and not (port_is_poe_capable or is_poe_model(switch.model)):
            reasons.append(f"{spec.strategy.value}: {switch.model or 'this switch'} does not "
                           "appear to be a PoE model.")
            continue
        status = await verification_status(db, profile.key, spec.strategy.value, switch.model,
                                           switch.aos_version, minimum=required_level(switch))
        if not status.verified:
            candidate = candidate or spec
            reasons.append(f"{status.detail}. An administrator must verify it (Settings → "
                           "Command profiles). Dry run is still possible.")
            continue
        return StrategyChoice(True, spec, status.detail)
    return StrategyChoice(False, candidate, " ".join(reasons))
