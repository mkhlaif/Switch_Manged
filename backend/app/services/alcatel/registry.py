"""Profile registry: built-in profiles (code) + custom profiles, applicability and lab verification."""

from __future__ import annotations

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


def select_profile(profiles: dict[str, CommandProfile], switch) -> tuple[CommandProfile | None, str]:
    """Return (profile, reason). The profile is None when no verified profile applies to the
    switch's exact model family and AOS version (fail closed)."""
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


@dataclass
class VerificationStatus:
    required: bool
    verified: bool
    detail: str
    record_id: int | None = None


async def verification_status(db: AsyncSession, profile_key: str, capability: str,
                              model: str | None, version: str | None,
                              *, required: bool = True) -> VerificationStatus:
    family = model_family(model)
    if family is None or not version:
        return VerificationStatus(required, False, "model family or AOS version unknown")
    rows = (await db.execute(select(CommandVerification).where(
        CommandVerification.profile_key == profile_key,
        CommandVerification.capability == capability,
    ))).scalars().all()
    for row in rows:
        if row.model_family in {family, "*"} and version_matches_prefix(version, row.version_prefix):
            return VerificationStatus(required, True,
                                      f"{capability} lab-verified for {row.model_family} AOS "
                                      f"{row.version_prefix} by {row.verified_by}", row.id)
    return VerificationStatus(required, False,
                              f"{capability} of profile {profile_key} is not lab-verified for "
                              f"{family} AOS {version}")


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
                                           switch.aos_version)
        if not status.verified:
            candidate = candidate or spec
            reasons.append(f"{status.detail}. An administrator must lab-validate it and record "
                           "the verification (Settings → Command profiles). Dry run is still "
                           "possible.")
            continue
        return StrategyChoice(True, spec, status.detail)
    return StrategyChoice(False, candidate, " ".join(reasons))
