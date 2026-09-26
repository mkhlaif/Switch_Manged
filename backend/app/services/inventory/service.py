"""Switch inventory operations: connection targets, test, version detection, host-key enrollment."""

from __future__ import annotations

import time

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.crypto import CredentialCryptoError, decrypt_secret
from app.core.errors import AppError
from app.core.timeutil import utcnow
from app.models import Credential, Switch, SwitchStatus
from app.services.alcatel.profiles import BUILTIN_PROFILES
from app.services.alcatel.registry import load_profiles, select_profile
from app.security.firewall import ExecutionContext
from app.services.ssh.errors import SwitchError
from app.services.ssh.manager import ConnectionTarget, get_connector

_ERROR_TO_STATUS = {
    "timeout": SwitchStatus.OFFLINE,
    "connection_failed": SwitchStatus.OFFLINE,
    "auth_failed": SwitchStatus.AUTH_FAILED,
    "hostkey_error": SwitchStatus.HOSTKEY_ERROR,
}


def status_for_error(exc: SwitchError) -> SwitchStatus:
    return _ERROR_TO_STATUS.get(exc.status, SwitchStatus.ERROR)


async def build_target(db: AsyncSession, switch: Switch, prompt_pattern: str | None = None
                       ) -> ConnectionTarget:
    if switch.credential_id is None:
        raise AppError("No credential is assigned to this switch.", title="MISSING CREDENTIAL",
                       code="MISSING_CREDENTIAL", action="Assign a credential in the inventory.")
    credential = await db.get(Credential, switch.credential_id)
    if credential is None:
        raise AppError("The assigned credential no longer exists.", code="MISSING_CREDENTIAL")
    try:
        password = decrypt_secret(credential.password_encrypted)
    except CredentialCryptoError as exc:
        raise AppError(str(exc), title="CREDENTIAL ERROR", code="CREDENTIAL_ERROR") from exc
    return ConnectionTarget(
        switch_id=switch.id,
        name=switch.name,
        host=switch.host,
        port=switch.ssh_port,
        username=credential.username,
        password=password,
        host_key=switch.host_key or None,
        legacy_algorithms=switch.legacy_ssh_algorithms,
        transport=switch.transport,
        prompt_pattern=prompt_pattern or r"->\s*$",
        model=switch.model or None,
        aos_version=switch.aos_version or None,
        previous_status=switch.status or "unknown",
    )


async def known_switches(db: AsyncSession) -> frozenset[str]:
    """Lower-case names and management addresses of all inventory switches (topology hints)."""
    from sqlalchemy import select

    rows = (await db.execute(select(Switch.name, Switch.host))).all()
    return frozenset(v.lower() for row in rows for v in row if v)


def mark_success(switch: Switch) -> None:
    now = utcnow()
    switch.status = SwitchStatus.ONLINE.value
    switch.last_check_at = now
    switch.last_success_at = now
    switch.last_error = ""


def mark_failure(switch: Switch, exc: SwitchError) -> None:
    switch.status = status_for_error(exc).value
    switch.last_check_at = utcnow()
    switch.last_error = f"{exc.title}: {exc.reason}"


async def test_connection(db: AsyncSession, switch: Switch, ctx: ExecutionContext) -> dict:
    """Connect and run the approved read-only discovery command only (``show system``)."""
    target = await build_target(db, switch)
    started = time.monotonic()
    try:
        async with get_connector().session(target, ctx) as session:
            info = await session.discover()
            commands = session.executed_commands()
    except SwitchError as exc:
        mark_failure(switch, exc)
        await db.commit()
        return {"ok": False, "status": exc.status, "title": exc.title, "reason": exc.reason,
                "duration_ms": int((time.monotonic() - started) * 1000)}
    mark_success(switch)
    await db.commit()
    return {"ok": True, "status": "online", "duration_ms": int((time.monotonic() - started) * 1000),
            "model": info.model, "version": info.version, "system_name": info.name,
            "commands": commands}


async def detect(db: AsyncSession, switch: Switch, ctx: ExecutionContext) -> dict:
    """Detect model/AOS version via the discovery profile and select the command profile."""
    result = await test_connection(db, switch, ctx)
    if not result["ok"]:
        return result
    changed = {}
    if result.get("model") and result["model"] != switch.model:
        changed["model"] = [switch.model, result["model"]]
        switch.model = result["model"]
    if result.get("version") and result["version"] != switch.aos_version:
        changed["aos_version"] = [switch.aos_version, result["version"]]
        switch.aos_version = result["version"]
    profile, reason = select_profile(await load_profiles(db), switch)
    await db.commit()
    result.update({
        "changed": changed,
        "profile": profile.key if profile else None,
        "profile_reason": reason,
    })
    return result


async def fetch_host_key(switch: Switch) -> dict:
    if switch.transport != "ssh":
        raise AppError("Host keys apply to SSH transport only.", code="NOT_APPLICABLE")
    from app.services.ssh.asyncssh_session import fetch_host_key as _fetch

    settings = get_settings()
    try:
        key, fingerprint = await _fetch(switch.host, switch.ssh_port, switch.legacy_ssh_algorithms,
                                        settings.ssh_connect_timeout)
    except SwitchError as exc:
        raise AppError(exc.reason, title=exc.title, code=exc.status.upper(),
                       action="Check reachability and retry.") from exc
    return {"host_key": key, "fingerprint": fingerprint,
            "key_type": key.split(" ", 1)[0] if key else ""}


def profile_label(switch: Switch, profiles: dict | None = None) -> str:
    profiles = profiles or BUILTIN_PROFILES
    profile, _ = select_profile(profiles, switch)
    return profile.key if profile else ""
