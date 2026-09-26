"""Automatic device discovery.

    IP / hostname + credential reference
      → trusted SSH host key (enrolled, or matching the fingerprint supplied out of band)
      → SSH session through the Command Safety Firewall
      → the registry's read-only discovery command (``show system``)
      → vendor (description AND object id), model, AOS version — strict formats only
      → normalised version → exactly one Discovery Profile Registry entry
      → comparison with expected metadata and with the previously discovered identity
      → switch identity stored; command profile resolved from it

Fail closed: anything not identified exactly is DISCOVERY_FAILED (no other command is tried,
nothing is guessed); a changed identity is MISMATCH. Only a DISCOVERED switch may ever receive a
state-changing command (enforced again by port_control and the firewall).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.error_categories import ErrorCategory, category_for_status
from app.core.errors import AppError
from app.core.logging import get_logger, log_security
from app.core.timeutil import utcnow
from app.db.session import session_factory
from app.models import (
    ACTIVE_DISCOVERY_STATUSES,
    DiscoveryJob,
    DiscoveryJobStatus,
    DiscoveryStatus,
    Role,
    Switch,
    User,
)
from app.parsers.alcatel.system import SystemInfo
from app.security.firewall import ExecutionContext, UnexpectedOutput
from app.security.recorder import AlertItem, get_recorder
from app.services.alcatel.profiles import model_family
from app.services.alcatel.registry import load_profiles, select_profile
from app.services.audit.service import record
from app.services.discovery.registry import (
    expected_train,
    match_profile,
    normalize_discovered_version,
)
from app.services.inventory.service import build_target, mark_failure, mark_success
from app.services.ssh.errors import SwitchError
from app.services.ssh.manager import get_connector
from app.workers.tasks import spawn

log = get_logger("discovery")

JOB_TIMEOUT_SECONDS = 1800
FAILED = DiscoveryStatus.DISCOVERY_FAILED.value


@dataclass
class DiscoveryOutcome:
    status: str                     # DiscoveryStatus value
    category: str = ""              # ErrorCategory value or ""
    reason: str = ""
    vendor: str = ""
    model: str = ""
    version: str = ""
    discovery_profile: str = ""
    command_profile: str = ""
    profile_reason: str = ""
    system_name: str = ""
    mismatches: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == DiscoveryStatus.DISCOVERED.value

    def to_dict(self) -> dict:
        return {"ok": self.ok, "status": self.status, "category": self.category,
                "reason": self.reason, "vendor": self.vendor, "model": self.model,
                "version": self.version, "discovery_profile": self.discovery_profile,
                "profile": self.command_profile or None, "profile_reason": self.profile_reason,
                "system_name": self.system_name, "mismatches": self.mismatches,
                "commands": self.commands}


def _set_failed(switch: Switch, category: str, reason: str) -> DiscoveryOutcome:
    switch.discovery_status = FAILED
    switch.discovery_category = category
    switch.discovery_error = reason[:255]
    return DiscoveryOutcome(FAILED, category, reason)


IDENTIFIED = frozenset({DiscoveryStatus.DISCOVERED.value, DiscoveryStatus.MISMATCH.value})


def discovery_problem(info: SystemInfo) -> str | None:
    """Why a discovery answer does not identify the device exactly (None = identified)."""
    if info.vendor != "ALE":
        return ("The device did not identify itself as an Alcatel-Lucent Enterprise OmniSwitch "
                "(description and system object id).")
    if not info.model or normalize_discovered_version(info.version) is None:
        return "Model or AOS version could not be read in the documented format."
    return None


def normalized_version(raw: str | None) -> str:
    version = normalize_discovered_version(raw)
    return version.raw if version else ""


def apply_discovery(switch: Switch, info: SystemInfo) -> DiscoveryOutcome:
    """Evaluate a discovery answer and store the identity on the switch (no commit).

    The previous identity is compared BEFORE it is overwritten; a device that changed model or
    AOS version, or that differs from the administrator's expected metadata, becomes MISMATCH."""
    problem = discovery_problem(info)
    version = normalize_discovered_version(info.version)
    if problem or version is None or not info.model:
        return _set_failed(switch, ErrorCategory.DISCOVERY_FAILED.value,
                           problem or "Model or AOS version could not be read.")
    entry = match_profile(info.vendor, info.model, version)

    mismatches: list[str] = []
    # Any identity stored before counts — also after an address change reset the status: a
    # typo in the new address must not silently turn the entry into another device.
    if switch.vendor and switch.model:
        if model_family(switch.model) != model_family(info.model):
            mismatches.append(f"model changed from {switch.model} to {info.model}")
        prev = normalize_discovered_version(switch.aos_version)
        if prev is not None and prev.raw != version.raw:
            mismatches.append(f"AOS version changed from {prev.raw} to {version.raw}")
    if switch.expected_model and model_family(switch.expected_model) != model_family(info.model):
        mismatches.append(f"expected model {switch.expected_model}, device is {info.model}")
    if switch.expected_aos_version and expected_train(switch.expected_aos_version) != \
            version.train:
        mismatches.append(f"expected AOS {switch.expected_aos_version}, device runs "
                          f"{version.raw}")

    switch.vendor = info.vendor
    switch.model = info.model
    switch.aos_version = version.raw
    switch.system_name = (info.name or "")[:128]
    switch.system_description = (info.description or "")[:255]
    switch.system_object_id = (info.object_id or "")[:64]
    switch.discovery_profile = entry.key if entry else ""
    switch.discovered_at = utcnow()
    if mismatches:
        switch.discovery_status = DiscoveryStatus.MISMATCH.value
        switch.discovery_category = ErrorCategory.SAFETY_CHECK_FAILED.value
        switch.discovery_error = "; ".join(mismatches)[:255]
    else:
        switch.discovery_status = DiscoveryStatus.DISCOVERED.value
        switch.discovery_category = "" if entry else ErrorCategory.PROFILE_NOT_FOUND.value
        switch.discovery_error = "" if entry else (
            f"{info.model} AOS {version.raw} is not covered by any command profile.")
    return DiscoveryOutcome(switch.discovery_status, switch.discovery_category,
                            switch.discovery_error, info.vendor, info.model, version.raw,
                            switch.discovery_profile, system_name=switch.system_name,
                            mismatches=mismatches)


def identity_problems(switch: Switch, info: SystemInfo) -> list[str]:
    """Re-verification before a state change: differences between what the device reports now
    and the stored, discovered identity. Empty = same device (vendor, model, exact version)."""
    problems: list[str] = []
    if info.vendor != "ALE" or switch.vendor != "ALE":
        problems.append("the device did not identify itself as an Alcatel-Lucent Enterprise "
                        "OmniSwitch")
    if not info.model or info.model != switch.model:
        problems.append(f"model is {info.model or 'unreadable'}, discovered {switch.model}")
    version = normalize_discovered_version(info.version)
    if version is None or version.raw != switch.aos_version:
        problems.append(f"AOS version is {info.version or 'unreadable'}, discovered "
                        f"{switch.aos_version}")
    return problems


def apply_discovery_failure(switch: Switch, exc: SwitchError) -> DiscoveryOutcome:
    """A connection-level failure: a switch that was never identified becomes
    DISCOVERY_FAILED; an already identified one keeps its identity (it did not change — it
    just could not be reached)."""
    category = category_for_status(exc.status)
    if switch.discovery_status == DiscoveryStatus.DISCOVERED.value:
        return DiscoveryOutcome(switch.discovery_status, category, f"{exc.title}: {exc.reason}")
    return _set_failed(switch, category, f"{exc.title}: {exc.reason}")


async def audit_outcome(db: AsyncSession, switch: Switch, outcome: DiscoveryOutcome, *,
                        user: User | None = None, username: str = "", ip: str = "",
                        source: str = "manual") -> None:
    result = {"discovered": "SUCCESS", "mismatch": "BLOCKED"}.get(outcome.status, "FAILED")
    await record(db, action="DEVICE_DISCOVERY", result=result, user=user,
                 username=username or None, ip=ip, target_type="switch", target_id=switch.id,
                 switch_name=switch.name, site=switch.site, error_category=outcome.category,
                 severity="WARNING" if result != "SUCCESS" else "INFO",
                 message=(f"Discovered {outcome.vendor} {outcome.model} AOS {outcome.version}"
                          if outcome.model else f"Discovery failed: {outcome.reason}")
                 + (f" — MISMATCH: {outcome.reason}" if outcome.status == "mismatch" else ""),
                 details={**outcome.to_dict(), "source": source})
    if outcome.status == DiscoveryStatus.MISMATCH.value:
        from app.security.circuit_breaker import get_breaker

        get_breaker().record_profile_mismatch(switch_name=switch.name, detail=outcome.reason)
        get_recorder().submit(AlertItem(
            kind="DISCOVERY_MISMATCH", severity="HIGH",
            title=f"Device identity changed: {switch.name}",
            message=f"{outcome.reason}. State-changing operations are blocked until an "
                    "administrator accepts the discovered identity.",
            switch_name=switch.name, dedupe_key=f"discovery-mismatch:{switch.id}"))


# ---------------------------------------------------------------------------- one switch ---
def can_discover(switch: Switch) -> bool:
    """Automatic discovery is started only when it can succeed without anyone trusting an
    unverified host key: simulator, enrolled key, or a fingerprint supplied out of band."""
    return bool(switch.enabled and switch.credential_id and (
        switch.transport == "simulator" or switch.host_key
        or switch.expected_host_key_fingerprint or get_settings().ssh_allow_unknown_host_keys))


async def _trust_expected_host_key(db: AsyncSession, switch: Switch,
                                   username: str) -> DiscoveryOutcome | None:
    """SSH switches without an enrolled key: trusted only when the key the switch presents has
    exactly the fingerprint supplied out of band. Returns a failure outcome otherwise."""
    if switch.transport != "ssh" or switch.host_key or get_settings().ssh_allow_unknown_host_keys:
        return None
    expected = (switch.expected_host_key_fingerprint or "").strip()
    if not expected:
        return _set_failed(switch, ErrorCategory.HOST_KEY_UNTRUSTED.value,
                           "SSH host key not enrolled: trust it on the switch page (or import "
                           "its fingerprint); discovery then runs automatically.")
    from app.services.inventory.service import fetch_host_key

    try:
        data = await fetch_host_key(switch)
    except AppError as exc:
        return _set_failed(switch, ErrorCategory.DEVICE_UNREACHABLE.value, exc.message)
    if data["fingerprint"] != expected:
        log_security(log, "Host key of %s does not match the expected fingerprint", switch.name)
        get_recorder().submit(AlertItem(
            kind="HOSTKEY_MISMATCH", severity="HIGH",
            title=f"Unexpected SSH host key: {switch.name}",
            message="The switch presented a host key that does not match the fingerprint "
                    "supplied for it. Nothing was trusted.",
            switch_name=switch.name, dedupe_key=f"hostkey-mismatch:{switch.id}"))
        return _set_failed(switch, ErrorCategory.HOST_KEY_UNTRUSTED.value,
                           "The switch presented a host key that does not match the expected "
                           "fingerprint. Nothing was trusted.")
    switch.host_key, switch.host_key_fingerprint = data["host_key"], data["fingerprint"]
    await db.commit()
    await record(db, action="HOSTKEY_TRUST", result="SUCCESS", username=username,
                 target_type="switch", target_id=switch.id, switch_name=switch.name,
                 message="Host key trusted automatically: it matches the fingerprint supplied "
                         "for this switch", details={"fingerprint": data["fingerprint"]})
    return None


async def discover_switch(db: AsyncSession, switch: Switch, ctx: ExecutionContext, *,
                          user: User | None = None, source: str = "manual") -> DiscoveryOutcome:
    """Discover one switch now (read-only) and store the result."""
    started = time.monotonic()
    failure = await _trust_expected_host_key(db, switch, ctx.username)
    if failure is None:
        try:
            target = await build_target(db, switch)
        except AppError as exc:
            failure = _set_failed(switch, ErrorCategory.CONFIGURATION_ERROR.value, exc.message)
    if failure is not None:
        switch.last_check_at = utcnow()
        await db.commit()
        await audit_outcome(db, switch, failure, user=user, username=ctx.username, ip=ctx.ip,
                            source=source)
        return failure
    commands: list[str] = []
    try:
        async with get_connector().session(target, ctx) as fs:
            info = await fs.discover()
            commands = fs.executed_commands()
    except (SwitchError, UnexpectedOutput) as exc:
        mark_failure(switch, exc)
        outcome = apply_discovery_failure(switch, exc)
    else:
        mark_success(switch)
        outcome = apply_discovery(switch, info)
    outcome.commands = commands
    profile, reason = select_profile(await load_profiles(db), switch)
    outcome.command_profile = profile.key if profile else ""
    outcome.profile_reason = reason
    await db.commit()
    await audit_outcome(db, switch, outcome, user=user, username=ctx.username, ip=ctx.ip,
                        source=source)
    log.info("Discovery of %s: %s (%.1fs)", switch.name, outcome.status,
             time.monotonic() - started)
    return outcome


async def accept_identity(db: AsyncSession, switch: Switch, admin: User, reason: str,
                          ip: str) -> None:
    """Administrator accepts the discovered identity of a MISMATCH switch: the expected
    metadata becomes the discovered identity. Audited; the next restart re-checks it again."""
    if switch.discovery_status != DiscoveryStatus.MISMATCH.value:
        raise AppError("Only a switch in MISMATCH state can be accepted.", code="NOT_MISMATCH",
                       status_code=409)
    previous = {"expected_model": switch.expected_model,
                "expected_aos_version": switch.expected_aos_version,
                "mismatch": switch.discovery_error}
    switch.expected_model = switch.model
    switch.expected_aos_version = switch.aos_version
    switch.discovery_status = DiscoveryStatus.DISCOVERED.value
    switch.discovery_category = ""
    switch.discovery_error = ""
    await db.commit()
    await record(db, action="DISCOVERY_ACCEPT", result="SUCCESS", user=admin, ip=ip,
                 target_type="switch", target_id=switch.id, switch_name=switch.name,
                 site=switch.site, message=f"Discovered identity accepted: {switch.model} AOS "
                                           f"{switch.aos_version} ({reason})",
                 details={**previous, "reason": reason})


# ------------------------------------------------------------------------ background jobs ---
async def create_job(db: AsyncSession, user: User, switch_ids: list[int], *,
                     source: str = "manual") -> DiscoveryJob:
    job = DiscoveryJob(created_by_id=user.id, created_by=user.username, source=source,
                       switch_ids=sorted(set(switch_ids)), total=len(set(switch_ids)))
    db.add(job)
    await db.commit()
    await record(db, action="DISCOVERY_JOB_START", result="INFO", user=user,
                 target_type="discovery_job", target_id=job.id,
                 message=f"Discovery of {job.total} switch(es) started ({source})")
    spawn(run_job(job.id), name=f"discovery-{job.id}")
    return job


async def run_job(job_id: str) -> None:
    started = time.monotonic()
    async with session_factory()() as db:
        job = await db.get(DiscoveryJob, job_id)
        if job is None or job.status != DiscoveryJobStatus.QUEUED.value:
            return
        job.status, job.started_at = DiscoveryJobStatus.RUNNING.value, utcnow()
        await db.commit()
        user = await db.get(User, job.created_by_id) if job.created_by_id else None
        switch_ids = list(job.switch_ids or [])
        created_by = job.created_by
    ctx = ExecutionContext.for_user(user, "DISCOVERY", "", reference=job_id) if user else \
        ExecutionContext(None, created_by, Role.READONLY, "DISCOVERY", reference=job_id)
    # Bounded: never more parallel discoveries than the global SSH limit.
    limit = asyncio.Semaphore(get_settings().max_concurrent_switch_connections)
    results: list[dict] = []
    counts = {"discovered": 0, "failed": 0, "mismatched": 0}
    state = {"cancelled": False}

    async def one(switch_id: int) -> None:
        async with limit:
            if state["cancelled"] or time.monotonic() - started > JOB_TIMEOUT_SECONDS:
                results.append({"switch_id": switch_id, "status": "not_processed"})
                return
            async with session_factory()() as db:
                cancel = (await db.execute(select(DiscoveryJob.cancel_requested).where(
                    DiscoveryJob.id == job_id))).scalar_one()
                if cancel:
                    state["cancelled"] = True
                    results.append({"switch_id": switch_id, "status": "not_processed"})
                    return
                switch = await db.get(Switch, switch_id)
                if switch is None:
                    results.append({"switch_id": switch_id, "status": "deleted"})
                    return
                try:
                    outcome = await discover_switch(db, switch, ctx, user=user, source="job")
                except Exception as exc:  # noqa: BLE001 - one switch must not stop the job
                    log.exception("Discovery of switch %s crashed", switch_id)
                    await db.rollback()
                    outcome = DiscoveryOutcome(FAILED, ErrorCategory.INTERNAL_ERROR.value,
                                               exc.__class__.__name__)
                key = {"discovered": "discovered", "mismatch": "mismatched"}.get(
                    outcome.status, "failed")
                counts[key] += 1
                results.append({"switch_id": switch_id, "name": switch.name,
                                "status": outcome.status, "category": outcome.category,
                                "model": outcome.model, "version": outcome.version,
                                "reason": outcome.reason})
                await db.execute(update(DiscoveryJob).where(DiscoveryJob.id == job_id).values(
                    processed=len(results), **counts))
                await db.commit()

    error = ""
    try:
        await asyncio.gather(*(one(i) for i in switch_ids))
    except Exception as exc:  # noqa: BLE001
        log.exception("Discovery job %s crashed", job_id)
        error = f"Internal error ({exc.__class__.__name__})."
    if time.monotonic() - started > JOB_TIMEOUT_SECONDS and not error:
        error = f"Stopped after {JOB_TIMEOUT_SECONDS}s (timeout)."
    status = (DiscoveryJobStatus.CANCELLED if state["cancelled"] else
              DiscoveryJobStatus.FAILED if error else DiscoveryJobStatus.COMPLETED)
    async with session_factory()() as db:
        now = utcnow()
        await db.execute(update(DiscoveryJob).where(DiscoveryJob.id == job_id).values(
            status=status.value, results=results, processed=len(results), error=error,
            completed_at=None if status is DiscoveryJobStatus.FAILED else now,
            failed_at=now if status is DiscoveryJobStatus.FAILED else None, **counts))
        await db.commit()
        await record(db, action="DISCOVERY_JOB", result="SUCCESS" if not error else "FAILED",
                     username=created_by, target_type="discovery_job", target_id=job_id,
                     message=f"Discovery job {status.value}: {counts['discovered']} discovered, "
                             f"{counts['mismatched']} mismatch, {counts['failed']} failed",
                     details=counts)


async def mark_interrupted_jobs(db: AsyncSession) -> int:
    rows = (await db.execute(select(DiscoveryJob).where(
        DiscoveryJob.status.in_(ACTIVE_DISCOVERY_STATUSES)))).scalars().all()
    for job in rows:
        job.status, job.failed_at = DiscoveryJobStatus.INTERRUPTED.value, utcnow()
        job.error = "The application stopped while this discovery was running."
    await db.commit()
    return len(rows)


def job_view(job: DiscoveryJob) -> dict:
    return {
        "id": job.id, "status": job.status, "source": job.source, "created_by": job.created_by,
        "total": job.total, "processed": job.processed, "discovered": job.discovered,
        "failed": job.failed, "mismatched": job.mismatched,
        "cancel_requested": job.cancel_requested, "error": job.error,
        "results": job.results or [],
        **{k: (getattr(job, k).isoformat() if getattr(job, k) else None)
           for k in ("created_at", "started_at", "completed_at", "failed_at")},
    }
