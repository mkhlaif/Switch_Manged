"""MAC search jobs.

Workflow (strictly read-only):

    create job → connect to every enabled switch (bounded parallelism) → [detect version if
    unknown] → filtered MAC lookup → for each hit: VLANs / port status / LLDP / MAC count of that
    port only → classify → persist → summarise (multiple locations, MAC move, path) → alerts.

Search modes (§12):

* FAST — MAC lookup only (one command per switch). Ports are not analysed; classification uses
  only definitive facts (declared uplink, link aggregate) and is otherwise UNKNOWN.
* STANDARD — MAC lookup + VLAN membership, port status, LLDP and MAC count of the port.
* DEEP — STANDARD with every diagnostic forced on plus the MAC distribution of the port (the
  list of MACs learned there, from the same verified command) and path analysis. DEEP is never
  run against the whole network: it requires an explicit selection of at most
  ``DEEP_MAX_SWITCHES`` switches.

The search keeps going after the first hit because a MAC is normally visible on the edge port
AND on every uplink between that switch and the searching switches.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError, ValidationFailedError
from app.core.logging import get_logger
from app.core.timeutil import utcnow
from app.db.session import session_factory
from app.models import (
    FAILURE_STATUSES,
    MacSearch,
    MacSearchResult,
    MacSighting,
    Role,
    SearchStatus,
    Switch,
    SwitchResultStatus,
    User,
)
from app.parsers.common import format_mac
from app.services import system_settings
from app.security.firewall import CommandBlocked, ExecutionContext, UnexpectedOutput
from app.security.recorder import AlertItem, get_recorder
from app.security.validators import MacAddressValidator, ParameterRejected
from app.services.alcatel.adapter import AlcatelAdapter
from app.services.alcatel.investigation import PortInvestigation, investigate
from app.services.alcatel.profiles import CommandProfile
from app.services.alcatel.registry import load_profiles, select_profile
from app.services.audit.service import record
from app.services.classification.engine import PortClass
from app.services.inventory.service import (
    build_target,
    known_switches,
    mark_failure,
    mark_success,
)
from app.services.mac_search.path import build_path
from app.services.mac_search.progress import broker
from app.services.ssh.errors import CommandFailed, SwitchError
from app.services.ssh.manager import ConnectionTarget, get_connector
from app.workers.tasks import spawn

log = get_logger("mac_search")

MULTIPLE_LOCATION_REASONS = [
    "The MAC is seen on uplink/trunk ports between switches (normal: every switch on the path "
    "learns it).",
    "The device moved (MAC movement) and older entries have not aged out yet.",
    "A Layer-2 loop is making the MAC appear on several ports.",
    "The MAC is learned on multiple interfaces (e.g. dual-homed server, NIC teaming).",
    "Spanning-tree topology change moved the path.",
    "Virtualization: the same virtual MAC exists on several hosts, or a VM migrated.",
    "A stale MAC entry that has not aged out.",
]

EDGE_CLASSES = {PortClass.ACCESS.value, PortClass.LIKELY_ACCESS.value}
TRUNK_CLASSES = {PortClass.TRUNK.value, PortClass.LIKELY_TRUNK.value}
SEARCH_MODES = ("FAST", "STANDARD", "DEEP")
DEEP_MAX_SWITCHES = 5


@dataclass
class SwitchSnapshot:
    id: int
    name: str
    host: str
    location: str
    model: str
    aos_version: str
    profile_key: str
    uplink_ports: list[str]
    role: str = "unknown"


@dataclass
class SwitchJob:
    snapshot: SwitchSnapshot
    target: ConnectionTarget | None
    setup_error: str = ""


@dataclass
class SwitchOutcome:
    job: SwitchJob
    status: str
    error: str = ""
    profile_key: str = ""
    detected_model: str | None = None
    detected_version: str | None = None
    investigations: list[PortInvestigation] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    duration_ms: int = 0
    reachable: bool = False
    switch_error: SwitchError | None = None


def _no_profile_message(model: str, version: str, reason: str, *, discovered: bool) -> str:
    executed = ("Only the read-only discovery command was executed; no MAC lookup command was "
                "executed." if discovered else "No command was executed.")
    return (f"COMMAND BLOCKED. {reason} Model: {model or 'unknown'}, AOS: "
            f"{version or 'unknown'}. {executed}")


def _snapshot(sw: Switch) -> SwitchSnapshot:
    return SwitchSnapshot(sw.id, sw.name, sw.host, sw.location, sw.model, sw.aos_version,
                          sw.profile_key, list(sw.uplink_ports or []), sw.role or "unknown")


# --------------------------------------------------------------------------------------------
async def start_search(db: AsyncSession, user: User, mac_input: str,
                       switch_ids: list[int] | None = None, ip: str = "",
                       mode: str = "STANDARD", purpose: str = "MAC_SEARCH") -> MacSearch:
    mode = (mode or "STANDARD").upper()
    if mode not in SEARCH_MODES:
        raise ValidationFailedError(f"Unknown search mode {mode!r}.", code="INVALID_MODE")
    if mode == "DEEP" and (not switch_ids or len(set(switch_ids)) > DEEP_MAX_SWITCHES):
        raise ValidationFailedError(
            f"DEEP mode is never run against the whole network. Select between 1 and "
            f"{DEEP_MAX_SWITCHES} switches.", code="DEEP_REQUIRES_SELECTION")
    try:
        mac = MacAddressValidator.validate(mac_input)
    except ParameterRejected as exc:
        await record(db, action="INJECTION_ATTEMPT" if exc.severity.value in {"HIGH", "CRITICAL"}
                     else "INVALID_PARAMETER", result="BLOCKED", severity=exc.severity.value,
                     user=user, ip=ip, message=f"SEARCH_MAC blocked: {exc.reason}",
                     details={"operation": "SEARCH_MAC", "parameter": "mac",
                              "value": exc.value_preview, "commands_executed": 0})
        raise ValidationFailedError(
            f"COMMAND BLOCKED BY SAFETY POLICY. Invalid MAC address: {exc.reason}. No command "
            "was executed.", code="COMMAND_BLOCKED") from exc

    query = select(Switch).where(Switch.enabled.is_(True))
    if switch_ids:
        query = query.where(Switch.id.in_(switch_ids))
    switches = (await db.execute(query.order_by(Switch.name))).scalars().all()
    if not switches:
        raise AppError("There are no enabled switches to search.", title="NO SWITCHES",
                       code="NO_SWITCHES", action="Add or enable switches in the inventory.")

    settings = await system_settings.get_all(db)
    # The simplified (MAC_OPERATOR) flow always collects the full endpoint evidence.
    full_evidence = mode == "DEEP" or purpose == "SIMPLE_SEARCH"
    search = MacSearch(
        mac=mac,
        requested_by_id=user.id,
        requested_by=user.username,
        status=SearchStatus.QUEUED.value,
        total_switches=len(switches),
        mode=mode,
        options={
            "switch_ids": [s.id for s in switches],
            "role": user.role,
            "purpose": purpose,
            "include_lldp": full_evidence or bool(settings["search_include_lldp"]),
            "include_mac_count": full_evidence or bool(settings["search_include_mac_count"]),
        },
    )
    db.add(search)
    await db.commit()
    await record(db, action="MAC_SEARCH", result="INFO", user=user, mac=mac, ip=ip,
                 operation="SEARCH_MAC", target_type="search", target_id=search.id,
                 message=f"MAC search ({mode}) started across {len(switches)} switch(es)")
    log.info("MAC search %s started for %s across %d switches", search.id, format_mac(mac),
             len(switches))
    spawn(run_search(search.id), name=f"mac-search-{search.id}")
    return search


# --------------------------------------------------------------------------------------------
async def _search_switch(job: SwitchJob, mac: str, profiles: dict[str, CommandProfile],
                         include_lldp: bool, include_mac_count: bool,
                         ctx: ExecutionContext, mode: str = "STANDARD",
                         known: frozenset[str] = frozenset()) -> SwitchOutcome:
    started = time.monotonic()
    snap = job.snapshot

    def done(status: str, **kw) -> SwitchOutcome:
        return SwitchOutcome(job, status, duration_ms=int((time.monotonic() - started) * 1000),
                             **kw)

    if job.target is None:
        return done(SwitchResultStatus.ERROR.value, error=job.setup_error)

    budget = get_settings().ssh_switch_budget_seconds
    detected_model = detected_version = None
    commands: list[str] = []

    # Fail closed BEFORE connecting when the version is known but no verified profile exists.
    profile, reason = select_profile(profiles, snap)  # type: ignore[arg-type]
    if profile is None and (snap.aos_version or snap.profile_key):
        return done(SwitchResultStatus.UNSUPPORTED.value, error=_no_profile_message(
            snap.model, snap.aos_version, reason, discovered=False))
    try:
        # The budget starts once a connection slot is acquired, so switches queued behind the
        # concurrency limit are not penalised. Connect/login have their own SSH timeouts.
        async with get_connector().session(job.target, ctx) as session:
            async with asyncio.timeout(budget):
                try:
                    if profile is None:
                        # Unknown version: only the separately approved discovery command runs.
                        info = await session.discover()
                        detected_model, detected_version = info.model, info.version
                        snap.model = info.model or snap.model
                        snap.aos_version = info.version or ""
                        profile, reason = select_profile(profiles, snap)  # type: ignore[arg-type]
                    if profile is None:
                        return done(SwitchResultStatus.UNSUPPORTED.value,
                                    error=_no_profile_message(snap.model, snap.aos_version,
                                                              reason, discovered=True),
                                    reachable=True, commands=session.executed_commands(),
                                    detected_model=detected_model,
                                    detected_version=detected_version)
                    await session.bind_profile(profile, model=snap.model or None,
                                               version=snap.aos_version or None)
                    adapter = AlcatelAdapter(session)
                    entries, _raw = await adapter.find_mac(mac)
                    entries = [e for e in entries if e.valid] or entries
                    others = known - {snap.name.lower(), snap.host.lower()}
                    if mode == "FAST":
                        investigations = [_fast_investigation(e, snap) for e in entries]
                    else:
                        investigations = [
                            await investigate(adapter, e, uplink_ports=snap.uplink_ports,
                                              include_lldp=include_lldp,
                                              include_mac_count=include_mac_count
                                              and mode != "DEEP",
                                              switch_role=snap.role, known_switches=others)
                            for e in entries
                        ]
                        if mode == "DEEP":
                            for inv in investigations:
                                await _deep_diagnostics(adapter, inv, snap, others)
                    status = (SwitchResultStatus.FOUND if investigations
                              else SwitchResultStatus.NOT_FOUND).value
                    return done(status, profile_key=profile.key, investigations=investigations,
                                commands=session.executed_commands(), reachable=True,
                                detected_model=detected_model, detected_version=detected_version)
                finally:
                    commands = session.executed_commands()
    except CommandBlocked as exc:
        return done(SwitchResultStatus.BLOCKED.value, commands=commands,
                    error=f"{exc.title}: {exc.reason}", reachable=True,
                    detected_model=detected_model, detected_version=detected_version)
    except UnexpectedOutput as exc:
        return done(SwitchResultStatus.UNEXPECTED_OUTPUT.value, commands=commands,
                    error=f"{exc.title}: {exc.reason}", reachable=True,
                    detected_model=detected_model, detected_version=detected_version)
    except TimeoutError:
        return done(SwitchResultStatus.TIMEOUT.value, commands=commands,
                    error=f"The switch did not complete the lookup within {budget:.0f}s.")
    except CommandFailed as exc:
        return done(SwitchResultStatus.COMMAND_FAILED.value, commands=commands, reachable=True,
                    error=f"The switch rejected '{exc.command}': {exc.reason}. The selected "
                          "command profile may not be compatible with this AOS version. No "
                          "configuration changes were made.",
                    detected_model=detected_model, detected_version=detected_version)
    except SwitchError as exc:
        return done(exc.status if exc.status in {s.value for s in SwitchResultStatus}
                    else SwitchResultStatus.ERROR.value,
                    error=exc.reason, commands=commands, switch_error=exc)
    except Exception as exc:  # noqa: BLE001 - one broken switch must not stop the search
        log.exception("Unexpected error searching %s", snap.name)
        return done(SwitchResultStatus.ERROR.value, error=f"Internal error ({exc.__class__.__name__}).",
                    commands=commands)


def _fast_investigation(entry, snap: SwitchSnapshot) -> PortInvestigation:
    """FAST mode: no port commands. Only definitive facts are used; everything else is UNKNOWN
    (which can never be restarted)."""
    from app.services.classification.engine import (
        Classification,
        ClassificationInput,
        Reason,
        classify_port,
    )

    declared = bool(entry.port and entry.port in set(snap.uplink_ports))
    inv = PortInvestigation(entry=entry, declared_uplink=declared)
    if declared or entry.is_linkagg:
        inv.classification = classify_port(ClassificationInput(
            port=entry.port, is_linkagg=entry.is_linkagg, linkagg_id=entry.linkagg_id,
            declared_uplink=declared))
    else:
        inv.classification = Classification(
            PortClass.UNKNOWN, "Low", 0.2, 0, 0,
            [Reason("neutral", "FAST mode: the port was not analysed (MAC lookup only). Run a "
                    "STANDARD search for port details and classification.")])
    return inv


async def _deep_diagnostics(adapter: AlcatelAdapter, inv: PortInvestigation,
                            snap: SwitchSnapshot, others: frozenset[str]) -> None:
    """DEEP mode: MAC distribution on the port (same verified command as the MAC count)."""
    from app.services.classification.engine import ClassificationInput, classify_port

    port = inv.entry.port
    if not port or inv.entry.is_linkagg or not adapter.has("mac_on_port"):
        return
    try:
        entries = await adapter.port_macs(port)
    except (CommandBlocked, CommandFailed, UnexpectedOutput) as exc:
        inv.warnings.append(f"MAC distribution unavailable: {exc.reason}")
        return
    valid = [e for e in entries if e.valid]
    inv.mac_count = len({(e.mac, e.vlan_id) for e in valid})
    inv.mac_distribution = [{"mac": e.mac, "vlan_id": e.vlan_id, "type": e.mac_type}
                            for e in valid[:200]]
    inv.classification = classify_port(ClassificationInput(
        port=port, declared_uplink=inv.declared_uplink, vlans=inv.vlans, lldp=inv.lldp,
        mac_count=inv.mac_count, speed_mbps=inv.detail.speed_mbps if inv.detail else None,
        alias=inv.detail.alias if inv.detail else None, switch_role=snap.role,
        known_switches=others))


def _result_rows(search_id: str, outcome: SwitchOutcome) -> list[MacSearchResult]:
    snap = outcome.job.snapshot
    base = dict(
        search_id=search_id, switch_id=snap.id, switch_name=snap.name, switch_host=snap.host,
        location=snap.location, model=outcome.detected_model or snap.model,
        aos_version=outcome.detected_version or snap.aos_version, profile_key=outcome.profile_key,
        status=outcome.status, error_message=outcome.error, commands_executed=outcome.commands,
        duration_ms=outcome.duration_ms,
    )
    if not outcome.investigations:
        return [MacSearchResult(**base)]
    rows = []
    for inv in outcome.investigations:
        e, c, d = inv.entry, inv.classification, inv.detail
        rows.append(MacSearchResult(
            **base,
            port=e.port or "",
            interface_raw=e.interface_raw,
            is_linkagg=e.is_linkagg,
            vlan_id=e.vlan_id,
            mac_type=e.mac_type,
            operation=e.operation or "",
            port_details={**(d.to_dict() if d else {}),
                          **({"mac_distribution": inv.mac_distribution}
                             if inv.mac_distribution is not None else {})},
            vlans=inv.vlans_as_dicts(),
            tagged_vlans=inv.tagged_vlans,
            untagged_vlan=inv.untagged_vlan,
            lldp=inv.lldp_as_dicts(),
            mac_count_on_port=inv.mac_count,
            classification=c.category.value if c else "",
            classification_confidence=c.confidence if c else "",
            classification_score=c.confidence_score if c else None,
            classification_reasons=[r.to_dict() for r in c.reasons] if c else [],
            warnings=inv.warnings,
        ))
    return rows


def _progress_event(search: MacSearch) -> dict:
    return {
        "type": "progress",
        "search_id": search.id,
        "status": search.status,
        "total": search.total_switches,
        "checked": search.checked,
        "found": search.found_count,
        "failed": search.failed_count,
        "timeout": search.timeout_count,
    }


async def run_search(search_id: str) -> None:
    factory = session_factory()
    async with factory() as db:
        search = await db.get(MacSearch, search_id)
        if search is None:
            return
        try:
            await _run(db, search)
        except Exception:  # noqa: BLE001
            log.exception("MAC search %s failed", search_id)
            await db.rollback()
            search = await db.get(MacSearch, search_id)
            if search is not None:
                search.status = SearchStatus.FAILED.value
                search.finished_at = utcnow()
                await db.commit()
                broker.publish(search_id, _progress_event(search))
        finally:
            broker.publish(search_id, {"type": "done", "search_id": search_id})


async def _run(db: AsyncSession, search: MacSearch) -> None:
    ids = search.options.get("switch_ids") or []
    switches = {s.id: s for s in (await db.execute(
        select(Switch).where(Switch.id.in_(ids))
    )).scalars()}
    profiles = await load_profiles(db)
    known = await known_switches(db)

    jobs: list[SwitchJob] = []
    for sw in switches.values():
        try:
            target = await build_target(db, sw)
            jobs.append(SwitchJob(_snapshot(sw), target))
        except AppError as exc:
            jobs.append(SwitchJob(_snapshot(sw), None, exc.message))

    search.status = SearchStatus.RUNNING.value
    search.started_at = utcnow()
    search.total_switches = len(jobs)
    await db.commit()
    broker.publish(search.id, _progress_event(search))

    include_lldp = bool(search.options.get("include_lldp", True))
    include_count = bool(search.options.get("include_mac_count", True))
    try:
        role = Role(search.options.get("role", Role.READONLY.value))
    except ValueError:
        role = Role.READONLY
    ctx = ExecutionContext(search.requested_by_id, search.requested_by, role,
                           str(search.options.get("purpose") or "MAC_SEARCH"),
                           reference=search.id)
    mode = search.mode or "STANDARD"
    tasks = [asyncio.create_task(_search_switch(j, search.mac, profiles, include_lldp,
                                                include_count, ctx, mode, known)) for j in jobs]
    all_rows: list[MacSearchResult] = []
    for next_done in asyncio.as_completed(tasks):
        outcome = await next_done
        rows = _result_rows(search.id, outcome)
        db.add_all(rows)
        all_rows.extend(rows)

        sw = switches.get(outcome.job.snapshot.id)
        if sw is not None:
            if outcome.detected_version:
                sw.aos_version = outcome.detected_version
            if outcome.detected_model:
                sw.model = outcome.detected_model
            if outcome.reachable:
                mark_success(sw)
            elif outcome.switch_error is not None:
                mark_failure(sw, outcome.switch_error)
            elif outcome.status == SwitchResultStatus.TIMEOUT.value:
                sw.status, sw.last_check_at = "offline", utcnow()
                sw.last_error = f"TIMEOUT: {outcome.error}"

        search.checked += 1
        if outcome.status == SwitchResultStatus.FOUND.value:
            search.found_count += 1
            log.info("MAC %s found on %s (%s)", search.mac, outcome.job.snapshot.name,
                     ", ".join(r.port or r.interface_raw for r in rows))
        elif outcome.status == SwitchResultStatus.TIMEOUT.value:
            search.timeout_count += 1
        elif outcome.status in FAILURE_STATUSES:
            search.failed_count += 1
        await db.commit()
        broker.publish(search.id, {
            "type": "switch",
            "search_id": search.id,
            "switch_id": outcome.job.snapshot.id,
            "switch_name": outcome.job.snapshot.name,
            "status": outcome.status,
            "error": outcome.error,
            "locations": len(outcome.investigations),
            "duration_ms": outcome.duration_ms,
        })
        broker.publish(search.id, _progress_event(search))

    roles = {s.name: s.role or "unknown" for s in switches.values()}
    search.summary = await _summarize(db, search, all_rows, roles)
    search.status = SearchStatus.COMPLETED.value
    search.finished_at = utcnow()
    if search.started_at:
        search.duration_ms = int((search.finished_at - search.started_at).total_seconds() * 1000)
    await db.commit()
    broker.publish(search.id, _progress_event(search))
    log.info("MAC search %s completed: %d found, %d failed, %d timeout", search.id,
             search.found_count, search.failed_count, search.timeout_count)


async def _summarize(db: AsyncSession, search: MacSearch, rows: list[MacSearchResult],
                     roles: dict[str, str] | None = None) -> dict:
    found = [r for r in rows if r.status == SwitchResultStatus.FOUND.value]
    edge = [r for r in found if r.classification in EDGE_CLASSES and r.port and not r.is_linkagg]
    alerts = get_recorder()
    summary: dict = {
        "mode": search.mode,
        "path": build_path(rows, roles),
        "found": bool(found),
        "locations": len(found),
        "switches_with_mac": len({r.switch_name for r in found}),
        "multiple_locations": len(found) > 1,
        "multiple_location_reasons": MULTIPLE_LOCATION_REASONS if len(found) > 1 else [],
        "edge_candidates": len(edge),
        "likely_edge": None,
        "mac_move": None,
        "failed_switches": sorted({r.switch_name for r in rows
                                   if r.status in FAILURE_STATUSES or r.status == "timeout"}),
    }
    if len(edge) == 1:
        e = edge[0]
        summary["likely_edge"] = {"switch_name": e.switch_name, "port": e.port,
                                  "vlan_id": e.vlan_id, "classification": e.classification}
        previous = (await db.execute(
            select(MacSighting).where(MacSighting.mac == search.mac)
            .order_by(desc(MacSighting.seen_at)).limit(1)
        )).scalar_one_or_none()
        now = utcnow()
        if previous and (previous.switch_name, previous.port) != (e.switch_name, e.port):
            summary["mac_move"] = {
                "previous": {"switch_name": previous.switch_name, "port": previous.port,
                             "vlan_id": previous.vlan_id, "seen_at": previous.seen_at.isoformat()},
                "current": {"switch_name": e.switch_name, "port": e.port, "vlan_id": e.vlan_id,
                            "seen_at": now.isoformat()},
            }
            log.warning("MAC MOVE %s: %s %s -> %s %s", search.mac, previous.switch_name,
                        previous.port, e.switch_name, e.port)
            alerts.submit(AlertItem(
                kind="MAC_MOVE", severity="WARNING", title=f"MAC move {format_mac(search.mac)}",
                message=f"{format_mac(search.mac)} moved from {previous.switch_name} "
                        f"{previous.port} to {e.switch_name} {e.port}.",
                switch_name=e.switch_name, port=e.port, mac=search.mac,
                dedupe_key=f"mac-move:{search.mac}:{e.switch_name}:{e.port}",
                details={"search_id": search.id, **summary["mac_move"]}))
        db.add(MacSighting(mac=search.mac, switch_id=e.switch_id, switch_name=e.switch_name,
                           port=e.port, vlan_id=e.vlan_id, search_id=search.id, seen_at=now))
    elif len(edge) > 1:
        summary["edge_warning"] = (
            f"The MAC appears on {len(edge)} access-like ports at the same time. Possible "
            "duplicate MAC, loop through an unmanaged device, or virtualization."
        )
        alerts.submit(AlertItem(
            kind="MULTIPLE_LOCATIONS", severity="WARNING",
            title=f"Multiple locations detected for {format_mac(search.mac)}",
            message=summary["edge_warning"], mac=search.mac,
            dedupe_key=f"multi:{search.mac}",
            details={"search_id": search.id,
                     "locations": [f"{r.switch_name} {r.port}" for r in edge]}))
    for r in found:
        declared = any(str(c.get("text", "")).startswith("Port is declared as an uplink")
                       for c in r.classification_reasons or [])
        if r.classification in TRUNK_CLASSES and r.port and not r.is_linkagg and not declared:
            alerts.submit(AlertItem(
                kind="UNEXPECTED_TRUNK", severity="INFO",
                title=f"Undeclared trunk-like port {r.switch_name} {r.port}",
                message=f"{r.switch_name} {r.port} is classified {r.classification} from its "
                        "evidence but is not declared as an uplink in the inventory. Review the "
                        "inventory (declare the uplink) or the port configuration.",
                switch_name=r.switch_name, port=r.port,
                dedupe_key=f"trunk:{r.switch_name}:{r.port}",
                details={"search_id": search.id, "classification": r.classification}))
    return summary


async def mark_interrupted_searches(db: AsyncSession) -> int:
    rows = (await db.execute(select(MacSearch).where(
        MacSearch.status.in_([SearchStatus.QUEUED.value, SearchStatus.RUNNING.value])
    ))).scalars().all()
    for row in rows:
        row.status = SearchStatus.INTERRUPTED.value
        row.finished_at = utcnow()
    await db.commit()
    return len(rows)
