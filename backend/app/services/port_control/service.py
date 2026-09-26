"""Controlled port restart (link bounce / PoE power cycle) — RESTART_PORT.

    READ FIRST → ANALYZE SECOND → CHANGE LAST

1. ``prepare_restart`` (read-only, through the Command Safety Firewall): verify the user, switch,
   port and MAC; re-read VLANs/status/LLDP/MAC count and classify the port; evaluate the restart
   policy (role, classification, topology role, operation mode); run the firewall's COMMAND SAFETY
   TEST on the exact commands. Stores a single-use, user-bound, expiring plan and a ``plan``
   snapshot of the port.
2. ``execute_restart``: exact confirmation ("RESTART PORT <port>"; none for the simplified
   MAC_OPERATOR flow, which only ever reaches confident ACCESS ports), operation mode / kill
   switch / SAFE MODE, dry-run, rate limits, DB-backed switch + port locks, and finally a
   firewall-issued RestartAuthorization. Without every one of these, no command is sent.
3. ``_run_bounce`` (background, shielded): pre-restart re-verification against the plan snapshot
   ("Network state changed since confirmation. Operation cancelled for safety."), ``before``
   snapshot, then ``down`` → hold → ``up`` via the firewall (down ≤ 1, up ≤ 2 per
   authorization), then post-restart verification and an ``after`` snapshot (change report).

Never retried blindly: the down command is never re-sent. After an ambiguous result (timeout
without a response) the port's admin state is READ before anything else is sent, and the
restore command is only sent when the port is (or may be) down.

Nothing here ever runs automatically; every path starts from an explicit user confirmation.
"""

from __future__ import annotations

import asyncio
import time
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import (
    AppError,
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
    ValidationFailedError,
)
from app.core.logging import get_logger, log_security
from app.core.timeutil import utcnow
from app.db.session import session_factory
from app.models import (
    MacSearch,
    MacSearchResult,
    OperationLock,
    PortAction,
    PortActionStatus,
    PortSnapshot,
    Role,
    Switch,
    User,
)
from app.parsers.common import format_mac
from app.security.firewall import (
    CommandBlocked,
    ExecutionContext,
    RestartAuthorization,
    UnexpectedOutput,
    get_firewall,
)
from app.security.recorder import AlertItem, get_recorder
from app.security.restart_policy import (
    check_phrases,
    endpoint_evidence_problems,
    evaluate_restart_policy,
)
from app.security.validators import MacAddressValidator, ParameterRejected, PortValidator
from app.services import system_settings
from app.services.alcatel.adapter import AlcatelAdapter
from app.services.alcatel.investigation import PortInvestigation, investigate
from app.services.alcatel.profiles import BounceMethod, CommandProfile
from app.services.alcatel.registry import choose_strategy, load_profiles, select_profile
from app.services.audit.service import record
from app.services.classification.engine import PortClass
from app.services.integrations.netbox import endpoint_port_evidence
from app.services.inventory.service import build_target, known_switches
from app.services.ssh.errors import CommandFailed, SwitchError
from app.services.ssh.manager import ConnectionTarget, get_connector
from app.workers.tasks import spawn

log = get_logger("port_control")

RECOVERY_WINDOW_SECONDS = 90
LOCK_TTL = timedelta(minutes=15)
LIVE_STATUSES = [PortActionStatus.RUNNING.value, PortActionStatus.SUCCESS.value,
                 PortActionStatus.FAILED.value, PortActionStatus.ABORTED.value,
                 PortActionStatus.INTERRUPTED.value]
STATE_CHANGED = "Network state changed since confirmation. Operation cancelled for safety."
MAC_NOT_RELEARNED = "WARNING: MAC has not been relearned"
LINK_BOUNCE_STRATEGIES = {"INTERFACE_ADMIN_STATE", "INTERFACE_ADMIN"}


def _step(action: PortAction, name: str, ok: bool, message: str = "", **extra) -> None:
    entry = {"step": name, "ok": ok, "message": message, "at": utcnow().isoformat(), **extra}
    action.steps = [*(action.steps or []), entry]


async def _reject_parameter(db: AsyncSession, user: User, ip: str, exc: ParameterRejected,
                            **target) -> None:
    await record(db, action="INJECTION_ATTEMPT" if exc.severity.value in {"HIGH", "CRITICAL"}
                 else "INVALID_PARAMETER", result="BLOCKED", severity=exc.severity.value,
                 user=user, ip=ip, operation="RESTART_PORT",
                 message=f"RESTART_PORT blocked: invalid {exc.parameter}",
                 details={"operation": "RESTART_PORT", "parameter": exc.parameter,
                          "value": exc.value_preview, "commands_executed": 0}, **target)
    raise ValidationFailedError(f"COMMAND BLOCKED BY SAFETY POLICY. Invalid parameter "
                                f"'{exc.parameter}': {exc.reason}. No command was executed.",
                                code="COMMAND_BLOCKED")


# ------------------------------------------------------------------------------ snapshots ---
def snapshot_data(mac: str, port: str, entries, inv: PortInvestigation | None) -> dict:
    """Structured, comparable description of a port (§53 configuration snapshot)."""
    on_port = [e for e in entries if e.port == port]
    data: dict = {
        "mac": mac,
        "mac_on_port": bool(on_port),
        "mac_vlan": on_port[0].vlan_id if on_port else None,
        "mac_locations": sorted({e.port or e.interface_raw for e in entries}),
    }
    if inv is not None:
        d = inv.detail
        c = inv.classification
        data.update({
            "admin_status": d.admin_status if d else None,
            "oper_status": d.oper_status if d else None,
            "speed": d.speed_mbps if d else None,
            "alias": d.alias if d else None,
            "vlans": sorted(({"vlan_id": v.vlan_id, "tagged": v.tagged}
                             for v in inv.vlans or []), key=lambda v: v["vlan_id"]),
            "vlans_known": inv.vlans is not None,
            "lldp": sorted({(n.system_name or n.chassis_id or "?") for n in inv.lldp or []}),
            "lldp_known": inv.lldp is not None,
            "mac_count": inv.mac_count,
            "classification": c.category.value if c else PortClass.UNKNOWN.value,
            "confidence": c.confidence if c else "",
            "declared_uplink": inv.declared_uplink,
        })
    return data


def state_changes(plan: dict, now: dict) -> list[str]:
    """Differences that make a confirmed plan unsafe to execute (§21). Empty = unchanged."""
    problems = []
    if not now.get("mac_on_port"):
        problems.append(f"the MAC is no longer learned on the port (now: "
                        f"{', '.join(now.get('mac_locations') or []) or 'nowhere'})")
    if now.get("classification") != plan.get("classification"):
        problems.append(f"classification changed from {plan.get('classification')} to "
                        f"{now.get('classification')}")
    if now.get("declared_uplink"):
        problems.append("the port is now declared as an uplink")
    for key, label in (("vlans", "VLAN membership"), ("lldp", "LLDP neighbors"),
                       ("admin_status", "admin state"), ("oper_status", "operational state")):
        if plan.get(key) != now.get(key):
            problems.append(f"{label} changed ({plan.get(key)} → {now.get(key)})")
    if plan.get("mac_vlan") is not None and now.get("mac_vlan") != plan.get("mac_vlan"):
        problems.append(f"MAC VLAN changed ({plan.get('mac_vlan')} → {now.get('mac_vlan')})")
    return problems


async def _save_snapshot(db: AsyncSession, action: PortAction, phase: str, data: dict) -> None:
    db.add(PortSnapshot(action_id=action.id, phase=phase, switch_name=action.switch_name,
                        port=action.port, data=data))
    await db.commit()


async def _latest_snapshot(db: AsyncSession, action_id: int, phase: str) -> dict | None:
    row = (await db.execute(select(PortSnapshot).where(
        PortSnapshot.action_id == action_id, PortSnapshot.phase == phase,
    ).order_by(PortSnapshot.id.desc()).limit(1))).scalar_one_or_none()
    return row.data if row else None


async def _read_port(adapter: AlcatelAdapter, switch: Switch, port: str, mac: str,
                     known: frozenset[str]) -> tuple[list, PortInvestigation | None]:
    entries, _ = await adapter.find_mac(mac)
    on_port = [e for e in entries if e.port == port]
    inv = None
    if on_port:
        inv = await investigate(adapter, on_port[0], uplink_ports=switch.uplink_ports or [],
                                include_lldp=True, include_mac_count=True,
                                switch_role=switch.role or "",
                                known_switches=known - {switch.name.lower(),
                                                        switch.host.lower()})
    return entries, inv


# ---------------------------------------------------------------------------------- prepare ---
async def prepare_restart(
    db: AsyncSession,
    user: User,
    *,
    method: str,
    search_result_id: int | None = None,
    switch_id: int | None = None,
    port: str | None = None,
    mac: str | None = None,
    ip: str = "",
) -> PortAction:
    if user.role_enum is Role.READONLY:
        raise PermissionDeniedError("Read-only users cannot restart ports.")
    try:
        bounce_method = BounceMethod(method)
    except ValueError as exc:
        raise ValidationFailedError("Method must be 'link_bounce' or 'poe_cycle'.") from exc

    search_id = None
    if search_result_id is not None:
        row = await db.get(MacSearchResult, search_result_id)
        if row is None:
            raise NotFoundError("Search result not found.")
        if row.status != "found" or not row.port:
            raise ValidationFailedError("This search result does not identify a physical port.")
        search = await db.get(MacSearch, row.search_id)
        switch_id, port, mac, search_id = row.switch_id, row.port, search.mac if search else None, \
            row.search_id
    if switch_id is None or not port or not mac:
        raise ValidationFailedError("switch_id, port and mac are required.")
    try:
        mac = MacAddressValidator.validate(mac)
    except ParameterRejected as exc:
        await _reject_parameter(db, user, ip, exc)

    switch = await db.get(Switch, switch_id)
    if switch is None:
        raise NotFoundError("Switch not found.")
    if not switch.enabled:
        raise AppError("The switch is disabled in the inventory.", code="SWITCH_DISABLED")

    profiles = await load_profiles(db)
    profile, profile_reason = select_profile(profiles, switch)
    if profile is None:
        raise AppError(f"PORT RESTART NOT AVAILABLE. COMMAND BLOCKED: {profile_reason} No "
                       "command was executed.", title="PORT RESTART NOT AVAILABLE",
                       code="NO_PROFILE")
    try:
        port = PortValidator.validate(port, profile.family)
    except ParameterRejected as exc:
        await _reject_parameter(db, user, ip, exc, switch_name=switch.name)

    settings = await system_settings.get_all(db)
    firewall = get_firewall()
    action = PortAction(
        method=bounce_method.value, profile_key=profile.key, switch_id=switch.id,
        switch_name=switch.name, switch_host=switch.host, aos_version=switch.aos_version,
        port=port, mac=mac, requested_by_id=user.id, requested_by=user.username,
        search_id=search_id, search_result_id=search_result_id,
        dry_run=bool(settings["dry_run_mode"]),
        expires_at=utcnow() + timedelta(seconds=int(settings["restart_plan_ttl_seconds"])),
    )
    ctx = ExecutionContext.for_user(user, "RESTART_PREPARE", ip, reference=f"{switch.name} {port}")
    snapshot: dict | None = None

    def deny(reason: str) -> PortAction:
        action.status = PortActionStatus.DENIED.value
        action.available = False
        action.blocked_reason = reason
        return action

    # ---- fresh, read-only re-check through the firewall -------------------------------------
    known = await known_switches(db)
    target = await build_target(db, switch)
    try:
        async with get_connector().session(target, ctx) as fs:
            await fs.bind_profile(profile, model=switch.model or None,
                                  version=switch.aos_version or None)
            adapter = AlcatelAdapter(fs)
            entries, inv = await _read_port(adapter, switch, port, mac, known)
            snapshot = snapshot_data(mac, port, entries, inv)
            _step(action, "recheck", True, "Read-only re-check completed",
                  commands=fs.executed_commands())
    except (SwitchError, UnexpectedOutput) as exc:
        _step(action, "recheck", False, f"{exc.title}: {exc.reason}")
        deny(f"Re-check failed: {exc.title}: {exc.reason}. No changes were made.")
        return await _save_plan(db, action, user, ip)

    if inv is None:
        elsewhere = ", ".join(snapshot["mac_locations"]) or "nowhere"
        return await _save_plan(db, deny(
            f"MAC {format_mac(mac)} is no longer learned on {port} (currently: {elsewhere}). "
            "Run a new search before restarting."), user, ip, snapshot)

    if snapshot.get("admin_status") == "disabled":
        return await _save_plan(db, deny(
            "PORT RESTART BLOCKED. The port is administratively disabled; a restart would "
            "enable it, which is a configuration change. No command was executed."),
            user, ip, snapshot)

    c = inv.classification
    assert c is not None
    action.vlan_id = snapshot["mac_vlan"]
    action.vlans = inv.vlans_as_dicts()
    action.classification = c.category.value
    action.classification_confidence = c.confidence
    action.classification_reasons = [r.to_dict() for r in c.reasons]

    state = await firewall.safety_state()
    policy = evaluate_restart_policy(
        category=c.category, role=user.role_enum, port=port, declared_uplink=inv.declared_uplink,
        is_linkagg=inv.entry.is_linkagg, mode=state.mode,
        operator_classes=set(settings["operator_restart_classes"]),
        switch_role=switch.role or "", confidence=c.confidence, mac_count=inv.mac_count,
    )
    action.risk_level = policy.risk_level
    action.required_phrases = policy.required_phrases
    action.warnings = policy.warnings + inv.warnings
    action.trunk_override = policy.trunk_override
    if not policy.allowed:
        return await _save_plan(db, deny(policy.blocked_reason), user, ip, snapshot)

    # NetBox (read-only), when configured: documentation that contradicts an endpoint port.
    verdict, nb_detail = await endpoint_port_evidence(switch.name, port)
    if verdict != "not_configured":
        _step(action, "netbox", verdict not in {"contradicts", "unavailable"}, nb_detail,
              verdict=verdict)
    if user.role_enum is Role.MAC_OPERATOR:
        # No human approval in this flow, so every independent signal must agree.
        problems = endpoint_evidence_problems(snapshot, switch.role or "")
        if verdict in {"contradicts", "unavailable"}:
            problems.append(nb_detail)
        if problems:
            return await _save_plan(db, deny(
                "RESTART BLOCKED for the simplified flow: " + "; ".join(problems)
                + ". No command was executed."), user, ip, snapshot)
    elif verdict == "contradicts":
        action.warnings = [*action.warnings, f"NetBox: {nb_detail}"]

    choice = await choose_strategy(db, profile, switch, bounce_method)
    if not choice.dry_run_possible:
        return await _save_plan(db, deny(
            f"PORT RESTART NOT AVAILABLE. No verified {bounce_method.value.replace('_', ' ')} "
            f"command profile exists for this switch. {choice.reason} No command was executed."),
            user, ip, snapshot)
    assert choice.strategy is not None
    block = state.state_changing_block_reason(user.role_enum)
    report = await firewall.safety_test(ctx, device=switch.name, port=port, profile=profile,
                                        strategy_spec=choice.strategy,
                                        execution_reason=block or "")
    action.safety_report = report.to_dict()
    if report.safety != "PASS":
        return await _save_plan(db, deny("PORT RESTART BLOCKED. The generated commands failed the "
                                         "safety test. No command was executed."), user, ip,
                                snapshot)
    action.strategy = choice.strategy.strategy.value
    action.commands = [cmd["text"] for cmd in report.commands]
    action.available = True
    action.execution_allowed = choice.available and block is None
    notes = [choice.reason] if not choice.available else []
    if block:
        notes.append(block)
    action.execution_note = " ".join(notes) or choice.reason
    if not action.execution_allowed:
        action.dry_run = True
    return await _save_plan(db, action, user, ip, snapshot)


async def _save_plan(db: AsyncSession, action: PortAction, user: User, ip: str,
                     snapshot: dict | None = None) -> PortAction:
    db.add(action)
    await db.commit()
    if snapshot is not None:
        await _save_snapshot(db, action, "plan", snapshot)
    fps = [c.get("fingerprint", "") for c in (action.safety_report or {}).get("commands", [])]
    await record(
        db, action="PORT_RESTART_PREPARE",
        result="INFO" if action.status == PortActionStatus.PLANNED.value else "DENIED",
        user=user, ip=ip, mac=action.mac, switch_name=action.switch_name, port=action.port,
        target_type="port_action", target_id=action.id, operation="RESTART_PORT",
        vlan=action.vlan_id, profile=action.profile_key, risk_level=action.risk_level,
        fingerprint=fps[0] if fps else "", before_state=snapshot,
        message=action.blocked_reason or f"Plan prepared ({action.classification}, "
                                         f"{'dry run' if action.dry_run else 'live'})",
        details={"classification": action.classification, "commands": action.commands,
                 "fingerprints": fps, "strategy": action.strategy, "method": action.method},
    )
    return action


# ---------------------------------------------------------------------------------- execute ---
async def _check_rate_limits(db: AsyncSession, user: User, action: PortAction,
                             settings: dict) -> str | None:
    now = utcnow()
    recent = (await db.execute(select(func.count()).select_from(PortAction).where(
        PortAction.requested_by_id == user.id, PortAction.dry_run.is_(False),
        PortAction.status.in_(LIVE_STATUSES),
        PortAction.started_at >= now - timedelta(minutes=10),
    ))).scalar_one()
    limit = int(settings["max_restarts_per_10_minutes"])
    if recent >= limit:
        return f"Rate limit: at most {limit} port restarts per 10 minutes per user."
    last = (await db.execute(select(func.max(PortAction.started_at)).where(
        PortAction.switch_id == action.switch_id, PortAction.port == action.port,
        PortAction.dry_run.is_(False), PortAction.status.in_(LIVE_STATUSES),
    ))).scalar_one()
    interval = int(settings["min_port_restart_interval_seconds"])
    if last is not None:
        if last.tzinfo is None:
            from datetime import timezone

            last = last.replace(tzinfo=timezone.utc)
        if (now - last).total_seconds() < interval:
            return (f"{action.switch_name} {action.port} was restarted less than {interval}s ago; "
                    "wait before restarting it again.")
    return None


async def acquire_locks(switch_id: int, switch_name: str, port: str, action_id: int,
                        holder: str, operation: str = "RESTART_PORT") -> None:
    """Database-backed switch lock + port lock (§28), taken atomically. Raises ConflictError if
    another state-changing operation holds either."""
    async with session_factory()() as db:
        now = utcnow()
        await db.execute(delete(OperationLock).where(OperationLock.expires_at < now))
        common = dict(switch_id=switch_id, switch_name=switch_name, operation=operation,
                      action_id=action_id, holder=holder, acquired_at=now,
                      expires_at=now + LOCK_TTL)
        db.add(OperationLock(scope="switch", target_key=str(switch_id), port="", **common))
        db.add(OperationLock(scope="port", target_key=f"{switch_id}:{port}", port=port,
                             **common))
        try:
            await db.commit()
        except IntegrityError as exc:
            await db.rollback()
            held = (await db.execute(select(OperationLock).where(
                OperationLock.switch_id == switch_id))).scalars().all()
            what = "port" if any(h.port == port for h in held) else "switch"
            raise ConflictError(f"{what.upper()} LOCKED: another state-changing operation is in "
                                f"progress on this {what}. No second command was executed.",
                                code="PORT_LOCKED" if what == "port" else "SWITCH_LOCKED"
                                ) from exc


async def release_locks(action_id: int) -> None:
    async with session_factory()() as db:
        await db.execute(delete(OperationLock).where(OperationLock.action_id == action_id))
        await db.commit()


def _approval_text(role: Role, phrases: list[str]) -> str:
    if role is Role.MAC_OPERATOR:
        return "simple confirmation (MAC_OPERATOR)"
    return ("confirmed: " + " + ".join(phrases))[:128] if phrases else "confirmed"


async def execute_restart(db: AsyncSession, user: User, *, plan_token: str,
                          confirmations: list[str], reason: str = "", ip: str = "") -> PortAction:
    action = (await db.execute(
        select(PortAction).where(PortAction.plan_token == plan_token)
    )).scalar_one_or_none()
    if action is None:
        raise NotFoundError("Restart plan not found.")
    if action.requested_by_id != user.id:
        raise PermissionDeniedError("A restart plan can only be confirmed by the user who "
                                    "prepared it.")
    if action.status != PortActionStatus.PLANNED.value:
        raise ConflictError(f"This restart plan is {action.status} and cannot be executed. "
                            "Prepare a new one.")
    if action.expires_at and utcnow() > action.expires_at:
        action.status = PortActionStatus.EXPIRED.value
        await db.commit()
        raise ConflictError("The restart plan expired. Re-check the port and confirm again.",
                            action="Prepare a new restart plan")

    settings = await system_settings.get_all(db)
    firewall = get_firewall()
    state = await firewall.safety_state()
    switch = await db.get(Switch, action.switch_id) if action.switch_id else None
    try:
        planned_class = PortClass(action.classification)
    except ValueError:
        planned_class = PortClass.UNKNOWN
    policy = evaluate_restart_policy(
        category=planned_class, role=user.role_enum, port=action.port,
        declared_uplink=bool(switch and action.port in (switch.uplink_ports or [])),
        is_linkagg=False, mode=state.mode,
        operator_classes=set(settings["operator_restart_classes"]),
        switch_role=(switch.role if switch else "") or "",
        confidence=action.classification_confidence,
    )
    audit = dict(user=user, ip=ip, mac=action.mac, switch_name=action.switch_name,
                 port=action.port, target_type="port_action", target_id=action.id,
                 operation="RESTART_PORT", vlan=action.vlan_id, profile=action.profile_key,
                 risk_level=action.risk_level)
    if not policy.allowed or not action.available:
        action.status = PortActionStatus.DENIED.value
        action.blocked_reason = policy.blocked_reason or action.blocked_reason
        await db.commit()
        await record(db, action="PORT_RESTART", result="DENIED", message=action.blocked_reason,
                     severity="WARNING", **audit)
        raise PermissionDeniedError(action.blocked_reason or "Restart not permitted.")

    if not check_phrases(action.required_phrases, confirmations):
        await record(db, action="PORT_RESTART", result="DENIED",
                     message="Confirmation text did not match", **audit)
        raise ValidationFailedError(
            "Confirmation text does not match. Type exactly: "
            + " / ".join(action.required_phrases),
            code="CONFIRMATION_MISMATCH",
        )

    action.confirmed_at = utcnow()
    action.reason = (reason or "User requested port restart")[:500]
    ctx = ExecutionContext.for_user(user, "RESTART_EXECUTE", ip, reference=str(action.id))
    block = state.state_changing_block_reason(user.role_enum)
    approval = _approval_text(user.role_enum, action.required_phrases)

    profile = (await load_profiles(db)).get(action.profile_key)
    strategy_spec = next((s for s in (profile.strategies if profile else ())
                          if s.strategy.value == action.strategy), None)

    async def safety_test(reason_text: str) -> None:
        if profile is not None and strategy_spec is not None:
            report = await firewall.safety_test(ctx, device=action.switch_name, port=action.port,
                                                profile=profile, strategy_spec=strategy_spec,
                                                execution_reason=reason_text)
            action.safety_report = report.to_dict()

    # ---- global safety modes: RESTART_PORT blocked ----------------------------------------
    if block:
        text = f"PORT RESTART BLOCKED. {block} No command was executed."
        await safety_test(block)
        action.status = PortActionStatus.DENIED.value
        action.blocked_reason = text
        action.finished_at = utcnow()
        _step(action, "blocked", False, text)
        await db.commit()
        await record(db, action="PORT_RESTART_BLOCKED", result="BLOCKED", severity="WARNING",
                     message=text, approval=approval, details={"commands_executed": 0}, **audit)
        get_recorder().submit(AlertItem(
            kind="BLOCKED_OPERATION", severity="WARNING", title="Port restart blocked",
            message=text, switch_name=action.switch_name, port=action.port, mac=action.mac,
            dedupe_key=f"restart-blocked:{action.switch_name}:{action.port}"))
        raise PermissionDeniedError(text, code="COMMAND_BLOCKED",
                                    title="COMMAND BLOCKED BY SAFETY POLICY")

    # ---- dry run / not approved: COMMAND SAFETY TEST, nothing is sent ---------------------
    reasons = []
    if settings["dry_run_mode"]:
        reasons.append("dry-run mode is enabled")
    if not action.execution_allowed:
        reasons.append(action.execution_note or "strategy not approved")
    if reasons:
        why = "; ".join(reasons)
        await safety_test(why)
        action.dry_run = True
        action.status = PortActionStatus.DRY_RUN.value
        action.finished_at = utcnow()
        action.result_message = f"DRY RUN: NO COMMANDS WERE EXECUTED ({why})."
        _step(action, "dry_run", True, action.result_message, commands=action.commands)
        await db.commit()
        fps = [c.get("fingerprint", "") for c in (action.safety_report or {}).get("commands", [])]
        await record(db, action="PORT_RESTART_DRY_RUN", result="SUCCESS",
                     message=action.result_message, approval=approval,
                     fingerprint=fps[0] if fps else "",
                     details={"commands": action.commands, "fingerprints": fps,
                              "reason": action.reason,
                              "safety": action.safety_report.get("safety"),
                              "commands_executed": 0}, **audit)
        return action

    # ---- live: rate limits, locks, firewall authorization ---------------------------------
    limited = await _check_rate_limits(db, user, action, settings)
    if limited:
        await record(db, action="PORT_RESTART_BLOCKED", result="BLOCKED", severity="WARNING",
                     message=limited, details={"commands_executed": 0}, **audit)
        raise RateLimitedError(f"PORT RESTART BLOCKED. {limited} No command was executed.")

    if switch is None or profile is None or strategy_spec is None:
        raise ConflictError("Switch, profile or strategy changed since the plan was prepared. "
                            "Prepare a new plan.")
    # Commit pending changes first: the locks are taken in their own transaction and must not
    # wait on this session (SQLite has a single writer).
    await db.commit()
    await acquire_locks(action.switch_id, action.switch_name, action.port, action.id,
                        user.username)
    try:
        auth = await firewall.authorize_restart(
            ctx, action_id=action.id, switch_id=action.switch_id, device=action.switch_name,
            port=action.port, profile=profile, strategy_spec=strategy_spec,
            classification=action.classification,
            confidence=action.classification_confidence,
            declared_uplink=action.port in (switch.uplink_ports or []), is_linkagg=False,
            switch_role=switch.role or "", model=switch.model or None,
            version=switch.aos_version or None,
            trunk_override_confirmed=action.trunk_override,
            operator_classes=set(settings["operator_restart_classes"]), confirmed=True,
        )
    except CommandBlocked as exc:
        await release_locks(action.id)
        firewall.report(ctx, exc, device=action.switch_name, port=action.port, mac=action.mac)
        action.status = PortActionStatus.DENIED.value
        action.blocked_reason = exc.reason
        await db.commit()
        await record(db, action="PORT_RESTART_BLOCKED", result="BLOCKED", severity="WARNING",
                     message=exc.reason, approval=approval, error=exc.reason,
                     details={"commands_executed": 0}, **audit)
        raise PermissionDeniedError(exc.reason, code="COMMAND_BLOCKED",
                                    title="COMMAND BLOCKED BY SAFETY POLICY") from exc

    await safety_test("")
    if action.safety_report:
        action.safety_report = {**action.safety_report, "execution": "ENABLED",
                                "result": "EXECUTING"}
    action.status = PortActionStatus.RUNNING.value
    action.started_at = utcnow()
    await db.commit()
    await record(db, action="PORT_RESTART", result="INFO", approval=approval,
                 message=f"Port restart requested: {action.reason}",
                 details={"commands": action.commands, "classification": action.classification,
                          "trunk_override": action.trunk_override}, **audit)
    spawn(_run_bounce(action.id, auth, ctx, approval), name=f"port-action-{action.id}")
    return action


# ------------------------------------------------------------------------------ background ---
async def _run_bounce(action_id: int, auth: RestartAuthorization, ctx: ExecutionContext,
                      approval: str = "") -> None:
    # Shield: once started, a client disconnect or request cancellation must not stop the "up".
    await asyncio.shield(_run_bounce_inner(action_id, auth, ctx, approval))


async def _run_bounce_inner(action_id: int, auth: RestartAuthorization,
                            ctx: ExecutionContext, approval: str) -> None:
    async with session_factory()() as db:
        action = await db.get(PortAction, action_id)
        if action is None:
            return
        try:
            await _bounce(db, action, auth, ctx, approval)
        except Exception as exc:  # noqa: BLE001
            log.exception("Port action %s crashed", action_id)
            await db.rollback()
            action = await db.get(PortAction, action_id)
            if action is not None:
                await _finish(db, action, PortActionStatus.FAILED, ctx,
                              f"Internal error ({exc.__class__.__name__}). Check the port "
                              "state on the switch manually.", approval=approval)
        finally:
            get_firewall().close_authorization(auth)
            await release_locks(action_id)


async def _bounce(db: AsyncSession, action: PortAction, auth: RestartAuthorization,
                  ctx: ExecutionContext, approval: str) -> None:
    switch = await db.get(Switch, action.switch_id) if action.switch_id else None
    if switch is None:
        await _finish(db, action, PortActionStatus.ABORTED, ctx,
                      "Switch no longer exists. Nothing was changed.", approval=approval)
        return
    profile = (await load_profiles(db)).get(action.profile_key)
    if profile is None:
        await _finish(db, action, PortActionStatus.ABORTED, ctx,
                      "Command profile no longer exists. Nothing was changed.",
                      approval=approval)
        return
    settings = await system_settings.get_all(db)
    known = await known_switches(db)
    plan = await _latest_snapshot(db, action.id, "plan")
    target = await build_target(db, switch)
    hold = int(settings["port_bounce_hold_seconds"])
    down_attempted = down_sent = up_ok = False
    ambiguous = False
    before: dict | None = None

    try:
        async with get_connector().session(target, ctx) as fs:
            await fs.bind_profile(profile, model=switch.model or None,
                                  version=switch.aos_version or None)
            adapter = AlcatelAdapter(fs)
            # §21 pre-restart re-verification, immediately before the change.
            entries, inv = await _read_port(adapter, switch, action.port, action.mac, known)
            before = snapshot_data(action.mac, action.port, entries, inv)
            await _save_snapshot(db, action, "before", before)
            changes = state_changes(plan or {}, before) if plan else [
                "no confirmed plan snapshot exists"]
            if not changes and ctx.role is Role.MAC_OPERATOR:
                changes = endpoint_evidence_problems(before, switch.role or "")
            if changes:
                _step(action, "pre_restart_verification", False, STATE_CHANGED, changes=changes)
                await _finish(db, action, PortActionStatus.ABORTED, ctx,
                              f"{STATE_CHANGED} ({'; '.join(changes)}). Nothing was changed.",
                              approval=approval, before=before)
                return
            _step(action, "pre_restart_verification", True,
                  f"Unchanged since confirmation: MAC on {action.port}, "
                  f"{before.get('classification')}")
            await db.commit()

            async with fs.restart(auth) as restart:
                down_attempted = True
                try:
                    await restart.down()
                except CommandBlocked as exc:
                    _step(action, "down", False, f"Blocked: {exc.reason}")
                    await _finish(db, action, PortActionStatus.ABORTED, ctx,
                                  f"COMMAND BLOCKED BY SAFETY POLICY: {exc.reason}",
                                  approval=approval, before=before)
                    return
                except CommandFailed as exc:
                    _step(action, "down", False, f"Switch rejected: {exc.reason}")
                    await _finish(db, action, PortActionStatus.FAILED, ctx,
                                  f"The switch rejected the down command ({exc.reason}). The "
                                  "selected command profile may not be compatible with this AOS "
                                  "version. No configuration changes were made.",
                                  approval=approval, before=before)
                    return
                down_sent = True
                down_cmd = action.commands[0]
                _step(action, "down", True, down_cmd, fingerprint=restart.fingerprints[-1])
                action.commands_executed = [down_cmd]
                await db.commit()
                log.warning("Port %s on %s administratively DOWN (restart by %s, action %s)",
                            action.port, action.switch_name, ctx.username, action.id)
                await asyncio.sleep(hold)
                up_ok = await _send_up(restart, action, adapter)
    except SwitchError as exc:
        _step(action, "session", False, f"{exc.title}: {exc.reason}")
        if down_attempted and not down_sent and not isinstance(exc, CommandBlocked):
            # AMBIGUOUS: the down command may or may not have been applied (timeout / dropped
            # session). It is NEVER re-sent. The recovery path reads the admin state first.
            ambiguous = True
            down_sent = True
            action.commands_executed = [action.commands[0]]
        if not down_sent:
            await _finish(db, action, PortActionStatus.FAILED, ctx,
                          f"{exc.title}: {exc.reason}. The down command was NOT sent; no "
                          "configuration changes were made.", approval=approval, before=before)
            return

    up_cmd = action.commands[1]
    if down_sent and not up_ok:
        up_ok = await _recover_up(target, ctx, profile, auth, action, ambiguous=ambiguous)
    if down_sent and not up_ok:
        msg = (f"CRITICAL: the port may still be DOWN. The up command could not be confirmed. "
               f"Run '{up_cmd}' on {action.switch_name} manually.")
        log_security(log, "%s (action %s)", msg, action.id)
        _alert_failed(action, msg)
        await _finish(db, action, PortActionStatus.FAILED, ctx, msg, approval=approval,
                      before=before)
        return

    action.commands_executed = list(action.commands)
    await db.commit()
    verification = await _verify(target, ctx, profile, action, switch, known,
                                 int(settings["post_restart_verify_seconds"]))
    after = verification.pop("snapshot", None)
    if after is not None:
        await _save_snapshot(db, action, "after", after)
    verification["changes"] = compare_snapshots(before or {}, after or {})
    action.verification = verification
    if action.safety_report:
        action.safety_report = {**action.safety_report, "result": "EXECUTED"}
    if verification.get("port_status") == "up":
        if verification.get("mac_learned"):
            await _finish(db, action, PortActionStatus.SUCCESS, ctx,
                          f"PORT RESTART COMPLETED. Port {action.port}: UP. MAC: LEARNED. "
                          f"VLAN: {verification.get('mac_vlan') or '-'}", approval=approval,
                          before=before, after=after)
        else:
            get_recorder().submit(AlertItem(
                kind="MAC_NOT_RETURNED", severity="WARNING",
                title=f"MAC not relearned after restart ({action.switch_name} {action.port})",
                message=f"{format_mac(action.mac)} was not relearned on {action.port} within "
                        f"{settings['post_restart_verify_seconds']}s after the restart.",
                switch_name=action.switch_name, port=action.port, mac=action.mac,
                dedupe_key=f"mac-not-returned:{action.mac}:{action.switch_name}:{action.port}",
                details={"action_id": action.id}))
            await _finish(db, action, PortActionStatus.SUCCESS, ctx,
                          f"PORT RESTART COMPLETED. Port {action.port}: UP. {MAC_NOT_RELEARNED} "
                          f"within {settings['post_restart_verify_seconds']}s.",
                          approval=approval, before=before, after=after)
    else:
        msg = (f"Commands were sent, but port {action.port} did not return to UP within "
               f"{settings['post_restart_verify_seconds']}s "
               f"(state: {verification.get('port_status') or 'unknown'}).")
        _alert_failed(action, msg)
        await _finish(db, action, PortActionStatus.FAILED, ctx, msg, approval=approval,
                      before=before, after=after)


def _alert_failed(action: PortAction, message: str) -> None:
    get_recorder().submit(AlertItem(
        kind="RESTART_FAILED", severity="HIGH",
        title=f"Port restart failed: {action.switch_name} {action.port}", message=message,
        switch_name=action.switch_name, port=action.port, mac=action.mac,
        dedupe_key=f"restart-failed:{action.id}", details={"action_id": action.id}))


async def _admin_state(adapter: AlcatelAdapter, port: str) -> str | None:
    """Read the port's admin state (read-only). None when it cannot be determined."""
    try:
        detail = await adapter.port_detail(port)
    except (SwitchError, UnexpectedOutput):
        return None
    return (detail.admin_status or "").lower() or None


async def _send_up(restart, action: PortAction, adapter: AlcatelAdapter) -> bool:
    """Send the approved restore command. A second attempt (the firewall budget allows two) is
    only made after the admin state has been READ and shows the port is still down."""
    attempt = 0
    while True:
        attempt += 1
        try:
            await restart.up()
            _step(action, "up", True, action.commands[1], attempt=attempt,
                  fingerprint=restart.fingerprints[-1])
            return True
        except CommandBlocked as exc:
            _step(action, "up", False, f"Blocked: {exc.reason}", attempt=attempt)
            return False
        except SwitchError as exc:
            _step(action, "up", False, f"{exc.title}: {exc.reason}", attempt=attempt)
            if exc.status in {"connection_failed", "timeout"}:
                return False  # session is gone; recover with a fresh connection
            if attempt >= 2:
                return False
            await asyncio.sleep(2)
            if action.strategy in LINK_BOUNCE_STRATEGIES:
                state = await _admin_state(adapter, action.port)
                if state == "enabled":
                    _step(action, "up", True, "Admin state already enabled; no resend needed")
                    return True


async def _recover_up(target: ConnectionTarget, ctx: ExecutionContext, profile: CommandProfile,
                      auth: RestartAuthorization, action: PortAction, *,
                      ambiguous: bool = False) -> bool:
    """The session died around the down/up command (e.g. management traffic used that path).
    Keep reconnecting for a bounded window. On each new session the admin state is READ first
    (link-bounce strategies): if the port is enabled nothing is sent. The up command itself is
    still limited by the firewall budget for this authorization."""
    deadline = time.monotonic() + RECOVERY_WINDOW_SECONDS
    switch_model, switch_version = target.model, target.aos_version
    while time.monotonic() < deadline:
        try:
            async with get_connector().session(target, ctx) as fs:
                await fs.bind_profile(profile, model=switch_model, version=switch_version)
                if action.strategy in LINK_BOUNCE_STRATEGIES:
                    state = await _admin_state(AlcatelAdapter(fs), action.port)
                    if state == "enabled":
                        _step(action, "recovery", True,
                              "Admin state is enabled; the restore command was not needed"
                              + (" (the down command outcome was ambiguous)" if ambiguous
                                 else ""))
                        return True
                async with fs.restart(auth) as restart:
                    await restart.up()
                    _step(action, "recovery", True, "Up command sent on a new session",
                          fingerprint=restart.fingerprints[-1])
                    return True
        except CommandBlocked as exc:
            _step(action, "recovery", False, f"Blocked: {exc.reason}")
            return False
        except SwitchError as exc:
            _step(action, "recovery", False, f"{exc.title}: {exc.reason}")
        await asyncio.sleep(5)
    return False


async def _verify(target: ConnectionTarget, ctx: ExecutionContext, profile: CommandProfile,
                  action: PortAction, switch: Switch, known: frozenset[str],
                  timeout: int) -> dict:
    """§23 post-restart verification: port up, MAC relearned, VLAN, LLDP, classification."""
    started = time.monotonic()
    deadline = started + timeout
    interval = max(0.5, min(3.0, timeout / 20))
    result: dict = {"port_status": None, "mac_learned": False, "mac_vlan": None, "vlans": [],
                    "vlan_matches": None}
    verify_ctx = ExecutionContext(ctx.user_id, ctx.username, ctx.role, "RESTART_VERIFY", ctx.ip,
                                  ctx.reference)
    try:
        async with get_connector().session(target, verify_ctx) as fs:
            await fs.bind_profile(profile, model=target.model, version=target.aos_version)
            adapter = AlcatelAdapter(fs)
            while time.monotonic() < deadline:
                result["port_status"] = await adapter.oper_status(action.port)
                if result["port_status"] == "up":
                    entries, _ = await adapter.find_mac(action.mac)
                    on_port = [e for e in entries if e.port == action.port]
                    if on_port:
                        result["mac_learned"] = True
                        result["mac_vlan"] = on_port[0].vlan_id
                        break
                await asyncio.sleep(interval)
            if result["port_status"] == "up":
                entries, inv = await _read_port(adapter, switch, action.port, action.mac, known)
                snap = snapshot_data(action.mac, action.port, entries, inv)
                result["snapshot"] = snap
                if inv is not None and inv.vlans is not None:
                    result["vlans"] = inv.vlans_as_dicts()
                    before_vlans = {v["vlan_id"] for v in action.vlans or []}
                    result["vlan_matches"] = before_vlans == {v.vlan_id for v in inv.vlans}
                result["classification"] = snap.get("classification")
    except (SwitchError, UnexpectedOutput) as exc:
        result["error"] = f"{exc.title}: {exc.reason}"
    if not result["mac_learned"]:
        result["warning"] = MAC_NOT_RELEARNED
    result["elapsed_seconds"] = round(time.monotonic() - started, 1)
    problems = []
    if result["port_status"] != "up":
        problems.append(f"port state {result['port_status'] or 'unknown'}")
    if not result["mac_learned"]:
        problems.append("MAC not relearned on the port")
    elif action.vlan_id is not None and result["mac_vlan"] != action.vlan_id:
        problems.append(f"MAC relearned in VLAN {result['mac_vlan']}, expected {action.vlan_id}")
    if action.vlans and result["vlan_matches"] is not True:
        problems.append("port VLAN membership differs or could not be read")
    if result.get("classification") != action.classification:
        problems.append(f"classification now {result.get('classification') or 'unknown'}")
    result["verified"] = not problems
    result["verification_problems"] = problems
    return result


def compare_snapshots(before: dict, after: dict) -> list[dict]:
    """§54 change report: field-by-field differences between the before and after snapshots."""
    fields = ("mac_on_port", "mac_vlan", "admin_status", "oper_status", "speed", "alias",
              "vlans", "lldp", "mac_count", "classification")
    return [{"field": f, "before": before.get(f), "after": after.get(f),
             "changed": before.get(f) != after.get(f)} for f in fields
            if f in before or f in after]


async def change_report(db: AsyncSession, action: PortAction) -> dict:
    snaps = (await db.execute(select(PortSnapshot).where(
        PortSnapshot.action_id == action.id).order_by(PortSnapshot.id))).scalars().all()
    by_phase = {s.phase: {"data": s.data, "taken_at": s.taken_at.isoformat()} for s in snaps}
    before = (by_phase.get("before") or by_phase.get("plan") or {}).get("data") or {}
    after = (by_phase.get("after") or {}).get("data") or {}
    fingerprints = [s.get("fingerprint") for s in action.steps or [] if s.get("fingerprint")]
    return {
        "action_id": action.id, "status": action.status, "switch_name": action.switch_name,
        "port": action.port, "mac": action.mac, "requested_by": action.requested_by,
        "dry_run": action.dry_run, "commands_planned": action.commands,
        "commands_executed": action.commands_executed, "fingerprints": fingerprints,
        "snapshots": by_phase, "changes": compare_snapshots(before, after) if after else [],
        "result": action.result_message or action.blocked_reason,
        "verification": action.verification,
    }


async def _finish(db: AsyncSession, action: PortAction, status: PortActionStatus,
                  ctx: ExecutionContext, message: str, *, approval: str = "",
                  before: dict | None = None, after: dict | None = None) -> None:
    action.status = status.value
    action.finished_at = utcnow()
    action.result_message = message
    if status in (PortActionStatus.FAILED, PortActionStatus.ABORTED):
        action.error_message = message
    await db.commit()
    critical = message.startswith("CRITICAL")
    fingerprints = [s.get("fingerprint") for s in action.steps or [] if s.get("fingerprint")]
    await record(
        db, action="PORT_RESTART",
        result={PortActionStatus.SUCCESS: "SUCCESS", PortActionStatus.ABORTED: "FAILED"}.get(
            status, "FAILED"),
        username=ctx.username, role=ctx.role.value, ip=ctx.ip, mac=action.mac,
        switch_name=action.switch_name, port=action.port, target_type="port_action",
        target_id=action.id, message=message, operation="RESTART_PORT", vlan=action.vlan_id,
        profile=action.profile_key, risk_level=action.risk_level,
        fingerprint=fingerprints[0] if fingerprints else "", approval=approval,
        error=message if status is not PortActionStatus.SUCCESS else "",
        before_state=before, after_state=after,
        severity="CRITICAL" if critical else ("INFO" if status is PortActionStatus.SUCCESS
                                              else "WARNING"),
        details={"status": status.value, "commands_executed": action.commands_executed,
                 "fingerprints": fingerprints, "verification": action.verification},
    )


async def mark_interrupted_actions(db: AsyncSession) -> int:
    rows = (await db.execute(select(PortAction).where(
        PortAction.status == PortActionStatus.RUNNING.value
    ))).scalars().all()
    for row in rows:
        row.status = PortActionStatus.INTERRUPTED.value
        row.finished_at = utcnow()
        row.error_message = ("The application stopped while this action was running. Check the "
                             f"state of port {row.port} on {row.switch_name} manually.")
        log_security(log, "Port action %s was interrupted: %s", row.id, row.error_message)
    await db.execute(delete(OperationLock))  # locks of a previous process are stale by definition
    await db.commit()
    return len(rows)
