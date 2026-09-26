"""Simplified API for the MAC_OPERATOR role.

Exactly two capabilities: SEARCH_MAC (the answer is the device's human location only) and a
direct RESTART of the endpoint port — no administrator approval, but every technical safety
check stays mandatory. The client never chooses a switch, port or VLAN: the server derives the
single valid location from the user's own recent search, re-reads the port and runs the normal
restart pipeline (fresh re-check, restart policy, endpoint evidence gate, NetBox evidence,
Command Safety Firewall, operation mode / kill switch / SAFE MODE, locks, pre-restart
re-verification, post-restart verification). This module adds no bypass.

Responses never contain technical data (no switch name, port, VLAN, IP, model, command, error
text). Every technical detail is written to the audit log and the application log instead.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, require
from app.core.errors import AppError, RateLimitedError
from app.core.logging import get_logger
from app.core.permissions import Permission
from app.core.ratelimit import limiter
from app.core.timeutil import utcnow
from app.db.session import get_db
from app.models import (
    FAILURE_STATUSES,
    MacSearch,
    MacSearchResult,
    PortAction,
    PortActionStatus,
    SearchStatus,
    Switch,
    User,
)
from app.schemas.common import SimpleRestartRequest, SimpleSearchRequest
from app.security.validators import MacAddressValidator, ParameterRejected
from app.services import system_settings
from app.services.audit.service import record
from app.services.mac_search.service import EDGE_CLASSES, start_search
from app.services.port_control.service import execute_restart, prepare_restart

log = get_logger("simple")
router = APIRouter(prefix="/api/simple", tags=["simple"])

GENERIC_ERROR = "Something went wrong. Please try again or contact IT support."
NOT_FOUND = "Device Not Found. Please check the MAC address and try again."
MULTIPLE = "Multiple locations detected. Please contact IT support."
CANNOT_RESTART = "This device cannot be restarted automatically. Please contact IT support."
RESTART_OK = "Device restarted successfully."
RESTART_NOT_BACK = "The device could not be verified after restart. Please contact IT support."
RESTART_FAILED = "The device could not be restarted. Please contact IT support."
INVALID_MAC = "Please enter a valid MAC address."
NO_LOCATION = "Location not recorded"
SEARCH_MAX_AGE = timedelta(minutes=10)


def device_location(switch: Switch | None, port: str | None) -> str:
    """The only location text a MAC_OPERATOR sees: the administrator-defined label of the port,
    otherwise the switch's site and location. Never the switch name, address or port."""
    if switch is None:
        return NO_LOCATION
    label = (switch.port_locations or {}).get(port or "")
    if label:
        return label
    return " - ".join(p for p in (switch.site, switch.location) if p) or NO_LOCATION


def _msg(state: str, message: str, **extra) -> dict:
    return {"state": state, "message": message, **extra}


async def _own_search(db: AsyncSession, user: User, search_id: str) -> MacSearch | None:
    search = await db.get(MacSearch, search_id)
    if search is None or search.requested_by_id != user.id:
        return None  # another user's search is indistinguishable from a missing one
    return search


async def _switches(db: AsyncSession, rows: list[MacSearchResult]) -> dict[int, Switch]:
    ids = {r.switch_id for r in rows if r.switch_id}
    if not ids:
        return {}
    return {s.id: s for s in (await db.execute(select(Switch).where(Switch.id.in_(ids))))
            .scalars()}


def _evaluate(search: MacSearch, rows: list[MacSearchResult],
              switches: dict[int, Switch]) -> dict:
    """Decide what the simplified user sees, and whether a restart may be offered. Internal
    only: returns the chosen row id, which is never sent to the client. Offering the button is
    a preview; the restart request re-checks everything on the switch."""
    if search.status in {SearchStatus.QUEUED.value, SearchStatus.RUNNING.value}:
        return _msg("searching", "Searching…")
    if search.status != SearchStatus.COMPLETED.value:
        return _msg("error", GENERIC_ERROR)
    found = [r for r in rows if r.status == "found"]
    failed = [r for r in rows if r.status in FAILURE_STATUSES or r.status == "timeout"]
    edge = [r for r in found if r.classification in EDGE_CLASSES and r.port and not r.is_linkagg]
    if not found:
        # Not seen anywhere; if some switches could not be checked the answer is uncertain.
        return _msg("error", GENERIC_ERROR) if failed else _msg("not_found", NOT_FOUND)
    if len(edge) > 1:
        return _msg("multiple", MULTIPLE)
    if len(edge) == 1:
        e = edge[0]
        sw = switches.get(e.switch_id or 0)
        can_restart = (e.classification == "ACCESS"
                       and e.classification_confidence == "High"
                       and sw is not None and (sw.role or "") == "access"
                       and not failed)
        return _msg("found", "Device Found", location=device_location(sw, e.port),
                    can_restart=can_restart, _row_id=e.id)
    switch_ids = {r.switch_id for r in found}
    if len(switch_ids) == 1:
        sw = switches.get(next(iter(switch_ids)) or 0)
        return _msg("found", "Device Found", location=device_location(sw, None),
                    can_restart=False)
    return _msg("multiple", MULTIPLE)


def _public(result: dict) -> dict:
    return {k: v for k, v in result.items() if not k.startswith("_")}


@router.post("/search")
async def simple_search(body: SimpleSearchRequest, request: Request,
                        user: User = Depends(require(Permission.SIMPLE_SEARCH)),
                        db: AsyncSession = Depends(get_db)) -> dict:
    ip = client_ip(request)
    try:
        MacAddressValidator.validate(body.mac)
    except ParameterRejected as exc:
        high = exc.severity.value in {"HIGH", "CRITICAL"}
        await record(db, action="INJECTION_ATTEMPT" if high else "INVALID_PARAMETER",
                     result="BLOCKED", severity=exc.severity.value, user=user, ip=ip,
                     operation="SEARCH_MAC", message=f"SEARCH_MAC blocked: {exc.reason}",
                     details={"operation": "SEARCH_MAC", "parameter": "mac",
                              "value": exc.value_preview, "commands_executed": 0})
        return _msg("invalid", INVALID_MAC)
    try:
        per_minute = int(await system_settings.get_value(db, "max_mac_searches_per_minute"))
        limiter.hit(f"search:{user.id}", limit=min(per_minute, 10), window_seconds=60)
        search = await start_search(db, user, body.mac, ip=ip, mode="STANDARD",
                                    purpose="SIMPLE_SEARCH")
    except RateLimitedError:
        return _msg("error", "Too many searches. Please wait a minute and try again.")
    except Exception:  # noqa: BLE001 - never expose internals to this role
        log.exception("Simple search failed for %s", user.username)
        return _msg("error", GENERIC_ERROR)
    return {"state": "searching", "message": "Searching…", "search_id": search.id}


@router.get("/search/{search_id}")
async def simple_search_status(search_id: str,
                               user: User = Depends(require(Permission.SIMPLE_SEARCH)),
                               db: AsyncSession = Depends(get_db)) -> dict:
    try:
        search = await _own_search(db, user, search_id)
        if search is None:
            return _msg("error", GENERIC_ERROR)
        rows = list((await db.execute(select(MacSearchResult).where(
            MacSearchResult.search_id == search.id))).scalars().all())
        return _public(_evaluate(search, rows, await _switches(db, rows)))
    except Exception:  # noqa: BLE001
        log.exception("Simple search status failed")
        return _msg("error", GENERIC_ERROR)


@router.post("/restart")
async def simple_restart(body: SimpleRestartRequest, request: Request,
                         user: User = Depends(require(Permission.SIMPLE_RESTART)),
                         db: AsyncSession = Depends(get_db)) -> dict:
    """REQUEST_RESTART_PORT: the server re-derives the single valid location and runs the full
    restart pipeline. Any failed condition → RESTART BLOCKED (reason in the audit log only)."""
    ip = client_ip(request)

    async def blocked(reason: str) -> dict:
        await record(db, action="SIMPLE_RESTART_BLOCKED", result="BLOCKED", severity="WARNING",
                     user=user, ip=ip, operation="RESTART_PORT",
                     target_type="search", target_id=body.search_id, message=reason)
        return _msg("blocked", CANNOT_RESTART)

    try:
        limiter.hit(f"simple-restart:{user.id}", limit=3, window_seconds=60)
        search = await _own_search(db, user, body.search_id)
        if search is None:
            return await blocked("search not found or not owned by the user")
        if search.finished_at is None or utcnow() - search.finished_at > SEARCH_MAX_AGE:
            return await blocked("search result is too old; a new search is required")
        rows = list((await db.execute(select(MacSearchResult).where(
            MacSearchResult.search_id == search.id))).scalars().all())
        verdict = _evaluate(search, rows, await _switches(db, rows))
        if verdict["state"] != "found" or not verdict.get("can_restart"):
            return await blocked(f"not exactly one High-confidence ACCESS location on an access "
                                 f"switch (state={verdict['state']})")
        row = next(r for r in rows if r.id == verdict["_row_id"])
        # Fresh read of the switch + policy + endpoint gate + NetBox + firewall safety test.
        action = await prepare_restart(db, user, method="link_bounce",
                                       search_result_id=row.id, ip=ip)
        if action.status != PortActionStatus.PLANNED.value or not action.available \
                or not action.execution_allowed or action.dry_run \
                or action.required_phrases:
            return await blocked(f"restart plan not executable: "
                                 f"{action.blocked_reason or action.execution_note or 'dry run'}")
        if action.switch_id != row.switch_id or action.port != row.port or \
                action.vlan_id != row.vlan_id:
            return await blocked(f"network state changed since the search (switch/port/VLAN "
                                 f"{row.switch_name} {row.port} VLAN {row.vlan_id} → "
                                 f"{action.switch_name} {action.port} VLAN {action.vlan_id})")
        action = await execute_restart(db, user, plan_token=action.plan_token,
                                       confirmations=[], reason="Simple restart (MAC_OPERATOR)",
                                       ip=ip)
        if action.status != PortActionStatus.RUNNING.value:
            return await blocked(f"restart not started: {action.status}")
        return {"state": "running", "message": "Restarting the device…",
                "request_id": action.plan_token}
    except RateLimitedError:
        return _msg("error", "Please wait a minute before trying again.")
    except AppError as exc:
        return await blocked(f"{exc.code}: {exc.message}")
    except Exception:  # noqa: BLE001
        log.exception("Simple restart failed for %s", user.username)
        return _msg("error", GENERIC_ERROR)


@router.get("/restart/{request_id}")
async def simple_restart_status(request_id: str,
                                user: User = Depends(require(Permission.SIMPLE_RESTART)),
                                db: AsyncSession = Depends(get_db)) -> dict:
    try:
        action = (await db.execute(select(PortAction).where(
            PortAction.plan_token == request_id))).scalar_one_or_none()
        if action is None or action.requested_by_id != user.id:
            return _msg("error", GENERIC_ERROR)
        if action.status == PortActionStatus.RUNNING.value:
            return _msg("running", "Restarting the device…")
        if action.status == PortActionStatus.SUCCESS.value:
            # Success only when the post-restart verification fully passed (port up, MAC back
            # on the same port and VLAN, VLANs and classification unchanged).
            verified = bool((action.verification or {}).get("verified"))
            return _msg("success" if verified else "success_pending",
                        RESTART_OK if verified else RESTART_NOT_BACK)
        return _msg("failed", RESTART_FAILED)
    except Exception:  # noqa: BLE001
        log.exception("Simple restart status failed")
        return _msg("error", GENERIC_ERROR)
