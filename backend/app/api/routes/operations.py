"""Operation gateway: the client requests a predefined operation, never a command.

    POST /api/operations {"operation": "GET_PORT_VLAN", "switch_id": 27, "port": "1/1/26"}

Unknown or denied operations (EXECUTE_COMMAND, CONFIGURATION, …) are blocked and recorded as
security events. The backend generates every command through the Command Safety Firewall.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import Permission
from app.api.deps import client_ip, get_current_user, require
from app.core.errors import AppError, PermissionDeniedError, ValidationFailedError
from app.core.ratelimit import limiter
from app.db.session import get_db
from app.core.permissions import has_permission
from app.models import Role, User
from app.schemas.common import MacSearchOut, OperationRequest, PortActionOut
from app.security.policy import (
    API_OPERATIONS,
    COMMAND_POLICIES,
    DENIED_OPERATION_CATEGORIES,
    Operation,
)
from app.services import system_settings
from app.services.audit.service import record
from app.services.mac_search.service import start_search
from app.services.port_control.service import execute_restart
from app.services.port_query import PORT_OPERATIONS, query_port

router = APIRouter(prefix="/api/operations", tags=["operations"])

# The permission each operation requires (server-side RBAC, §36). MAC_OPERATOR holds none of
# these: its only entry point is the simplified /api/simple API.
OPERATION_PERMISSION = {
    Operation.SEARCH_MAC: Permission.MAC_SEARCH,
    Operation.GET_PORT_VLAN: Permission.PORT_INSPECT,
    Operation.GET_PORT_STATUS: Permission.PORT_INSPECT,
    Operation.GET_LLDP: Permission.PORT_INSPECT,
    Operation.GET_PORT_MACS: Permission.PORT_INSPECT,
    Operation.RESTART_PORT: Permission.RESTART_PORT,
}


@router.get("")
async def list_operations(_: User = Depends(require(Permission.VIEW_SAFETY))) -> dict:
    return {"operations": sorted(o.value for o in API_OPERATIONS),
            "denied_categories": list(DENIED_OPERATION_CATEGORIES)}


@router.post("")
async def run_operation(body: OperationRequest, request: Request,
                        user: User = Depends(get_current_user),
                        db: AsyncSession = Depends(get_db)) -> dict:
    ip = client_ip(request)
    name = body.operation.strip().upper()
    try:
        operation = Operation(name)
    except ValueError:
        operation = None
    if operation is None or operation not in API_OPERATIONS:
        denied = name in DENIED_OPERATION_CATEGORIES
        severity = "HIGH" if denied or "COMMAND" in name or "EXEC" in name else "WARNING"
        await record(db, action="UNKNOWN_OPERATION", result="BLOCKED", severity=severity,
                     user=user, ip=ip, message=f"Operation {name[:64]!r} is not permitted",
                     details={"operation": name[:64], "commands_executed": 0})
        raise AppError(f"COMMAND BLOCKED BY SAFETY POLICY. Operation {name[:64]!r} is not "
                       "permitted. No command was executed.", title="COMMAND BLOCKED",
                       code="COMMAND_BLOCKED", status_code=400)

    policy = COMMAND_POLICIES[operation]
    permission = OPERATION_PERMISSION.get(operation)
    if permission is None or not has_permission(user.role, permission) or \
            user.role_enum not in policy.allowed_roles:
        high = user.role_enum is Role.MAC_OPERATOR
        await record(db, action="RBAC_VIOLATION" if high else "OPERATION_DENIED",
                     result="DENIED", severity="HIGH" if high else "WARNING", user=user, ip=ip,
                     operation=operation.value,
                     message=f"{operation.value} is not permitted for role {user.role}",
                     details={"operation": operation.value, "commands_executed": 0})
        raise PermissionDeniedError("You do not have permission for this action. No command "
                                    "was executed.")

    if operation is Operation.SEARCH_MAC:
        if not body.mac:
            raise ValidationFailedError("SEARCH_MAC requires 'mac'.")
        per_minute = int(await system_settings.get_value(db, "max_mac_searches_per_minute"))
        limiter.hit(f"search:{user.id}", limit=per_minute, window_seconds=60)
        search = await start_search(db, user, body.mac, body.switch_ids, ip=ip,
                                    mode=body.mode)
        return {"operation": operation.value,
                "search": MacSearchOut.model_validate(search).model_dump(mode="json")}

    if operation in PORT_OPERATIONS:
        if body.switch_id is None or not body.port:
            raise ValidationFailedError(f"{operation.value} requires 'switch_id' and 'port'.")
        limiter.hit(f"port-info:{user.id}", limit=30, window_seconds=60)
        data = await query_port(db, user, switch_id=body.switch_id, port=body.port, mac=None,
                                ip=ip, operations={operation})
        return {"operation": operation.value, **data}

    if operation is Operation.RESTART_PORT:
        if not body.confirmation_token:
            raise ValidationFailedError("RESTART_PORT requires 'confirmation_token' (the plan "
                                        "token from /api/ports/restart/prepare) and the typed "
                                        "'confirmations'.")
        limiter.hit(f"restart:{user.id}", limit=5, window_seconds=60)
        action = await execute_restart(db, user, plan_token=body.confirmation_token,
                                       confirmations=body.confirmations, reason=body.reason,
                                       ip=ip)
        return {"operation": operation.value,
                "action": PortActionOut.model_validate(action).model_dump(mode="json")}

    raise AppError("Operation not implemented.", code="COMMAND_BLOCKED")  # pragma: no cover
