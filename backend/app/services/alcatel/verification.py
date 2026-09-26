"""Administrator lab verification of a profile's READ-ONLY commands (§9).

Runs every read-only command of the switch's profile exactly once against one sample port, each
through the Command Safety Firewall, and checks the output twice: against the command's output
contract (firewall) and by parsing it (the parser must find the documented fields). No
state-changing command exists on this path; restart strategies can only be recorded as verified
manually after a supervised lab test.
"""

from __future__ import annotations

import re

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError, NotFoundError, ValidationFailedError
from app.models import Switch, User
from app.parsers.alcatel.lldp import parse_lldp_remote
from app.parsers.alcatel.mac_table import parse_mac_table
from app.parsers.alcatel.port_status import parse_interface_detail, parse_port_admin
from app.parsers.alcatel.vlan_port import parse_vlan_port
from app.security.firewall import CommandBlocked, ExecutionContext, UnexpectedOutput
from app.security.policy import Operation
from app.security.validators import MacAddressValidator, ParameterRejected, PortValidator
from app.services.alcatel.profiles import model_family
from app.services.alcatel.registry import load_profiles, select_profile
from app.services.audit.service import record
from app.services.inventory.service import build_target
from app.services.ssh.errors import CommandFailed, SwitchError
from app.services.ssh.manager import get_connector

PLACEHOLDER_MAC = "000000000001"

# command key -> (operation, parameter name, parse check)
CHECKS = (
    ("mac_lookup", Operation.SEARCH_MAC, "mac", lambda out, port: parse_mac_table(out) is not None),
    ("vlan_port", Operation.GET_PORT_VLAN, "port", lambda out, port: bool(parse_vlan_port(out))),
    ("port_detail", Operation.GET_PORT_STATUS, "port",
     lambda out, port: parse_interface_detail(out).oper_status is not None),
    ("port_admin", Operation.GET_PORT_STATUS, "port",
     lambda out, port: parse_port_admin(out, port)["admin_status"] is not None),
    ("lldp_port", Operation.GET_LLDP, "port", lambda out, port: parse_lldp_remote(out) is not None),
    ("mac_on_port", Operation.GET_PORT_MACS, "port",
     lambda out, port: parse_mac_table(out) is not None),
)


async def run_read_verification(db: AsyncSession, admin: User, *, switch_id: int, port: str,
                                mac: str | None, ip: str) -> dict:
    switch = await db.get(Switch, switch_id)
    if switch is None:
        raise NotFoundError("Switch not found.")
    profile, reason = select_profile(await load_profiles(db), switch)
    if profile is None:
        raise AppError(f"{reason} No command was executed.", code="NO_PROFILE",
                       title="COMMAND PROFILE UNAVAILABLE")
    try:
        canonical_port = PortValidator.validate(port, profile.family)
        canonical_mac = MacAddressValidator.validate(mac) if mac else PLACEHOLDER_MAC
    except ParameterRejected as exc:
        raise ValidationFailedError(f"Invalid {exc.parameter}: {exc.reason}. No command was "
                                    "executed.", code="COMMAND_BLOCKED") from exc
    family = model_family(switch.model)
    m = re.match(r"^(\d+\.\d+)", switch.aos_version or "")
    if family is None or m is None:
        raise ValidationFailedError("Detect the switch model and AOS version first.")

    ctx = ExecutionContext.for_user(admin, "PROFILE_VERIFICATION", ip,
                                    reference=f"{switch.name} {profile.key}")
    target = await build_target(db, switch)
    results: list[dict] = []
    commands: list[str] = []
    try:
        async with get_connector().session(target, ctx) as fs:
            await fs.bind_profile(profile, model=switch.model, version=switch.aos_version)
            for key, operation, param, check in CHECKS:
                spec = profile.command(key)
                if spec is None or not spec.usable:
                    results.append({"command_key": key, "status": "not_in_profile"})
                    continue
                value = canonical_mac if param == "mac" else canonical_port
                try:
                    output = await fs.run(operation, key, **{param: value})
                except UnexpectedOutput as exc:
                    results.append({"command_key": key, "status": "unexpected_output",
                                    "detail": exc.reason})
                    continue
                except CommandFailed as exc:
                    results.append({"command_key": key, "status": "rejected_by_switch",
                                    "detail": exc.reason})
                    continue
                except CommandBlocked as exc:
                    results.append({"command_key": key, "status": "blocked",
                                    "detail": exc.reason})
                    continue
                try:
                    parsed = bool(check(output, canonical_port))
                except Exception as exc:  # noqa: BLE001 - parser failure is a result
                    parsed = False
                    results.append({"command_key": key, "status": "parse_failed",
                                    "detail": exc.__class__.__name__})
                    continue
                results.append({"command_key": key,
                                "status": "ok" if parsed else "parse_failed",
                                "output_lines": len(output.splitlines())})
            commands = fs.executed_commands()
    except SwitchError as exc:
        raise AppError(f"{exc.title}: {exc.reason}", code=exc.status.upper(),
                       status_code=502) from exc
    if profile.command("vlan_linkagg"):
        results.append({"command_key": "vlan_linkagg", "status": "not_exercised",
                        "detail": "requires a link aggregate id; verify manually"})
    exercised = [r for r in results if r["status"] not in {"not_in_profile", "not_exercised"}]
    passed = bool(exercised) and all(r["status"] == "ok" for r in exercised)
    out = {"switch": switch.name, "profile": profile.key, "model_family": family,
           "version_prefix": m.group(1), "aos_version": switch.aos_version, "port": canonical_port,
           "results": results, "passed": passed, "commands": commands, "recorded": False}
    await record(db, action="PROFILE_VERIFICATION_RUN", result="SUCCESS" if passed else "FAILED",
                 user=admin, ip=ip, switch_name=switch.name, port=canonical_port,
                 operation="PROFILE_VERIFICATION", profile=profile.key,
                 message=f"Read-only verification of {profile.key} on {family} AOS "
                         f"{switch.aos_version}: {'PASSED' if passed else 'FAILED'}",
                 details={"results": results, "commands_executed": len(commands)})
    return out
