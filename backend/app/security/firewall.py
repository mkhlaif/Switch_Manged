"""COMMAND SAFETY FIREWALL — the only path from application logic to a switch CLI.

Pipeline for every command (any failure → COMMAND BLOCKED, nothing is sent)::

    authentication/authorization (API) → operation validation → role check
    → switch profile validation (exact model family + AOS version applicability,
      administrator lab verification) → command-key allowlist → parameter validation
    → command generation → risk classification → sealing (HMAC) + fingerprint
    → final validation (seal, re-render, allowlist, risk, fingerprint, injection scan)
    → safety gate for state-changing commands (mode / kill switch / SAFE MODE / role)
    → command budgets + session limits → transport (re-verifies the seal) → switch
    → output contract validation (unexpected output → flagged, counted, fail closed)

Business code never handles command strings; it requests an operation and a command key.
Transports only expose ``run_approved(request)``, which rejects anything not sealed here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from typing import Protocol

from app.core.config import get_settings
from app.core.logging import get_logger, log_security
from app.core.timeutil import utcnow
from app.models.user import Role
from app.parsers.alcatel.system import SystemInfo, parse_show_system
from app.security.policy import (
    COMMAND_POLICIES,
    DISCOVERY_PROFILE,
    MAX_COMMAND_LENGTH,
    READ_COMMAND_KEYS,
    STRATEGY_TEMPLATES,
    BounceStrategyId,
    Operation,
    PolicyViolation,
    Risk,
    Severity,
    check_strategy_templates,
    check_template,
    policy_digest,
    verify_policy_integrity,
)
from app.security.recorder import (
    AlertItem,
    CommandEvent,
    Recorder,
    SecurityEvent,
    SessionRecord,
    get_recorder,
)
from app.security.risk import classify_command, dangerous_hits, has_injection
from app.security.state import SafetyState, load_safety_state
from app.security.validators import (
    AosVersionValidator,
    LinkAggValidator,
    MacAddressValidator,
    ParameterRejected,
    PortValidator,
)
from app.services.ssh.errors import SwitchError

log = get_logger("security.firewall")

# One secret per process. Requests sealed with it can only have been produced by build().
_PROCESS_SECRET = secrets.token_bytes(32)
RESTART_AUTH_TTL_SECONDS = 900
MAX_COMMANDS_PER_SESSION = 60
_MODEL_RE = re.compile(r"^OS\d{2,5}K?[A-Z]?(?:-[A-Z0-9]+)*$")


class CommandBlocked(SwitchError):
    status = "blocked"
    title = "COMMAND BLOCKED BY SAFETY POLICY"

    def __init__(self, reason: str, *, severity: Severity = Severity.WARNING,
                 event: str = "COMMAND_BLOCKED", operation: str = "", parameter: str = "",
                 details: dict | None = None) -> None:
        super().__init__(reason)
        self.severity = severity
        self.event = event
        self.operation = operation
        self.parameter = parameter
        self.details = details or {}


class UnexpectedOutput(SwitchError):
    """The switch answered, but not in the documented format: never trusted, never guessed."""

    status = "unexpected_output"
    title = "UNEXPECTED CLI OUTPUT"


# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ExecutionContext:
    """Who is asking, and why. Passed explicitly into every SSH session."""

    user_id: int | None
    username: str
    role: Role
    purpose: str
    ip: str = ""
    reference: str = ""

    @classmethod
    def for_user(cls, user, purpose: str, ip: str = "", reference: str = "") -> ExecutionContext:
        return cls(user.id, user.username, Role(user.role), purpose, ip, reference)


@dataclass(frozen=True)
class CommandRequest:
    """Structured representation of one command (the 'command AST'). Only build() creates
    valid (sealed) instances. The CLI text exists only here, at the final layer."""

    request_id: str
    session_id: str
    operation: Operation
    command_key: str
    profile_key: str
    family: str
    template: str
    parameters: tuple[tuple[str, str], ...]
    text: str
    risk: Risk
    fingerprint: str
    device: str
    expected_output: str = ""
    allow_empty: bool = False
    authorization_id: str = ""
    seal: str = ""

    def structured(self) -> dict:
        return {
            "operation": self.operation.value,
            "device": self.device,
            "command_profile": self.profile_key,
            "command_key": self.command_key,
            "parameters": dict(self.parameters),
            "risk": self.risk.value,
            "fingerprint": self.fingerprint,
        }

    def _payload(self) -> bytes:
        body = {k: v for k, v in self.__dict__.items() if k != "seal"}
        body["operation"] = self.operation.value
        body["risk"] = self.risk.value
        return json.dumps(body, sort_keys=True, default=list).encode()


@dataclass(frozen=True)
class RestartAuthorization:
    """Issued by the firewall only after the restart policy passed and the user confirmed."""

    auth_id: str
    action_id: int
    switch_id: int
    device: str
    port: str
    profile_key: str
    family: str
    strategy: BounceStrategyId
    down_template: str
    up_template: str
    user_id: int | None
    classification: str
    trunk_override: bool
    expires_at: float
    seal: str = ""

    def _payload(self) -> bytes:
        body = {k: v for k, v in self.__dict__.items() if k != "seal"}
        body["strategy"] = self.strategy.value
        return json.dumps(body, sort_keys=True).encode()


def _sign(payload: bytes) -> str:
    return hmac.new(_PROCESS_SECRET, payload, hashlib.sha256).hexdigest()


def fingerprint(text: str, device: str, operation: str, profile_key: str) -> str:
    """§32: SHA-256(command + switch + operation + profile)."""
    return hashlib.sha256(f"{text}\n{device}\n{operation}\n{profile_key}".encode()).hexdigest()


def assert_sealed(request: object) -> CommandRequest:
    """Called by every transport immediately before sending. Anything not produced by build()
    is refused (defence against any bypass of the firewall)."""
    if not isinstance(request, CommandRequest) or not request.seal:
        raise CommandBlocked("Transport refused an unsealed command.", severity=Severity.CRITICAL,
                             event="UNSEALED_COMMAND")
    if not hmac.compare_digest(request.seal, _sign(request._payload())):
        raise CommandBlocked("Transport refused a command with an invalid seal.",
                             severity=Severity.CRITICAL, event="FORGED_COMMAND")
    if "\n" in request.text or "\r" in request.text or len(request.text) > MAX_COMMAND_LENGTH:
        raise CommandBlocked("Transport refused a malformed command.",
                             severity=Severity.CRITICAL, event="MALFORMED_COMMAND")
    return request


class Transport(Protocol):
    label: str

    async def run_approved(self, request: CommandRequest, timeout: float | None = None) -> str: ...

    async def close(self) -> None: ...


@dataclass
class VerificationResult:
    required: bool
    verified: bool
    detail: str
    # Profile state that was found: LAB_VERIFIED | PRODUCTION_VERIFIED (verified results
    # without an explicit level count as LAB_VERIFIED — never more).
    level: str = ""

    @property
    def effective_level(self) -> str:
        if not self.verified:
            return ""
        return self.level if self.level in _LEVELS else "LAB_VERIFIED"

    def meets(self, minimum: str) -> bool:
        return self.verified and _LEVELS.get(self.effective_level, 0) >= _LEVELS[minimum]


_LEVELS = {"LAB_VERIFIED": 1, "PRODUCTION_VERIFIED": 2}


VerificationProvider = Callable[[str, str, "str | None", "str | None"],
                                Awaitable[VerificationResult]]


async def load_verification(profile_key: str, capability: str, model: str | None,
                            version: str | None) -> VerificationResult:
    """Default provider: administrator lab-verification records from the database."""
    from app.db.session import session_factory
    from app.services import system_settings
    from app.services.alcatel.registry import verification_status

    try:
        async with session_factory()() as db:
            required = True
            if capability == "READ":
                required = bool(await system_settings.get_value(db, "require_lab_verification"))
            st = await verification_status(db, profile_key, capability, model, version,
                                           required=required)
        return VerificationResult(st.required, st.verified or (
            st.level in _LEVELS), st.detail, st.level if st.level in _LEVELS else "")
    except Exception as exc:  # noqa: BLE001 - fail closed
        return VerificationResult(True, False, f"verification records unavailable "
                                               f"({exc.__class__.__name__})")


# ---------------------------------------------------------------------------------------------
@dataclass
class SafetyTestReport:
    """COMMAND SAFETY TEST: what WOULD be executed, validated but never sent."""

    operation: str
    device: str
    port: str
    profile_key: str
    strategy: str
    commands: list[dict] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    safety: str = "PASS"
    execution: str = "DISABLED"
    execution_reason: str = ""
    result: str = "NO COMMAND SENT"

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"check": name, "ok": ok, "detail": detail})
        if not ok:
            self.safety = "FAIL"

    def to_dict(self) -> dict:
        return dict(self.__dict__)


class CommandSafetyFirewall:
    def __init__(self, *, state_provider: Callable[[], Awaitable[SafetyState]] | None = None,
                 recorder: Recorder | None = None,
                 verification_provider: VerificationProvider | None = None,
                 breaker=None) -> None:
        self._state_provider = state_provider or load_safety_state
        self._verification = verification_provider or load_verification
        self.recorder = recorder or get_recorder()
        self.breaker = breaker
        self.failed_reason = ""
        try:
            report = verify_policy_integrity()
            if not report.ok:
                self.failed_reason = "; ".join(report.problems)
            self.digest = policy_digest()
        except Exception as exc:  # noqa: BLE001 - corrupted policy => fail closed
            self.failed_reason = f"policy integrity check crashed: {exc.__class__.__name__}"
            self.digest = ""
        self._auth_usage: dict[str, Counter] = {}
        self._auth_closed: set[str] = set()
        if self.failed_reason:
            log_security(log, "CRITICAL: Command Safety Firewall FAILED integrity check (%s). "
                         "ALL switch commands are blocked.", self.failed_reason)

    # -------------------------------------------------------------------------- status ---
    @property
    def ready(self) -> bool:
        return not self.failed_reason

    def status(self) -> dict:
        return {"ready": self.ready, "failed_reason": self.failed_reason,
                "policy_digest": self.digest}

    def ensure_ready(self) -> None:
        if not self.ready:
            raise CommandBlocked(f"Safety policy unavailable ({self.failed_reason}). No command "
                                 "was executed.", severity=Severity.CRITICAL,
                                 event="SAFETY_POLICY_UNAVAILABLE")

    async def safety_state(self) -> SafetyState:
        try:
            return await self._state_provider()
        except Exception as exc:  # noqa: BLE001
            from app.security.state import locked_state

            return locked_state(exc.__class__.__name__)

    async def verification(self, profile_key: str, capability: str, model: str | None,
                           version: str | None) -> VerificationResult:
        try:
            return await self._verification(profile_key, capability, model, version)
        except Exception as exc:  # noqa: BLE001 - fail closed
            return VerificationResult(True, False, f"verification check failed "
                                                   f"({exc.__class__.__name__})")

    # -------------------------------------------------------------------------- events ---
    def report(self, ctx: ExecutionContext | None, exc: CommandBlocked, *, device: str = "",
               port: str = "", mac: str = "") -> None:
        self.recorder.submit(SecurityEvent(
            action=exc.event, severity=exc.severity, reason=exc.reason,
            user_id=ctx.user_id if ctx else None, username=ctx.username if ctx else "",
            operation=exc.operation, parameter=exc.parameter, switch_name=device, port=port,
            mac=mac, ip=ctx.ip if ctx else "", details=exc.details,
        ))
        if exc.severity in (Severity.HIGH, Severity.CRITICAL):
            if self.breaker is not None:
                self.breaker.record_validation_failure(reason=f"{exc.event}: {exc.reason}")
            self.recorder.submit(AlertItem(
                kind="BLOCKED_OPERATION", severity=exc.severity.value,
                title=f"Blocked {exc.event.replace('_', ' ').lower()}",
                message=exc.reason, switch_name=device, port=port, mac=mac,
                dedupe_key=f"blocked:{exc.event}:{ctx.username if ctx else ''}:{device}",
                details={"operation": exc.operation, "user": ctx.username if ctx else ""},
            ))

    # ------------------------------------------------------------------------- profiles ---
    def accept_profile(self, profile) -> None:
        """Re-validate a command profile against the policy before any command uses it."""
        self.ensure_ready()
        try:
            if profile is None or not getattr(profile, "enabled", False):
                raise PolicyViolation("command profile is missing or disabled")
            if profile.family not in {"AOS6", "AOS7", "AOS8"}:
                raise PolicyViolation(f"unknown profile family {profile.family!r}")
            for key, spec in profile.commands.items():
                if key not in READ_COMMAND_KEYS:
                    raise PolicyViolation(f"profile command key {key!r} is not in the policy")
                check_template(key, spec.template)
            for strat in profile.strategies:
                check_strategy_templates(strat.strategy.value, strat.down_template,
                                         strat.up_template)
        except PolicyViolation as exc:
            raise CommandBlocked(f"Command profile rejected by the safety policy: {exc}. No "
                                 "command was executed.", severity=Severity.HIGH,
                                 event="PROFILE_REJECTED") from exc

    async def check_applicability(self, ctx: ExecutionContext, profile, *, model: str | None,
                                  version: str | None, transport: str) -> None:
        """Exact model family + AOS version, plus administrator lab verification (§8/§9)."""
        from app.services.alcatel.profiles import profile_applicability

        ok, why = profile_applicability(profile, model, version)
        if not ok:
            raise CommandBlocked(f"Command profile unavailable for this switch model/version "
                                 f"({why}). No command was executed.",
                                 severity=Severity.WARNING, event="PROFILE_UNAVAILABLE")
        if transport == "simulator":
            return  # lab simulator: not a production switch
        if ctx.purpose == "PROFILE_VERIFICATION":
            if ctx.role is not Role.ADMIN:
                raise CommandBlocked("Profile verification runs are administrator-only.",
                                     severity=Severity.HIGH, event="ROLE_NOT_PERMITTED")
            return  # the admin is producing the verification evidence right now
        v = await self.verification(profile.key, "READ", model, version)
        if v.required and not v.verified:
            raise CommandBlocked(f"Command profile unavailable for this switch model/version: "
                                 f"{v.detail}. An administrator must lab-verify it first. No "
                                 "command was executed.", severity=Severity.WARNING,
                                 event="PROFILE_NOT_LAB_VERIFIED")

    # --------------------------------------------------------------- generation (pre) ---
    def build(self, ctx: ExecutionContext, *, session_id: str, device: str,
              operation: Operation, command_key: str, params: dict,
              profile=None, authorization: RestartAuthorization | None = None) -> CommandRequest:
        """Validate everything and generate one sealed command. Raises CommandBlocked."""
        try:
            return self._build(ctx, session_id, device, operation, command_key, params, profile,
                               authorization)
        except CommandBlocked:
            raise
        except ParameterRejected as exc:
            raise CommandBlocked(
                f"Invalid parameter '{exc.parameter}': {exc.reason}. No command was executed.",
                severity=exc.severity,
                event="INJECTION_ATTEMPT" if exc.severity in {Severity.HIGH, Severity.CRITICAL}
                else "INVALID_PARAMETER",
                operation=getattr(operation, "value", str(operation)), parameter=exc.parameter,
                details={"value": exc.value_preview},
            ) from exc
        except PolicyViolation as exc:
            raise CommandBlocked(f"{exc} No command was executed.", severity=Severity.HIGH,
                                 event="COMMAND_NOT_ALLOWED",
                                 operation=getattr(operation, "value", str(operation))) from exc
        except Exception as exc:  # noqa: BLE001 - fail closed
            log.exception("Firewall build failed")
            raise CommandBlocked("Safety check failed unexpectedly; the command was blocked "
                                 "(fail closed).", severity=Severity.CRITICAL,
                                 event="SAFETY_CHECK_ERROR") from exc

    def _build(self, ctx, session_id, device, operation, command_key, params, profile,
               authorization) -> CommandRequest:
        self.ensure_ready()
        if not isinstance(operation, Operation) or operation not in COMMAND_POLICIES:
            raise CommandBlocked(f"Unknown operation {operation!r}. No command was executed.",
                                 severity=Severity.WARNING, event="UNKNOWN_OPERATION",
                                 operation=str(operation))
        policy = COMMAND_POLICIES[operation]
        op = operation.value
        if ctx.role not in policy.allowed_roles:
            raise CommandBlocked(f"Role {ctx.role.value} may not perform {op}.",
                                 severity=Severity.HIGH, event="ROLE_NOT_PERMITTED", operation=op)
        rule = policy.commands.get(command_key)
        if rule is None:
            raise CommandBlocked(f"Command {command_key!r} is not permitted for {op}. No command "
                                 "was executed.", severity=Severity.HIGH,
                                 event="COMMAND_NOT_ALLOWED", operation=op)
        if set(params) != set(rule.params):
            raise CommandBlocked(f"{op}/{command_key} expects parameters {sorted(rule.params)}, "
                                 f"got {sorted(params)}.", severity=Severity.HIGH,
                                 event="COMMAND_NOT_ALLOWED", operation=op)

        # --- command profile -----------------------------------------------------------
        auth_id = ""
        expected, allow_empty = "", False
        if policy.uses_discovery_profile:
            disc = DISCOVERY_PROFILE[command_key]
            template, expected = disc.template, disc.expected_output
            profile_key, family = "DISCOVERY", "ANY"
        elif policy.risk is Risk.STATE_CHANGING:
            auth = self._verify_authorization(authorization, device)
            if profile is None or profile.key != auth.profile_key:
                raise CommandBlocked("Bound command profile does not match the restart "
                                     "authorization.", severity=Severity.HIGH,
                                     event="AUTHORIZATION_MISMATCH", operation=op)
            if params.get("port") != auth.port:
                raise CommandBlocked("Port does not match the restart authorization.",
                                     severity=Severity.HIGH, event="AUTHORIZATION_MISMATCH",
                                     operation=op, parameter="port")
            check_strategy_templates(auth.strategy.value, auth.down_template, auth.up_template)
            template = auth.down_template if command_key == "bounce_down" else auth.up_template
            profile_key, family, auth_id = auth.profile_key, auth.family, auth.auth_id
            allow_empty, expected = True, r"^\s*$"  # AOS prints nothing on success
        else:
            if profile is None:
                raise CommandBlocked("No verified command profile is bound to this session. No "
                                     "command was executed.", severity=Severity.WARNING,
                                     event="NO_PROFILE", operation=op)
            spec = profile.command(command_key)
            if spec is None:
                raise CommandBlocked(f"Profile {profile.key} does not define {command_key!r}. No "
                                     "command was executed.", severity=Severity.WARNING,
                                     event="NO_PROFILE", operation=op)
            if not spec.usable:
                raise CommandBlocked(f"Command {command_key!r} in profile {profile.key} is not "
                                     "verified. No command was executed.",
                                     severity=Severity.WARNING, event="UNVERIFIED_COMMAND",
                                     operation=op)
            template = spec.template
            check_template(command_key, template)
            profile_key, family = profile.key, profile.family
            expected, allow_empty = spec.expected_output, spec.allow_empty

        # --- parameters ----------------------------------------------------------------
        values: dict[str, str] = {}
        for name, value in params.items():
            if name == "mac":
                values[name] = MacAddressValidator.to_aos(MacAddressValidator.validate(value))
            elif name == "port":
                values[name] = PortValidator.validate(value, family)
            elif name == "agg":
                values[name] = LinkAggValidator.validate(value)
            else:  # pragma: no cover - rule.params only contains the names above
                raise CommandBlocked(f"Unsupported parameter {name!r}.", severity=Severity.HIGH,
                                     event="COMMAND_NOT_ALLOWED", operation=op, parameter=name)

        # --- generation + classification -----------------------------------------------
        text = template.format(**values)
        risk = classify_command(text)
        if risk is not policy.risk:
            raise CommandBlocked(
                f"Generated command classified {risk.value}, but {op} permits only "
                f"{policy.risk.value}. No command was executed.",
                severity=Severity.CRITICAL if risk is Risk.DANGEROUS else Severity.HIGH,
                event="RISK_MISMATCH", operation=op, details={"hits": dangerous_hits(text)},
            )
        request = CommandRequest(
            request_id=str(uuid.uuid4()), session_id=session_id, operation=operation,
            command_key=command_key, profile_key=profile_key, family=family, template=template,
            parameters=tuple(sorted(values.items())), text=text, risk=risk,
            fingerprint=fingerprint(text, device, op, profile_key), device=device,
            expected_output=expected, allow_empty=allow_empty, authorization_id=auth_id,
        )
        return replace(request, seal=_sign(request._payload()))

    # ------------------------------------------------------------- validation (post) ---
    def final_check(self, request: CommandRequest, session_id: str) -> None:
        """Second, independent validation of the generated command before execution."""
        try:
            assert_sealed(request)
            if request.session_id != session_id:
                raise CommandBlocked("Command was generated for a different session.",
                                     severity=Severity.CRITICAL, event="SESSION_MISMATCH")
            policy = COMMAND_POLICIES[request.operation]
            if request.command_key not in policy.commands:
                raise CommandBlocked("Command key not permitted for operation.",
                                     severity=Severity.CRITICAL, event="COMMAND_NOT_ALLOWED")
            if request.risk is Risk.STATE_CHANGING:
                pairs = STRATEGY_TEMPLATES[BounceStrategyId(self._strategy_of(request))]
                if not any(request.template in pair for pair in pairs):
                    raise CommandBlocked("State-changing template is not allowlisted.",
                                         severity=Severity.CRITICAL, event="COMMAND_NOT_ALLOWED")
            elif request.profile_key == "DISCOVERY":
                if request.template != DISCOVERY_PROFILE[request.command_key].template:
                    raise CommandBlocked("Discovery template mismatch.",
                                         severity=Severity.CRITICAL, event="COMMAND_NOT_ALLOWED")
            else:
                check_template(request.command_key, request.template)
            rerendered = request.template.format(**dict(request.parameters))
            if rerendered != request.text:
                raise CommandBlocked("Command text does not match its template.",
                                     severity=Severity.CRITICAL, event="TEMPLATE_MISMATCH")
            if classify_command(request.text) is not policy.risk or has_injection(request.text):
                raise CommandBlocked("Final command failed risk classification.",
                                     severity=Severity.CRITICAL, event="RISK_MISMATCH")
            expected_fp = fingerprint(request.text, request.device, request.operation.value,
                                      request.profile_key)
            if request.fingerprint != expected_fp:
                raise CommandBlocked("Command fingerprint mismatch.",
                                     severity=Severity.CRITICAL, event="FINGERPRINT_MISMATCH")
        except CommandBlocked:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed
            raise CommandBlocked("Final command validation failed (fail closed).",
                                 severity=Severity.CRITICAL, event="SAFETY_CHECK_ERROR") from exc

    def _strategy_of(self, request: CommandRequest) -> str:
        for sid, pairs in STRATEGY_TEMPLATES.items():
            if any(request.template in pair for pair in pairs):
                return sid.value
        raise CommandBlocked("Unknown state-changing template.", severity=Severity.CRITICAL,
                             event="COMMAND_NOT_ALLOWED")

    # ------------------------------------------------------ restart authorization ---
    async def authorize_restart(self, ctx: ExecutionContext, *, action_id: int, switch_id: int,
                                device: str, port: str, profile, strategy_spec,
                                classification: str, confidence: str, declared_uplink: bool,
                                is_linkagg: bool, switch_role: str, model: str | None,
                                version: str | None, trunk_override_confirmed: bool,
                                operator_classes: set[str], confirmed: bool,
                                discovery_status: str = "not_discovered",
                                transport: str = "ssh", environment: str = "production",
                                ) -> RestartAuthorization:
        """Issue a restart authorization after re-checking everything the firewall can check.

        Fail-closed defaults: an undiscovered device, and a production switch unless the
        strategy is PRODUCTION_VERIFIED, never get an authorization."""
        from app.security.restart_policy import evaluate_restart_policy
        from app.services.classification.engine import PortClass

        op = Operation.RESTART_PORT.value
        self.ensure_ready()
        if discovery_status != "discovered":
            raise CommandBlocked("Device identity not verified by discovery (status "
                                 f"{discovery_status}). UNKNOWN DEVICE = NO STATE-CHANGING "
                                 "OPERATION. No command was executed.",
                                 severity=Severity.WARNING, event="DEVICE_NOT_DISCOVERED",
                                 operation=op)
        if ctx.role not in COMMAND_POLICIES[Operation.RESTART_PORT].allowed_roles:
            raise CommandBlocked("Role may not restart ports.", severity=Severity.HIGH,
                                 event="ROLE_NOT_PERMITTED", operation=op)
        if not confirmed:
            raise CommandBlocked("RESTART_PORT requires explicit confirmation.",
                                 severity=Severity.HIGH, event="NOT_CONFIRMED", operation=op)
        state = await self.safety_state()
        block = state.state_changing_block_reason(ctx.role)
        if block:
            raise CommandBlocked(f"PORT RESTART BLOCKED. {block} No command was executed.",
                                 severity=Severity.WARNING, event="STATE_CHANGING_BLOCKED",
                                 operation=op)
        try:
            category = PortClass(classification)
        except ValueError as exc:
            raise CommandBlocked("Port classification unknown; restart blocked.",
                                 severity=Severity.HIGH, event="CLASSIFICATION_UNCERTAIN",
                                 operation=op) from exc
        policy = evaluate_restart_policy(
            category=category, role=ctx.role, port=port, declared_uplink=declared_uplink,
            is_linkagg=is_linkagg, mode=state.mode, operator_classes=operator_classes,
            switch_role=switch_role, confidence=confidence,
        )
        if not policy.allowed:
            raise CommandBlocked(policy.blocked_reason, severity=Severity.WARNING,
                                 event="RESTART_POLICY_BLOCKED", operation=op)
        if policy.trunk_override and not trunk_override_confirmed:
            raise CommandBlocked("Trunk override requires the second confirmation.",
                                 severity=Severity.HIGH, event="NOT_CONFIRMED", operation=op)
        self.accept_profile(profile)
        if strategy_spec not in profile.strategies:
            raise CommandBlocked("Strategy is not part of the bound profile.",
                                 severity=Severity.HIGH, event="COMMAND_NOT_ALLOWED",
                                 operation=op)
        verification = await self.verification(profile.key, strategy_spec.strategy.value, model,
                                               version)
        minimum = "LAB_VERIFIED" if transport == "simulator" or environment == "lab" \
            else "PRODUCTION_VERIFIED"
        if not verification.meets(minimum):
            raise CommandBlocked(f"Restart strategy not {minimum} for this switch: "
                                 f"{verification.detail}. PROFILE NOT VERIFIED = NO PRODUCTION "
                                 "EXECUTION. No command was executed.",
                                 severity=Severity.WARNING, event="STRATEGY_NOT_VERIFIED",
                                 operation=op)
        try:
            check_strategy_templates(strategy_spec.strategy.value, strategy_spec.down_template,
                                     strategy_spec.up_template)
            canonical_port = PortValidator.validate(port, profile.family)
        except (PolicyViolation, ParameterRejected) as exc:
            raise CommandBlocked(f"Restart authorization rejected: {exc}",
                                 severity=Severity.HIGH, event="COMMAND_NOT_ALLOWED",
                                 operation=op) from exc
        auth = RestartAuthorization(
            auth_id=str(uuid.uuid4()), action_id=action_id, switch_id=switch_id, device=device,
            port=canonical_port, profile_key=profile.key, family=profile.family,
            strategy=BounceStrategyId(strategy_spec.strategy.value),
            down_template=strategy_spec.down_template, up_template=strategy_spec.up_template,
            user_id=ctx.user_id, classification=classification,
            trunk_override=policy.trunk_override,
            expires_at=time.monotonic() + RESTART_AUTH_TTL_SECONDS,
        )
        auth = replace(auth, seal=_sign(auth._payload()))
        self._auth_usage[auth.auth_id] = Counter()
        return auth

    def _verify_authorization(self, auth: RestartAuthorization | None,
                              device: str) -> RestartAuthorization:
        op = Operation.RESTART_PORT.value
        if not isinstance(auth, RestartAuthorization) or not auth.seal or \
                not hmac.compare_digest(auth.seal, _sign(auth._payload())):
            raise CommandBlocked("RESTART_PORT requires a valid restart authorization. No "
                                 "command was executed.", severity=Severity.CRITICAL,
                                 event="MISSING_AUTHORIZATION", operation=op)
        if auth.auth_id not in self._auth_usage or auth.auth_id in self._auth_closed:
            raise CommandBlocked("Restart authorization is not active.", severity=Severity.HIGH,
                                 event="AUTHORIZATION_INACTIVE", operation=op)
        if time.monotonic() > auth.expires_at:
            raise CommandBlocked("Restart authorization expired.", severity=Severity.WARNING,
                                 event="AUTHORIZATION_EXPIRED", operation=op)
        if auth.device != device:
            raise CommandBlocked("Restart authorization is for a different switch.",
                                 severity=Severity.CRITICAL, event="AUTHORIZATION_MISMATCH",
                                 operation=op)
        return auth

    def usage(self, auth: RestartAuthorization) -> Counter:
        return self._auth_usage.setdefault(auth.auth_id, Counter())

    def close_authorization(self, auth: RestartAuthorization | None) -> None:
        if auth is not None:
            self._auth_closed.add(auth.auth_id)

    # ------------------------------------------------------------- safety test (§41) ---
    async def safety_test(self, ctx: ExecutionContext, *, device: str, port: str, profile,
                          strategy_spec, execution_reason: str) -> SafetyTestReport:
        """Generate and validate the restart commands WITHOUT any ability to execute them."""
        report = SafetyTestReport(operation=Operation.RESTART_PORT.value, device=device,
                                  port=port, profile_key=getattr(profile, "key", ""),
                                  strategy=getattr(getattr(strategy_spec, "strategy", None),
                                                   "value", ""),
                                  execution_reason=execution_reason)
        try:
            report.check("Firewall integrity", self.ready, self.failed_reason or self.digest[:16])
            self.accept_profile(profile)
            report.check("Command profile accepted", True, profile.key)
            check_strategy_templates(strategy_spec.strategy.value, strategy_spec.down_template,
                                     strategy_spec.up_template)
            report.check("Templates on allowlist", True, strategy_spec.strategy.value)
            canonical = PortValidator.validate(port, profile.family)
            report.check("Port parameter valid", True, canonical)
            role_ok = ctx.role in COMMAND_POLICIES[Operation.RESTART_PORT].allowed_roles
            report.check("Role permitted", role_ok, ctx.role.value)
            for key, template in (("bounce_down", strategy_spec.down_template),
                                  ("bounce_up", strategy_spec.up_template)):
                text = template.format(port=canonical)
                risk = classify_command(text)
                report.commands.append({
                    "command_key": key, "text": text, "risk": risk.value,
                    "fingerprint": fingerprint(text, device, Operation.RESTART_PORT.value,
                                               profile.key)})
                report.check(f"{key} risk is STATE_CHANGING", risk is Risk.STATE_CHANGING,
                             risk.value)
            state = await self.safety_state()
            block = state.state_changing_block_reason(ctx.role)
            report.check("Global safety state", True,
                         block or f"mode {state.mode}: state changes enabled")
        except CommandBlocked as exc:
            report.check("Safety policy", False, exc.reason)
        except (PolicyViolation, ParameterRejected) as exc:
            report.check("Safety policy", False, str(exc))
        except Exception as exc:  # noqa: BLE001
            report.check("Safety policy", False, f"unexpected error {exc.__class__.__name__}")
        return report

    # --------------------------------------------------------------------- sessions ---
    def open_session(self, transport: Transport, ctx: ExecutionContext, *, device: str,
                     switch_id: int | None, transport_kind: str = "ssh") -> FirewallSession:
        self.ensure_ready()
        return FirewallSession(self, transport, ctx, device=device, switch_id=switch_id,
                               transport_kind=transport_kind)

    def record_connection_failure(self, ctx: ExecutionContext, *, device: str,
                                  switch_id: int | None, exc: BaseException) -> None:
        rec = SessionRecord(switch_id=switch_id, switch_name=device, user_id=ctx.user_id,
                            username=ctx.username, purpose=ctx.purpose, reference=ctx.reference)
        rec.ended_at = utcnow()
        rec.result = "blocked" if isinstance(exc, CommandBlocked) else "connect_failed"
        rec.error = f"{getattr(exc, 'title', exc.__class__.__name__)}: " \
                    f"{getattr(exc, 'reason', str(exc))}"
        self.recorder.submit(rec)


class FirewallSession:
    """An SSH session that can ONLY execute firewall-built, sealed commands."""

    def __init__(self, firewall: CommandSafetyFirewall, transport: Transport,
                 ctx: ExecutionContext, *, device: str, switch_id: int | None,
                 transport_kind: str = "ssh") -> None:
        self._fw = firewall
        self.__transport = transport
        self.ctx = ctx
        self.device = device
        self.switch_id = switch_id
        self.transport_kind = transport_kind
        self.profile = None
        self.record = SessionRecord(switch_id=switch_id, switch_name=device,
                                    user_id=ctx.user_id, username=ctx.username,
                                    purpose=ctx.purpose, reference=ctx.reference)
        self.id = self.record.id
        self._executed: list[str] = []
        self._closed = False
        self._started = time.monotonic()
        self.unexpected_outputs: list[dict] = []

    # -- profile ---------------------------------------------------------------------------
    async def bind_profile(self, profile, *, model: str | None, version: str | None) -> None:
        """Bind a verified profile after checking applicability to this exact model/version and
        the administrator lab verification (§8/§9). Fails closed."""
        try:
            self._fw.accept_profile(profile)
            await self._fw.check_applicability(self.ctx, profile, model=model, version=version,
                                               transport=self.transport_kind)
        except CommandBlocked as exc:
            self._blocked("-", "-", exc)
            raise
        self.profile = profile
        self.record.profile_key = profile.key

    # -- operations ------------------------------------------------------------------------
    @asynccontextmanager
    async def operation(self, operation: Operation) -> AsyncIterator[OperationInvocation]:
        inv = OperationInvocation(self, operation)
        self.record.operations.append(getattr(operation, "value", str(operation)))
        yield inv

    async def run(self, operation: Operation, command_key: str, **params) -> str:
        async with self.operation(operation) as inv:
            return await inv.run(command_key, **params)

    async def discover(self) -> SystemInfo:
        """Separately approved read-only discovery. Parsed output is data only: model and
        version are accepted only if they match strict formats (output validation)."""
        output = await self.run(Operation.DISCOVER_SYSTEM, "system_info")
        info = parse_show_system(output)
        version = info.version if info.version and AosVersionValidator.is_valid(info.version) \
            else None
        model = info.model if info.model and _MODEL_RE.match(info.model) else None
        return SystemInfo(description=info.description, model=model, version=version,
                          name=info.name, location=info.location, contact=info.contact,
                          uptime=info.uptime, object_id=info.object_id, vendor=info.vendor)

    @asynccontextmanager
    async def restart(self, authorization: RestartAuthorization
                      ) -> AsyncIterator[RestartInvocation]:
        self.record.operations.append(Operation.RESTART_PORT.value)
        yield RestartInvocation(self, authorization)

    def executed_commands(self) -> list[str]:
        return list(self._executed)

    # -- internals -------------------------------------------------------------------------
    def _blocked(self, operation: str, command_key: str, exc: CommandBlocked,
                 fp: str = "") -> None:
        self.record.events.append(CommandEvent(operation, command_key, fp, "-", "blocked",
                                               exc.reason))
        if not exc.operation:
            exc.operation = operation
        self._fw.report(self.ctx, exc, device=self.device)

    def _check_limits(self) -> None:
        if self._closed:
            raise CommandBlocked("Session already closed.", severity=Severity.HIGH,
                                 event="SESSION_CLOSED")
        if time.monotonic() - self._started > get_settings().ssh_max_session_seconds:
            raise CommandBlocked("Maximum SSH session duration exceeded; no further commands.",
                                 severity=Severity.WARNING, event="SESSION_LIMIT")
        if len(self.record.events) >= MAX_COMMANDS_PER_SESSION:
            raise CommandBlocked("Maximum commands per SSH session exceeded.",
                                 severity=Severity.HIGH, event="SESSION_LIMIT")

    async def _execute(self, request: CommandRequest, *, restore: bool = False) -> str:
        self._check_limits()
        self._fw.final_check(request, self.id)
        if request.risk is Risk.STATE_CHANGING:
            state = await self._fw.safety_state()
            block = state.state_changing_block_reason(self.ctx.role)
            if block and not restore:
                raise CommandBlocked(f"{block} No command was executed.",
                                     severity=Severity.WARNING, event="STATE_CHANGING_BLOCKED",
                                     operation=request.operation.value)
            if block and restore:
                log_security(log, "Restore command %s allowed on %s despite: %s",
                             request.fingerprint[:16], self.device, block)
        started = time.monotonic()
        try:
            output = await self.__transport.run_approved(request)
        except SwitchError as exc:
            self.record.events.append(CommandEvent(
                request.operation.value, request.command_key, request.fingerprint,
                request.risk.value, "failed", exc.reason,
                duration_ms=int((time.monotonic() - started) * 1000)))
            self._executed.append(request.text)
            raise
        duration = int((time.monotonic() - started) * 1000)
        self._executed.append(request.text)
        # Output contract: switch output is untrusted data; unexpected formats are never guessed.
        if request.expected_output and not (request.allow_empty and not output.strip()):
            if not re.search(request.expected_output, output):
                detail = (f"{request.operation.value}/{request.command_key}: output does not "
                          "match the documented format")
                self.record.events.append(CommandEvent(
                    request.operation.value, request.command_key, request.fingerprint,
                    request.risk.value, "unexpected_output", detail, duration_ms=duration))
                self.unexpected_outputs.append({"command_key": request.command_key,
                                                "fingerprint": request.fingerprint})
                log_security(log, "UNEXPECTED CLI OUTPUT on %s for %s (fp %s)", self.device,
                             request.command_key, request.fingerprint[:16])
                if self._fw.breaker is not None:
                    self._fw.breaker.record_unexpected_output(switch_name=self.device,
                                                              detail=detail)
                self._fw.recorder.submit(AlertItem(
                    kind="UNEXPECTED_OUTPUT", severity="WARNING",
                    title="Unexpected CLI output", message=detail, switch_name=self.device,
                    dedupe_key=f"unexpected:{self.device}:{request.command_key}"))
                raise UnexpectedOutput(f"{detail}. The result was discarded (fail closed).")
        self.record.events.append(CommandEvent(
            request.operation.value, request.command_key, request.fingerprint,
            request.risk.value, "executed", "", duration_ms=duration))
        return output

    def close(self, error: BaseException | None = None) -> None:
        if self._closed:
            return
        self._closed = True
        rec = self.record
        rec.ended_at = utcnow()
        if error is not None:
            rec.result = "blocked" if isinstance(error, CommandBlocked) else "failed"
            rec.error = f"{getattr(error, 'title', error.__class__.__name__)}: " \
                        f"{getattr(error, 'reason', str(error))}"
        else:
            rec.result = "blocked" if rec.blocked and not rec.executed else "success"
        self._fw.recorder.submit(rec)


class OperationInvocation:
    """One invocation of an operation; enforces the operation's command budget."""

    def __init__(self, session: FirewallSession, operation: Operation) -> None:
        self.session = session
        self.operation = operation
        self.count = 0
        self.per_key: Counter = Counter()

    async def run(self, command_key: str, **params) -> str:
        s = self.session
        op_name = getattr(self.operation, "value", str(self.operation))
        try:
            policy = COMMAND_POLICIES.get(self.operation) if isinstance(
                self.operation, Operation) else None
            if policy is None:
                raise CommandBlocked(f"Unknown operation {op_name!r}. No command was executed.",
                                     severity=Severity.WARNING, event="UNKNOWN_OPERATION",
                                     operation=op_name)
            if policy.risk is not Risk.READ_ONLY:
                raise CommandBlocked(f"{op_name} is state-changing and requires a restart "
                                     "authorization.", severity=Severity.CRITICAL,
                                     event="MISSING_AUTHORIZATION", operation=op_name)
            rule = policy.commands.get(command_key)
            if self.count >= policy.max_commands or (
                    rule is not None and self.per_key[command_key] >= rule.max_per_invocation):
                raise CommandBlocked(f"OPERATION BLOCKED. Maximum command count for {op_name} "
                                     f"exceeded ({policy.max_commands}). No additional commands "
                                     "were executed.", severity=Severity.HIGH,
                                     event="COMMAND_BUDGET_EXCEEDED", operation=op_name)
            request = s._fw.build(s.ctx, session_id=s.id, device=s.device,
                                  operation=self.operation, command_key=command_key,
                                  params=params, profile=s.profile)
        except CommandBlocked as exc:
            s._blocked(op_name, str(command_key), exc)
            raise
        self.count += 1
        self.per_key[command_key] += 1
        try:
            return await s._execute(request)
        except CommandBlocked as exc:
            s._blocked(op_name, command_key, exc, request.fingerprint)
            raise


class RestartInvocation:
    """RESTART_PORT: down at most once, up at most twice per authorization (across sessions)."""

    def __init__(self, session: FirewallSession, authorization: RestartAuthorization) -> None:
        self.session = session
        self.auth = authorization
        self.fingerprints: list[str] = []

    async def _send(self, command_key: str, *, restore: bool) -> str:
        s = self.session
        fw = s._fw
        op = Operation.RESTART_PORT
        rule = COMMAND_POLICIES[op].commands[command_key]
        try:
            usage = fw.usage(self.auth)
            if usage[command_key] >= rule.max_per_invocation or \
                    sum(usage.values()) >= COMMAND_POLICIES[op].max_commands:
                raise CommandBlocked(f"OPERATION BLOCKED. Maximum {command_key} count for "
                                     "RESTART_PORT exceeded. No additional commands were "
                                     "executed.", severity=Severity.HIGH,
                                     event="COMMAND_BUDGET_EXCEEDED", operation=op.value)
            if command_key == "bounce_up" and usage["bounce_down"] < 1:
                raise CommandBlocked("The up (restore) command is only permitted after the down "
                                     "command of the same authorization.",
                                     severity=Severity.HIGH, event="COMMAND_NOT_ALLOWED",
                                     operation=op.value)
            request = fw.build(s.ctx, session_id=s.id, device=s.device, operation=op,
                               command_key=command_key, params={"port": self.auth.port},
                               profile=s.profile, authorization=self.auth)
        except CommandBlocked as exc:
            s._blocked(op.value, command_key, exc)
            raise
        usage[command_key] += 1
        self.fingerprints.append(request.fingerprint)
        try:
            return await s._execute(request, restore=restore)
        except CommandBlocked as exc:
            usage[command_key] -= 1  # blocked before sending: nothing was executed
            s._blocked(op.value, command_key, exc, request.fingerprint)
            raise

    async def down(self) -> str:
        return await self._send("bounce_down", restore=False)

    async def up(self) -> str:
        # Restoring a port this authorization took down is always permitted (even if the kill
        # switch was thrown meanwhile) — leaving the port down would be the unsafe outcome.
        return await self._send("bounce_up", restore=True)


# ---------------------------------------------------------------------------------------------
_firewall: CommandSafetyFirewall | None = None


def init_firewall(**kwargs) -> CommandSafetyFirewall:
    global _firewall
    _firewall = CommandSafetyFirewall(**kwargs)
    return _firewall


def get_firewall() -> CommandSafetyFirewall:
    global _firewall
    if _firewall is None:
        _firewall = CommandSafetyFirewall()
    return _firewall
