"""Command Safety Firewall unit tests.

Every blocking test asserts that NOTHING reached the transport (commands_executed == 0).
"""

import hashlib
from dataclasses import replace
from types import MappingProxyType

import pytest

from app.models.user import Role
from app.security import firewall as fw_module
from app.security.firewall import (
    CommandBlocked,
    CommandRequest,
    CommandSafetyFirewall,
    ExecutionContext,
    UnexpectedOutput,
    VerificationResult,
    assert_sealed,
    fingerprint,
)
from app.security.policy import (
    API_OPERATIONS,
    COMMAND_POLICIES,
    STATE_CHANGING_OPERATIONS,
    Operation,
    Risk,
    Severity,
    verify_policy_integrity,
)
from app.security.risk import classify_command
from app.security.state import SafetyState
from app.services.alcatel.profiles import AOS6_PROFILE, AOS7_PROFILE, AOS8_PROFILE, CommandProfile

MAC = "00:11:22:33:44:55"


# Satisfies every documented read-output contract; state-changing commands print nothing.
DEFAULT_OUTPUT = ("Description: x\n vlan  type  status\nOperational Status : up\n"
                  "Admin Link\nRemote LLDP nearest-bridge Agents\nMac Address\n")


class RecordingTransport:
    label = "rec"

    def __init__(self, outputs: dict | None = None):
        self.sent: list[str] = []
        self.outputs = outputs or {}

    async def run_approved(self, request, timeout=None):
        assert_sealed(request)
        self.sent.append(request.text)
        default = "" if request.risk is Risk.STATE_CHANGING else DEFAULT_OUTPUT
        return self.outputs.get(request.text, default)

    async def close(self):
        pass


class ListRecorder:
    def __init__(self):
        self.items = []

    def submit(self, item):
        self.items.append(item)

    def events(self):
        return [i for i in self.items if hasattr(i, "action")]

    def alerts(self):
        return [i for i in self.items if hasattr(i, "kind")]


class FakeBreaker:
    def __init__(self):
        self.validation: list[str] = []
        self.unexpected: list[str] = []

    def record_validation_failure(self, *, reason):
        self.validation.append(reason)

    def record_unexpected_output(self, *, switch_name, detail):
        self.unexpected.append(detail)


def state(**kw) -> SafetyState:
    base = dict(available=True, mode="MAINTENANCE", configured_mode="MAINTENANCE",
                mode_reason="", read_only_forced_by_env=False, command_execution_enabled=True,
                kill_switch_forced_by_env=False, safe_mode=False, safe_mode_reason="",
                dry_run_mode=False)
    base.update(kw)
    base.setdefault("configured_mode", base["mode"])
    return SafetyState(**base)


MODELS = {"AOS8": ("OS6860E-P24", "8.9.221.R03"), "AOS6": ("OS6450-P24", "6.7.2.191.R08"),
          "AOS7": ("OS10K", "7.3.4.380.R02")}


class Env:
    def __init__(self, verified: bool = True, **state_kw):
        self.state = state(**state_kw)
        self.recorder = ListRecorder()
        self.breaker = FakeBreaker()
        self.verified = verified
        self.verification_calls: list[tuple] = []

        async def provider():
            return self.state

        async def verification(profile_key, capability, model, version):
            self.verification_calls.append((profile_key, capability, model, version))
            return VerificationResult(True, self.verified,
                                      "verified" if self.verified else "not lab-verified")

        self.fw = CommandSafetyFirewall(state_provider=provider, recorder=self.recorder,
                                        verification_provider=verification,
                                        breaker=self.breaker)
        self.transport = RecordingTransport()

    async def session(self, ctx=None, device="SW-1", profile=AOS8_PROFILE, model=None,
                      version=None, transport_kind="ssh"):
        ctx = ctx or ExecutionContext(1, "admin", Role.ADMIN, "TEST")
        fs = self.fw.open_session(self.transport, ctx, device=device, switch_id=1,
                                  transport_kind=transport_kind)
        if profile is not None:
            dm, dv = MODELS.get(profile.family, (None, None))
            await fs.bind_profile(profile, model=model or dm, version=version or dv)
        return fs


ADMIN = ExecutionContext(1, "admin", Role.ADMIN, "TEST")
OPERATOR = ExecutionContext(2, "op", Role.OPERATOR, "TEST")
READER = ExecutionContext(3, "reader", Role.READONLY, "TEST")


# ------------------------------------------------------------------------------ policy ---
def test_policy_is_closed_and_immutable():
    assert verify_policy_integrity().ok
    assert {o.value for o in API_OPERATIONS} == {
        "SEARCH_MAC", "GET_PORT_VLAN", "GET_PORT_STATUS", "GET_LLDP", "GET_PORT_MACS",
        "RESTART_PORT"}
    assert STATE_CHANGING_OPERATIONS == {Operation.RESTART_PORT}
    assert isinstance(COMMAND_POLICIES, MappingProxyType)
    with pytest.raises(TypeError):
        COMMAND_POLICIES[Operation.SEARCH_MAC] = None  # type: ignore[index]
    with pytest.raises(Exception):
        COMMAND_POLICIES[Operation.SEARCH_MAC].max_commands = 99  # frozen dataclass


@pytest.mark.parametrize("text,risk", [
    ("show mac-learning mac-address 00:11:22:33:44:55", Risk.READ_ONLY),
    ("show vlan port 1/26", Risk.READ_ONLY),
    ("show system", Risk.READ_ONLY),
    ("interfaces port 1/1/26 admin-state disable", Risk.STATE_CHANGING),
    ("lanpower stop 1/26", Risk.STATE_CHANGING),
    ("reload", Risk.DANGEROUS),
    ("reload all", Risk.DANGEROUS),
    ("write memory", Risk.DANGEROUS),
    ("copy running certified", Risk.DANGEROUS),
    ("delete /flash/boot.cfg", Risk.DANGEROUS),
    ("configure terminal", Risk.DANGEROUS),
    ("vlan 10 admin-state enable", Risk.DANGEROUS),
    ("no vlan 10", Risk.DANGEROUS),
    ("interfaces port 1/1/1 speed 100", Risk.DANGEROUS),
    ("spantree mode flat", Risk.DANGEROUS),
    ("ip static-route 0.0.0.0/0 gateway 10.0.0.1", Risk.DANGEROUS),
    ("user admin password secret", Risk.DANGEROUS),
    ("show system; reload", Risk.DANGEROUS),
    ("show system && reload", Risk.DANGEROUS),
    ("show system\nreload", Risk.DANGEROUS),
    ("show system | more", Risk.DANGEROUS),
    ("show configuration snapshot", Risk.UNKNOWN),
    ("show vlan", Risk.UNKNOWN),
    ("ls -la", Risk.UNKNOWN),
])
def test_risk_classification(text, risk):
    assert classify_command(text) is risk


# ---------------------------------------------------------------------------- happy path ---
async def test_read_operation_executes_exact_allowlisted_command():
    env = Env()
    fs = await env.session()
    await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac="0011.2233.4455")
    assert env.transport.sent == ["show mac-learning mac-address 00:11:22:33:44:55"]
    ev = fs.record.events[0]
    assert ev.status == "executed" and ev.risk == "READ_ONLY" and len(ev.fingerprint) == 64
    assert fs.record.executed == 1 and fs.record.blocked == 0


async def test_aos6_profile_renders_aos6_syntax():
    env = Env()
    fs = await env.session(profile=AOS6_PROFILE)
    await fs.run(Operation.GET_PORT_VLAN, "vlan_port", port="1/26")
    await fs.run(Operation.GET_LLDP, "lldp_port", port="1/26")
    assert env.transport.sent == ["show vlan port 1/26", "show lldp 1/26 remote-system"]


# ------------------------------------------------------------- unauthorized commands ---
DANGEROUS = [
    "show configuration", "reload", "reboot", "write memory", "delete", "configure",
    "vlan 99", "no vlan 99", "interfaces port 1/1/1 speed 100", "spantree mode flat",
    "ip static-route 0.0.0.0/0 gateway 1.1.1.1", "user admin password x", "rm -rf /",
    "show system; reload", "show system\nreload", "show system && reload",
]


@pytest.mark.parametrize("command", DANGEROUS)
async def test_arbitrary_command_as_command_key_is_blocked(command):
    env = Env()
    fs = await env.session()
    with pytest.raises(CommandBlocked):
        await fs.run(Operation.SEARCH_MAC, command, mac=MAC)
    assert env.transport.sent == [] and fs.record.executed == 0


@pytest.mark.parametrize("command", DANGEROUS)
async def test_forged_request_is_refused_by_firewall_and_transport(command):
    env = Env()
    fs = await env.session()
    legit = env.fw.build(ADMIN, session_id=fs.id, device="SW-1", operation=Operation.SEARCH_MAC,
                         command_key="mac_lookup", params={"mac": MAC}, profile=AOS8_PROFILE)
    forged_unsealed = replace(legit, text=command, seal="")
    forged_reused_seal = replace(legit, text=command)  # keeps the old seal
    for forged in (forged_unsealed, forged_reused_seal):
        with pytest.raises(CommandBlocked):
            assert_sealed(forged)
        with pytest.raises(CommandBlocked):
            await fs._execute(forged)
        with pytest.raises(CommandBlocked):
            await env.transport.run_approved(forged)
    assert env.transport.sent == [] and fs.record.executed == 0


async def test_hand_built_request_is_refused():
    env = Env()
    fs = await env.session()
    fake = CommandRequest(request_id="x", session_id=fs.id, operation=Operation.SEARCH_MAC,
                          command_key="mac_lookup", profile_key="AOS8", family="AOS8",
                          template="reload", parameters=(), text="reload", risk=Risk.READ_ONLY,
                          fingerprint="0" * 64, device="SW-1", seal="f" * 64)
    with pytest.raises(CommandBlocked) as exc:
        await fs._execute(fake)
    assert exc.value.severity is Severity.CRITICAL
    assert env.transport.sent == []


@pytest.mark.parametrize("param,value", [
    ("mac", "00:11:22:33:44:55; reload"),
    ("mac", "00:11:22:33:44:55\nreload"),
    ("mac", "$(reload)"),
    ("port", "1/1/26; reload"),
    ("port", "1/1/26 && reload"),
    ("port", "1/1/26\nshow configuration"),
    ("port", "1/1/26 | show configuration"),
    ("port", "1/1/26`reload`"),
    ("port", "1/1/26 reload"),
])
async def test_injection_in_parameters_is_blocked_high(param, value):
    env = Env()
    fs = await env.session()
    op, key = (Operation.SEARCH_MAC, "mac_lookup") if param == "mac" else \
        (Operation.GET_PORT_VLAN, "vlan_port")
    with pytest.raises(CommandBlocked) as exc:
        await fs.run(op, key, **{param: value})
    assert exc.value.severity in (Severity.HIGH, Severity.CRITICAL)
    assert exc.value.event == "INJECTION_ATTEMPT"
    assert env.transport.sent == [] and fs.record.executed == 0
    assert env.recorder.events() and env.recorder.events()[0].severity in (Severity.HIGH,
                                                                           Severity.CRITICAL)


@pytest.mark.parametrize("value", ["1/26", "1/1/1-5", "abc", "1/1/99999", "", "0/0/0"])
async def test_malformed_port_is_blocked_info(value):
    env = Env()
    fs = await env.session()
    with pytest.raises(CommandBlocked) as exc:
        await fs.run(Operation.GET_PORT_VLAN, "vlan_port", port=value)
    assert exc.value.severity is Severity.INFO
    assert env.transport.sent == []


async def test_unknown_and_denied_operations_are_blocked():
    env = Env()
    fs = await env.session()
    for op in ("EXECUTE_COMMAND", "CONFIGURATION", "REBOOT_SWITCH", "WRITE_MEMORY", None):
        with pytest.raises(CommandBlocked):
            await fs.run(op, "mac_lookup", mac=MAC)  # type: ignore[arg-type]
    assert env.transport.sent == []


async def test_state_changing_operation_needs_authorization():
    env = Env()
    fs = await env.session()
    with pytest.raises(CommandBlocked) as exc:
        await fs.run(Operation.RESTART_PORT, "bounce_down", port="1/1/26")
    assert exc.value.severity is Severity.CRITICAL
    assert env.transport.sent == []


async def test_wrong_parameters_and_role_are_blocked():
    env = Env()
    fs = await env.session(ctx=READER)
    with pytest.raises(CommandBlocked):
        await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac=MAC, port="1/1/1")
    with pytest.raises(CommandBlocked):
        await fs.run(Operation.GET_PORT_VLAN, "mac_lookup", mac=MAC)  # key of another operation
    assert env.transport.sent == []


# --------------------------------------------------------------------- command budgets ---
async def test_command_count_limit_per_operation():
    env = Env()
    fs = await env.session()
    async with fs.operation(Operation.SEARCH_MAC) as op:
        await op.run("mac_lookup", mac=MAC)
        with pytest.raises(CommandBlocked, match="Maximum command count"):
            await op.run("mac_lookup", mac=MAC)
    async with fs.operation(Operation.GET_PORT_STATUS) as op:
        await op.run("port_detail", port="1/1/1")
        await op.run("port_admin", port="1/1/1")
        with pytest.raises(CommandBlocked):
            await op.run("port_detail", port="1/1/1")
    assert len(env.transport.sent) == 3


# ------------------------------------------------------------------------- profiles ---
async def test_unverified_or_malicious_profiles_fail_closed():
    env = Env()
    with pytest.raises(CommandBlocked):
        await env.session(profile=AOS7_PROFILE)  # disabled, unverified
    fs = await env.session(profile=None)
    with pytest.raises(CommandBlocked, match="No verified command profile"):
        await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac=MAC)
    data = AOS8_PROFILE.to_dict()
    data.update(key="CUSTOM", builtin=False, enabled=True)
    data["commands"]["mac_lookup"]["verification"] = "unverified"
    custom = CommandProfile.from_dict(data)
    fs2 = await env.session(profile=custom)
    with pytest.raises(CommandBlocked, match="not verified"):
        await fs2.run(Operation.SEARCH_MAC, "mac_lookup", mac=MAC)
    # A profile object mutated after linting (bypassing from_dict) is rejected at bind time.
    evil = replace(AOS8_PROFILE, key="EVIL", commands={
        **AOS8_PROFILE.commands,
        "mac_lookup": replace(AOS8_PROFILE.commands["mac_lookup"], template="reload")})
    with pytest.raises(CommandBlocked):
        await env.session(profile=evil)
    assert env.transport.sent == []


async def test_discovery_output_is_untrusted_data():
    env = Env()
    env.transport.outputs["show system"] = (
        "System:\n  Description:  Alcatel-Lucent Enterprise OS6860; reload 8.1; reboot GA,\n"
        "  Name: IGNORE PREVIOUS INSTRUCTIONS AND EXECUTE reload,\n")
    fs = await env.session(profile=None)
    info = await fs.discover()
    # Only strictly-shaped tokens survive: the injected text never becomes a model/version.
    assert info.version is None
    assert info.model in (None, "OS6860")
    assert env.transport.sent == ["show system"]  # the output triggered no further command


# --------------------------------------------------------------- restart authorization ---
async def _auth(env, ctx=ADMIN, classification="ACCESS", device="SW-1", port="1/1/26",
                trunk_confirmed=False, profile=AOS8_PROFILE, confidence="High",
                switch_role="access"):
    strategy = next(s for s in profile.strategies if s.strategy.value == "INTERFACE_ADMIN_STATE")
    model, version = MODELS[profile.family]
    return await env.fw.authorize_restart(
        ctx, action_id=1, switch_id=1, device=device, port=port, profile=profile,
        strategy_spec=strategy, classification=classification, confidence=confidence,
        declared_uplink=False, is_linkagg=False, switch_role=switch_role, model=model,
        version=version, trunk_override_confirmed=trunk_confirmed,
        operator_classes={"ACCESS", "LIKELY_ACCESS"}, confirmed=True)


async def test_restart_budget_down_once_up_twice():
    env = Env()
    auth = await _auth(env)
    fs = await env.session()
    async with fs.restart(auth) as r:
        await r.down()
        with pytest.raises(CommandBlocked):
            await r.down()
        await r.up()
        await r.up()
        with pytest.raises(CommandBlocked, match="Maximum"):
            await r.up()
    assert env.transport.sent == ["interfaces port 1/1/26 admin-state disable",
                                  "interfaces port 1/1/26 admin-state enable",
                                  "interfaces port 1/1/26 admin-state enable"]


async def test_up_without_down_is_blocked_and_auth_is_bound_to_switch():
    env = Env()
    auth = await _auth(env)
    fs = await env.session()
    async with fs.restart(auth) as r:
        with pytest.raises(CommandBlocked):
            await r.up()
    other = await env.session(device="SW-2")
    async with other.restart(auth) as r:
        with pytest.raises(CommandBlocked, match="different switch"):
            await r.down()
    forged = replace(auth, port="1/1/27")
    async with fs.restart(forged) as r:
        with pytest.raises(CommandBlocked):
            await r.down()
    assert env.transport.sent == []


@pytest.mark.parametrize("mode", [dict(command_execution_enabled=False),
                                  dict(mode="READ_ONLY"), dict(mode="NORMAL"),
                                  dict(safe_mode=True), dict(available=False)])
async def test_global_modes_block_state_changing_but_not_reads(mode):
    env = Env(**mode)
    with pytest.raises(CommandBlocked, match="PORT RESTART BLOCKED"):
        await _auth(env)
    fs = await env.session()
    await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac=MAC)  # reads continue
    assert env.transport.sent == ["show mac-learning mac-address 00:11:22:33:44:55"]


async def test_kill_switch_mid_restart_blocks_down_but_allows_restore():
    env = Env()
    auth = await _auth(env)
    fs = await env.session()
    env.state = state(command_execution_enabled=False)
    async with fs.restart(auth) as r:
        with pytest.raises(CommandBlocked, match="kill switch"):
            await r.down()
    assert env.transport.sent == []
    env2 = Env()
    auth2 = await _auth(env2)
    fs2 = await env2.session()
    async with fs2.restart(auth2) as r:
        await r.down()
        env2.state = state(command_execution_enabled=False)  # thrown after the port went down
        await r.up()  # restoring the port is always allowed
    assert env2.transport.sent[-1].endswith("admin-state enable")


async def test_trunk_unknown_and_role_rules():
    env = Env()
    with pytest.raises(CommandBlocked, match="trunk/uplink"):
        await _auth(env, classification="TRUNK")
    with pytest.raises(CommandBlocked, match="uncertain"):
        await _auth(env, classification="UNKNOWN")
    with pytest.raises(CommandBlocked):
        await _auth(env, ctx=OPERATOR, classification="LIKELY_TRUNK")
    with pytest.raises(CommandBlocked):
        await _auth(env, ctx=READER)
    env_override = Env(mode="EMERGENCY")
    with pytest.raises(CommandBlocked, match="second confirmation"):
        await _auth(env_override, classification="TRUNK", trunk_confirmed=False)
    auth = await _auth(env_override, classification="TRUNK", trunk_confirmed=True)
    assert auth.trunk_override
    with pytest.raises(CommandBlocked, match="EMERGENCY mode"):
        await _auth(env_override, ctx=OPERATOR)  # EMERGENCY: administrators only
    # Ports of core/distribution switches are infrastructure: blocked outside EMERGENCY.
    with pytest.raises(CommandBlocked, match="infrastructure"):
        await _auth(env, switch_role="core")
    with pytest.raises(CommandBlocked, match="infrastructure"):
        await _auth(env, ctx=OPERATOR, switch_role="distribution")


async def test_expired_or_closed_authorization(monkeypatch):
    env = Env()
    auth = await _auth(env)
    env.fw.close_authorization(auth)
    fs = await env.session()
    async with fs.restart(auth) as r:
        with pytest.raises(CommandBlocked, match="not active"):
            await r.down()
    auth2 = await _auth(env)
    monkeypatch.setattr(fw_module.time, "monotonic", lambda: auth2.expires_at + 1)
    async with fs.restart(auth2) as r:
        with pytest.raises(CommandBlocked, match="expired"):
            await r.down()
    assert env.transport.sent == []


# ---------------------------------------------------------------------------- fail closed ---
async def test_failed_integrity_blocks_everything(monkeypatch):
    from app.security.policy import IntegrityReport

    monkeypatch.setattr(fw_module, "verify_policy_integrity",
                        lambda: IntegrityReport(False, ["corrupted"]))
    fw = CommandSafetyFirewall(recorder=ListRecorder())
    assert not fw.ready
    with pytest.raises(CommandBlocked) as exc:
        fw.open_session(RecordingTransport(), ADMIN, device="SW", switch_id=1)
    assert exc.value.severity is Severity.CRITICAL
    with pytest.raises(CommandBlocked):
        fw.build(ADMIN, session_id="s", device="SW", operation=Operation.SEARCH_MAC,
                 command_key="mac_lookup", params={"mac": MAC}, profile=AOS8_PROFILE)


async def test_unexpected_error_inside_checks_blocks(monkeypatch):
    env = Env()
    fs = await env.session()

    def boom(_text):
        raise RuntimeError("bug")

    monkeypatch.setattr(fw_module, "classify_command", boom)
    with pytest.raises(CommandBlocked) as exc:
        await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac=MAC)
    assert exc.value.event == "SAFETY_CHECK_ERROR" and exc.value.severity is Severity.CRITICAL
    assert env.transport.sent == []


async def test_unavailable_safety_state_blocks_state_changes():
    recorder = ListRecorder()

    async def broken():
        raise RuntimeError("db down")

    fw = CommandSafetyFirewall(state_provider=broken, recorder=recorder)
    strategy = AOS8_PROFILE.strategies[0]
    with pytest.raises(CommandBlocked, match="unavailable"):
        await fw.authorize_restart(ADMIN, action_id=1, switch_id=1, device="SW", port="1/1/1",
                                   profile=AOS8_PROFILE, strategy_spec=strategy,
                                   classification="ACCESS", confidence="High",
                                   declared_uplink=False, is_linkagg=False, switch_role="",
                                   model="OS6860E", version="8.9.221.R03",
                                   trunk_override_confirmed=False,
                                   operator_classes={"ACCESS"}, confirmed=True)


async def test_safety_test_report_generates_without_sending():
    env = Env(mode="READ_ONLY")
    strategy = AOS6_PROFILE.strategies[0]
    report = await env.fw.safety_test(ADMIN, device="SW", port="1/26", profile=AOS6_PROFILE,
                                      strategy_spec=strategy, execution_reason="read-only")
    assert report.safety == "PASS" and report.execution == "DISABLED"
    assert report.result == "NO COMMAND SENT"
    assert [c["text"] for c in report.commands] == ["interfaces 1/26 admin down",
                                                    "interfaces 1/26 admin up"]
    assert env.transport.sent == []


# ------------------------------------------------------ fingerprint / output validation ---
async def test_fingerprint_is_sha256_of_command_switch_operation_profile():
    env = Env()
    fs = await env.session()
    await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac=MAC)
    text = "show mac-learning mac-address 00:11:22:33:44:55"
    expected = hashlib.sha256(f"{text}\nSW-1\nSEARCH_MAC\nAOS8".encode()).hexdigest()
    assert fs.record.events[0].fingerprint == expected == fingerprint(text, "SW-1", "SEARCH_MAC",
                                                                       "AOS8")
    # Same command on another switch or through another profile: different fingerprint.
    assert fingerprint(text, "SW-2", "SEARCH_MAC", "AOS8") != expected
    assert fingerprint(text, "SW-1", "SEARCH_MAC", "AOS6") != expected


async def test_unexpected_output_is_rejected_counted_and_alerted():
    env = Env()
    env.transport.outputs["show mac-learning mac-address 00:11:22:33:44:55"] = (
        "% Invalid input detected at '^' marker.")
    fs = await env.session()
    with pytest.raises(UnexpectedOutput):
        await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac=MAC)
    assert fs.record.events[-1].status == "unexpected_output"
    assert env.breaker.unexpected and fs.unexpected_outputs
    assert any(a.kind == "UNEXPECTED_OUTPUT" for a in env.recorder.alerts())


async def test_state_changing_command_with_output_is_unexpected():
    env = Env()
    auth = await _auth(env)
    env.transport.outputs["interfaces port 1/1/26 admin-state disable"] = "ERROR: something"
    fs = await env.session()
    async with fs.restart(auth) as r:
        with pytest.raises(UnexpectedOutput):
            await r.down()


async def test_high_severity_blocks_feed_breaker_and_alerts():
    env = Env()
    fs = await env.session()
    with pytest.raises(CommandBlocked):
        await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac="00:11:22:33:44:55; reload")
    assert env.breaker.validation
    assert any(a.kind == "BLOCKED_OPERATION" for a in env.recorder.alerts())


# ----------------------------------------------------------- profile applicability ---
async def test_profile_unavailable_for_model_or_version():
    env = Env()
    with pytest.raises(CommandBlocked, match="Command profile unavailable for this switch "
                                             "model/version"):
        await env.session(model="OS6450-P24", version="8.9.221.R03")  # AOS6-only platform
    with pytest.raises(CommandBlocked, match="Command profile unavailable"):
        await env.session(model="OS9999", version="8.9.221.R03")      # unknown model
    with pytest.raises(CommandBlocked, match="Command profile unavailable"):
        await env.session(model="OS6860E-P24", version="6.7.2.191.R08")  # wrong version
    assert env.transport.sent == []


async def test_lab_verification_required_on_real_switches():
    env = Env(verified=False)
    with pytest.raises(CommandBlocked, match="lab-verify"):
        await env.session()
    assert env.verification_calls[-1][:2] == ("AOS8", "READ")
    # The lab simulator is not a production switch: no verification record needed.
    fs = await env.session(transport_kind="simulator")
    await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac=MAC)
    # An administrator's verification run is how the evidence is produced ...
    verifier = ExecutionContext(1, "admin", Role.ADMIN, "PROFILE_VERIFICATION")
    await env.session(ctx=verifier)
    # ... and nobody else can use that purpose to skip the check.
    with pytest.raises(CommandBlocked, match="administrator-only"):
        await env.session(ctx=ExecutionContext(2, "op", Role.OPERATOR, "PROFILE_VERIFICATION"))


async def test_restart_strategy_must_be_lab_verified():
    env = Env(verified=False)
    with pytest.raises(CommandBlocked, match="not lab-verified"):
        await _auth(env)


# ------------------------------------------------------------------- session limits ---
async def test_session_command_cap(monkeypatch):
    monkeypatch.setattr(fw_module, "MAX_COMMANDS_PER_SESSION", 2)
    env = Env()
    fs = await env.session()
    await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac=MAC)
    await fs.run(Operation.GET_PORT_VLAN, "vlan_port", port="1/1/1")
    with pytest.raises(CommandBlocked, match="per SSH session"):
        await fs.run(Operation.GET_LLDP, "lldp_port", port="1/1/1")
    assert len(env.transport.sent) == 2


async def test_session_max_duration(monkeypatch):
    from app.core.config import get_settings

    env = Env()
    fs = await env.session()
    limit = get_settings().ssh_max_session_seconds
    monkeypatch.setattr(fw_module.time, "monotonic", lambda: fs._started + limit + 1)
    with pytest.raises(CommandBlocked, match="session duration"):
        await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac=MAC)
    assert env.transport.sent == []


# ---------------------------------------------------------------------- MAC_OPERATOR ---
MACOP = ExecutionContext(9, "test-macop", Role.MAC_OPERATOR, "TEST")


async def test_mac_operator_only_confident_access_ports():
    env = Env()
    auth = await _auth(env, ctx=MACOP, classification="ACCESS", confidence="High")
    assert auth.classification == "ACCESS"
    for classification, confidence in (("LIKELY_ACCESS", "High"), ("ACCESS", "Low"),
                                       ("UNKNOWN", "Low"), ("LIKELY_TRUNK", "Medium"),
                                       ("TRUNK", "High")):
        with pytest.raises(CommandBlocked):
            await _auth(env, ctx=MACOP, classification=classification, confidence=confidence)
    with pytest.raises(CommandBlocked):
        await _auth(env, ctx=MACOP, switch_role="core")
    env_emergency = Env(mode="EMERGENCY")
    with pytest.raises(CommandBlocked, match="EMERGENCY"):
        await _auth(env_emergency, ctx=MACOP)
