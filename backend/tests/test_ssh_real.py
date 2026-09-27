"""The real asyncssh client against the lab SSH server (127.0.0.1, ephemeral ports).

All commands go through the Command Safety Firewall, exactly as in production.
"""

import pytest
import pytest_asyncio

from app.core.config import get_settings
from app.models.user import Role
from app.parsers.alcatel.mac_table import find_mac
from app.parsers.alcatel.vlan_port import parse_vlan_port
from app.security.firewall import (
    CommandBlocked,
    CommandSafetyFirewall,
    ExecutionContext,
    VerificationResult,
    init_firewall,
)
from app.security.policy import Operation
from app.security.state import SafetyState
from app.services.alcatel.profiles import AOS6_PROFILE, AOS8_PROFILE
from app.services.ssh.asyncssh_session import AsyncSshCliSession, SshParams, fetch_host_key
from app.services.ssh.errors import AuthenticationFailed, CommandTimeout, HostKeyError
from app.services.ssh.manager import ConnectionTarget, SwitchConnector
from app.simulator.scenarios import SIM_PASSWORD, SIM_USERNAME, build_lab
from app.simulator.ssh_server import start_servers

CTX = ExecutionContext(1, "admin", Role.ADMIN, "TEST")


class _Recorder:
    def __init__(self):
        self.items = []

    def submit(self, item):
        self.items.append(item)


async def _state():
    return SafetyState(available=True, mode="MAINTENANCE", configured_mode="MAINTENANCE",
                       mode_reason="", read_only_forced_by_env=False,
                       command_execution_enabled=True, kill_switch_forced_by_env=False,
                       safe_mode=False, safe_mode_reason="", dry_run_mode=False)


async def _lab_verified(profile_key, capability, model, version):
    # Stands in for an administrator's lab-verification record of these lab switches.
    return VerificationResult(True, True, "lab-verified (test)")


MODELS = {"AOS8": ("OS6860E-P24", "8.9.221.R03"), "AOS6": ("OS6450-P24", "6.7.2.191.R08")}


@pytest.fixture
def firewall():
    fw = init_firewall(state_provider=_state, recorder=_Recorder(),
                       verification_provider=_lab_verified)
    yield fw
    init_firewall()


@pytest_asyncio.fixture
async def ssh_lab():
    switches = build_lab(relearn_delay=0.1)
    servers = await start_servers(switches, "127.0.0.1", 0)
    by_name = {sw.name: (port, pub) for sw, port, _acc, pub in servers}
    yield switches, by_name
    for _sw, _port, acceptor, _pub in servers:
        acceptor.close()
        await acceptor.wait_closed()


def params(port: int, host_key: str | None, *, password=SIM_PASSWORD, allow_unknown=False,
           command_timeout=3.0) -> SshParams:
    return SshParams(host="127.0.0.1", port=port, username=SIM_USERNAME, password=password,
                     host_key=host_key, allow_unknown_host_key=allow_unknown,
                     legacy_algorithms=False, connect_timeout=3, login_timeout=4,
                     command_timeout=command_timeout, prompt_pattern=r"->\s*$", label="test")


async def firewall_session(fw: CommandSafetyFirewall, transport, profile):
    fs = fw.open_session(transport, CTX, device="SIM", switch_id=1)
    model, version = MODELS[profile.family]
    await fs.bind_profile(profile, model=model, version=version)
    return fs


async def test_trusted_host_key_login_and_commands(ssh_lab, firewall):
    _switches, ports = ssh_lab
    port, pub = ports["SIM-SW-01"]
    transport = await AsyncSshCliSession.open(params(port, pub))
    try:
        assert "SIMULATED" in transport.banner
        fs = await firewall_session(firewall, transport, AOS8_PROFILE)
        out = await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac="00:11:22:33:44:55")
        assert [e.port for e in find_mac(out, "001122334455")] == ["1/1/26"]
    finally:
        await transport.close()


async def test_transport_refuses_raw_text(ssh_lab, firewall):
    _switches, ports = ssh_lab
    port, pub = ports["SIM-SW-01"]
    transport = await AsyncSshCliSession.open(params(port, pub))
    try:
        with pytest.raises(CommandBlocked):
            await transport.run_approved("reload")  # plain text is never accepted
        assert not hasattr(transport, "run")
    finally:
        await transport.close()
    assert _switches["SIM-SW-01"].command_log == []


async def test_pagination_over_real_ssh(ssh_lab, firewall):
    """SIM-SW-03 (AOS 6) has "more" mode on with 12-line pages."""
    _switches, ports = ssh_lab
    port, pub = ports["SIM-SW-03"]
    transport = await AsyncSshCliSession.open(params(port, pub))
    try:
        fs = await firewall_session(firewall, transport, AOS6_PROFILE)
        out = await fs.run(Operation.GET_PORT_STATUS, "port_detail", port="1/12")  # 3 pages
        assert "Operational Status" in out and "Late Collisions" in out
        assert "More?" not in out
        vlans = parse_vlan_port(await fs.run(Operation.GET_PORT_VLAN, "vlan_port", port="1/12"))
        assert [v.vlan_id for v in vlans] == [10, 300]
    finally:
        await transport.close()


async def test_missing_host_key_is_refused_by_default(ssh_lab):
    _switches, ports = ssh_lab
    port, _pub = ports["SIM-SW-01"]
    with pytest.raises(HostKeyError, match="No trusted SSH host key"):
        await AsyncSshCliSession.open(params(port, None))


async def test_wrong_host_key_is_refused(ssh_lab):
    import asyncssh

    _switches, ports = ssh_lab
    port, _pub = ports["SIM-SW-01"]
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode()
    with pytest.raises(HostKeyError, match="does not match"):
        await AsyncSshCliSession.open(params(port, other))


async def test_lab_option_allows_unknown_host_key(ssh_lab):
    _switches, ports = ssh_lab
    port, _pub = ports["SIM-SW-02"]
    session = await AsyncSshCliSession.open(params(port, None, allow_unknown=True))
    await session.close()


async def test_authentication_failure(ssh_lab):
    _switches, ports = ssh_lab
    port, pub = ports["SIM-SW-01"]
    with pytest.raises(AuthenticationFailed):
        await AsyncSshCliSession.open(params(port, pub, password="wrong"))
    port4, pub4 = ports["SIM-SW-04"]  # server rejects everyone
    with pytest.raises(AuthenticationFailed):
        await AsyncSshCliSession.open(params(port4, pub4))


async def test_command_hang_times_out(ssh_lab, firewall):
    _switches, ports = ssh_lab
    port, pub = ports["SIM-SW-05"]
    transport = await AsyncSshCliSession.open(params(port, pub, command_timeout=0.5))
    try:
        fs = await firewall_session(firewall, transport, AOS6_PROFILE)
        with pytest.raises(CommandTimeout):
            await fs.run(Operation.SEARCH_MAC, "mac_lookup", mac="00:11:22:33:44:55")
    finally:
        await transport.close()


async def test_fetch_host_key_matches_server(ssh_lab):
    import asyncssh

    _switches, ports = ssh_lab
    port, pub = ports["SIM-SW-01"]
    key, fingerprint = await fetch_host_key("127.0.0.1", port, False, 3)
    assert key.split()[:2] == pub.split()[:2]
    assert fingerprint == asyncssh.import_public_key(pub).get_fingerprint("sha256")


async def test_connector_concurrency_limit_and_authorized_restart(ssh_lab, firewall):
    switches, ports = ssh_lab
    port, pub = ports["SIM-SW-01"]
    settings = get_settings().model_copy(update={"max_concurrent_switch_connections": 1})
    connector = SwitchConnector(settings)
    target = ConnectionTarget(1, "SIM-SW-01", "127.0.0.1", port, SIM_USERNAME, SIM_PASSWORD, pub,
                              False)
    async with connector.session(target, CTX) as fs:
        assert connector.active == 1
        await fs.discover()
    assert connector.active == 0
    strategy = next(s for s in AOS8_PROFILE.strategies
                    if s.strategy.value == "INTERFACE_ADMIN_STATE")
    auth = await firewall.authorize_restart(
        CTX, action_id=1, switch_id=1, device="SIM-SW-01", port="1/1/26", profile=AOS8_PROFILE,
        strategy_spec=strategy, classification="ACCESS", confidence="High",
        declared_uplink=False, is_linkagg=False, switch_role="access", model="OS6860E-P24",
        version="8.9.221.R03", trunk_override_confirmed=False, operator_classes={"ACCESS"},
        confirmed=True, discovery_status="discovered", environment="lab")
    async with connector.session(target, CTX) as fs:
        await fs.bind_profile(AOS8_PROFILE, model="OS6860E-P24", version="8.9.221.R03")
        async with fs.restart(auth) as restart:
            await restart.down()
    assert not switches["SIM-SW-01"].ports["1/1/26"].admin_up
    assert switches["SIM-SW-01"].command_log[-1] == "interfaces port 1/1/26 admin-state disable"


async def test_search_reports_missing_read_verification_precisely(admin, ssh_lab):
    """A discovered real-SSH switch without a READ record is blocked, and the result carries
    the precise safe category (not the generic OPERATION_BLOCKED)."""
    from app.core.crypto import encrypt_secret
    from app.db.session import session_factory
    from app.models import Credential, Switch
    from tests.conftest import verify, wait_for_search

    _switches, ports = ssh_lab
    port, pub = ports["SIM-SW-01"]
    async with session_factory()() as db:
        cred = Credential(name="lab", username=SIM_USERNAME,
                          password_encrypted=encrypt_secret(SIM_PASSWORD))
        db.add(cred)
        await db.flush()
        db.add(Switch(name="REAL-1", host="127.0.0.1", ssh_port=port, transport="ssh",
                      host_key=pub, host_key_fingerprint="x", credential_id=cred.id,
                      vendor="ALE", model="OS6860E-P24", aos_version="8.9.221.R03",
                      discovery_status="discovered"))
        await db.commit()
    resp = await admin.post("/api/mac/search", json={"mac": "00:11:22:33:44:55"})
    await wait_for_search(admin, resp.json()["id"])
    rows = (await admin.get(f"/api/mac/search/{resp.json()['id']}/results")).json()
    assert (rows[0]["status"], rows[0]["category"]) == ("blocked", "PROFILE_NOT_VERIFIED")
    # With the READ record (LAB_VERIFIED is enough for reads) the same switch is searched.
    await verify("AOS8", "READ", "8.9", model_family="OS6860")
    resp = await admin.post("/api/mac/search", json={"mac": "00:11:22:33:44:55"})
    await wait_for_search(admin, resp.json()["id"])
    rows = (await admin.get(f"/api/mac/search/{resp.json()['id']}/results")).json()
    assert rows[0]["status"] == "found" and rows[0]["category"] == ""
